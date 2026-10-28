// Package cargoaudit implementa el adaptador de Rust con cargo-audit y una
// copia local de RustSec, sin consultas de red durante el escaneo.
package cargoaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// ID identifica el motor.
const ID = "cargo-audit"

// Adapter ejecuta cargo-audit.
type Adapter struct {
	Install provision.AdapterInstall
	Root    string
	DBDir   string
	Masker  *masking.Masker
}

// New construye el adaptador.
func New(install provision.AdapterInstall, root, dbDir string, m *masking.Masker) *Adapter {
	return &Adapter{Install: install, Root: root, DBDir: dbDir, Masker: m}
}

func (a *Adapter) ID() string { return ID }

// Applies cubre unidades Rust.
func (a *Adapter) Applies(u discovery.Unit) bool {
	if u.Kind == "repository" {
		return false
	}
	for _, l := range u.Languages {
		if l == discovery.Rust {
			return true
		}
	}
	return false
}

// Requirements comprueba el binario y la base RustSec local.
func (a *Adapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	var reqs []adapter.Requirement
	if a.Install.Dir == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "binary", Name: "cargo-audit", Detail: "no aprovisionado", Missing: true})
	}
	if a.DBDir == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "database", Name: "rustsec", Detail: "base local no preparada", Missing: true})
	}
	return reqs
}

// Invocations ejecuta cargo-audit contra Cargo.lock.
func (a *Adapter) Invocations(u discovery.Unit, _ plan.Plan) ([]runner.Invocation, error) {
	bin := filepath.Join(a.Install.Dir, "cargo-audit")
	args := []string{"audit", "--db", a.DBDir, "--no-fetch", "--stale", "--json", "-f", "Cargo.lock"}
	return []runner.Invocation{{
		Engine:  ID,
		Binary:  bin,
		Args:    args,
		Dir:     filepath.Join(a.Root, u.Path),
		Timeout: 10 * time.Minute,
		Env:     map[string]string{"NO_COLOR": "1"},
	}}, nil
}

// AcceptExit acepta 0 (limpio) y 1 (vulnerabilidades encontradas).
func (a *Adapter) AcceptExit(code int) bool { return code == 0 || code == 1 }

// Report es el JSON de cargo-audit.
type Report struct {
	Database struct {
		AdvisoryCount int `json:"advisory-count"`
	} `json:"database"`
	Vulnerabilities struct {
		Found bool   `json:"found"`
		Count int    `json:"count"`
		List  []Vuln `json:"list"`
	} `json:"vulnerabilities"`
}

// Vuln es una vulnerabilidad de dependencia.
type Vuln struct {
	Advisory struct {
		ID          string   `json:"id"`
		Package     string   `json:"package"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Aliases     []string `json:"aliases"`
		URL         string   `json:"url"`
	} `json:"advisory"`
	Versions struct {
		Patched []string `json:"patched"`
	} `json:"versions"`
	Package struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

// Parse interpreta el JSON.
func (a *Adapter) Parse(raw []byte) (adapter.Parsed, error) {
	if len(raw) == 0 {
		return adapter.Parsed{}, fmt.Errorf("salida de cargo-audit vacía")
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return adapter.Parsed{}, fmt.Errorf("salida de cargo-audit no es JSON válido: %w", err)
	}
	out := make([]normalize.Finding, 0, len(rep.Vulnerabilities.List))
	for _, v := range rep.Vulnerabilities.List {
		out = append(out, a.toFinding(v))
	}
	normalize.SortFindings(out)
	return adapter.Parsed{Findings: out}, nil
}

func (a *Adapter) toFinding(v Vuln) normalize.Finding {
	f := normalize.Finding{
		Kind:  normalize.KindVulnerability,
		Title: masking.Sanitize(firstNonEmpty(v.Advisory.Title, v.Advisory.ID)),
		Severity: normalize.SeverityInfo{
			Original: "", Normalized: normalize.SeverityUnknown, Source: ID,
		},
		Sources:  []normalize.SourceRef{{Engine: ID, Version: a.Install.Version, Rule: v.Advisory.ID}},
		Evidence: normalize.Evidence{Redacted: true},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	if v.Advisory.Description != "" {
		f.Descriptions = []normalize.Description{{Text: a.Masker.Redact(v.Advisory.Description, nil), Source: ID}}
	}
	f.AddID("RUSTSEC", v.Advisory.ID)
	for _, alias := range v.Advisory.Aliases {
		f.AddID(idType(alias), alias)
	}
	f.Package = &normalize.PackageRef{Ecosystem: "crates.io", Name: v.Package.Name, Version: v.Package.Version}
	if len(v.Versions.Patched) > 0 {
		fixed := strings.TrimLeft(v.Versions.Patched[0], "^=<>~ ")
		f.Package.FixedVersion = &fixed
		f.Remediation = []normalize.Remediation{{
			Description: fmt.Sprintf("Actualizar %s a %s o superior", v.Package.Name, fixed),
			Source:      "advisory",
		}}
	}
	f.AddLocation(normalize.Location{Path: "Cargo.lock"})
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

// Redact sanea la salida.
func (a *Adapter) Redact(raw []byte) []byte { return a.Masker.RedactBytes(raw, nil) }

// RecipeCandidates propone los comandos estándar de Rust.
func (a *Adapter) RecipeCandidates(u discovery.Unit) []adapter.RecipeCandidate {
	return []adapter.RecipeCandidate{
		{Unit: u.ID, Kind: "test", Command: "cargo test", Workdir: u.Path, Origin: "adapter"},
		{Unit: u.ID, Kind: "build", Command: "cargo build", Workdir: u.Path, Origin: "adapter"},
	}
}

func idType(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GHSA"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "RUSTSEC"
	}
	return "OTHER"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
