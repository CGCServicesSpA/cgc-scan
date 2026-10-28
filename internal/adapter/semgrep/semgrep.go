// Package semgrep implementa el tercer nivel opcional con reglas locales y sin
// métricas ni comprobación de versión (RF-30, CA-48).
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// ID identifica el motor.
const ID = "semgrep"

// Adapter ejecuta Semgrep CE con reglas propias o del usuario.
type Adapter struct {
	Version   string
	Root      string
	RulesDir  string
	Binary    string
	Mode      string // docker | global
	Masker    *masking.Masker
	RuleCount int
}

// New construye el adaptador.
func New(version, root, rulesDir, binary, mode string, ruleCount int, m *masking.Masker) *Adapter {
	return &Adapter{Version: version, Root: root, RulesDir: rulesDir, Binary: binary, Mode: mode, RuleCount: ruleCount, Masker: m}
}

func (a *Adapter) ID() string { return ID }

// Applies cubre todas las unidades de código, nunca la unidad de proyecto.
func (a *Adapter) Applies(u discovery.Unit) bool { return u.Kind != "repository" }

// Requirements comprueba el motor, las reglas locales y el modo.
func (a *Adapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	var reqs []adapter.Requirement
	if a.RulesDir == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "rules", Name: "reglas-locales", Detail: "no se pudieron preparar", Missing: true})
	} else if a.Mode != "docker" {
		if info, err := os.Stat(a.RulesDir); err != nil || !info.IsDir() {
			reqs = append(reqs, adapter.Requirement{Kind: "rules", Name: "reglas-locales", Detail: a.RulesDir, Missing: true})
		}
	}
	if a.Mode == "global" && a.Binary == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "binary", Name: "semgrep", Detail: "no está en PATH", Missing: true})
	}
	return reqs
}

// Invocations ejecuta Semgrep con métricas y comprobación de versión
// desactivadas y sin acceso al registro.
func (a *Adapter) Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error) {
	args := []string{
		"scan", "--config", a.RulesDir, "--json",
		"--metrics=off", "--disable-version-check",
		"--no-git-ignore", "--quiet", "--error",
	}
	for _, e := range p.Exclusions {
		if pat := expressible(e.Pattern); pat != "" {
			args = append(args, "--exclude", pat)
		}
	}
	args = append(args, ".")
	entrypoint := ""
	if a.Mode == "docker" {
		entrypoint = "semgrep"
	}
	return []runner.Invocation{{
		Engine:     ID,
		Binary:     a.Binary,
		Entrypoint: entrypoint,
		Args:       args,
		ProjectRO:  a.Root,
		Dir:        filepath.Join(a.Root, u.Path),
		Timeout:    10 * time.Minute,
		Env: map[string]string{
			"SEMGREP_SEND_METRICS":         "off",
			"SEMGREP_ENABLE_VERSION_CHECK": "0",
			"NO_COLOR":                     "1",
		},
	}}, nil
}

func expressible(pattern string) string {
	p := strings.TrimPrefix(pattern, "**/")
	p = strings.TrimSuffix(p, "/**")
	if p == "" {
		return ""
	}
	return p
}

// AcceptExit acepta 0 y 1 (hallazgos con --error).
func (a *Adapter) AcceptExit(code int) bool { return code == 0 || code == 1 }

// Report es el JSON de Semgrep.
type Report struct {
	Results []Result `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
		Path    string `json:"path"`
	} `json:"errors"`
}

// Result es un hallazgo.
type Result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE      []string `json:"cwe"`
			License  string   `json:"license"`
			Category string   `json:"category"`
		} `json:"metadata"`
	} `json:"extra"`
}

// Parse interpreta el JSON.
func (a *Adapter) Parse(raw []byte) (adapter.Parsed, error) {
	if len(raw) == 0 {
		return adapter.Parsed{}, fmt.Errorf("salida de semgrep vacía")
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return adapter.Parsed{}, fmt.Errorf("salida de semgrep no es JSON válido: %w", err)
	}
	out := make([]normalize.Finding, 0, len(rep.Results))
	for _, r := range rep.Results {
		out = append(out, a.toFinding(r))
	}
	var diags []adapter.Diagnostic
	for _, e := range rep.Errors {
		diags = append(diags, adapter.Diagnostic{Engine: ID, Message: e.Path + ": " + e.Message})
	}
	normalize.SortFindings(out)
	return adapter.Parsed{Findings: out, Diagnostics: diags}, nil
}

func (a *Adapter) toFinding(r Result) normalize.Finding {
	rule := shortRuleID(r.CheckID)
	f := normalize.Finding{
		Kind:  normalize.KindCode,
		Title: masking.Sanitize(r.Extra.Message),
		Severity: normalize.SeverityInfo{
			Original: r.Extra.Severity, Normalized: normalize.NormalizeSeverity(ID, r.Extra.Severity), Source: ID,
		},
		Sources:  []normalize.SourceRef{{Engine: ID, Version: a.Version, Rule: rule}},
		Evidence: normalize.Evidence{Snippet: masking.Sanitize(r.Extra.Message), Redacted: true},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	f.AddID("RULE", rule)
	for _, cwe := range r.Extra.Metadata.CWE {
		f.AddID("CWE", strings.TrimSpace(strings.SplitN(cwe, ":", 2)[0]))
	}
	loc := normalize.Location{Path: a.relative(r.Path)}
	if r.Start.Line > 0 {
		line := r.Start.Line
		loc.StartLine = &line
	}
	if r.End.Line > 0 {
		end := r.End.Line
		loc.EndLine = &end
	}
	if r.Start.Col > 0 {
		col := r.Start.Col
		loc.StartColumn = &col
	}
	if r.End.Col > 0 {
		col := r.End.Col
		loc.EndColumn = &col
	}
	f.AddLocation(loc)
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

func shortRuleID(id string) string {
	if i := strings.LastIndex(id, "."); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}

func (a *Adapter) relative(path string) string {
	if filepath.IsAbs(path) {
		if rel, err := filepath.Rel(a.Root, path); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(path)
}

// Redact sanea la salida.
func (a *Adapter) Redact(raw []byte) []byte { return a.Masker.RedactBytes(raw, nil) }

var _ = exec.LookPath
