// Package trivy implementa el adaptador del motor Trivy: argumentos,
// interpretación del JSON y enmascarado de secretos (design §8).
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// Version es la versión fijada del motor (P-07).
const Version = "0.76.1"

// ID es el identificador del motor en el reporte.
const ID = "trivy"

// Adapter es el adaptador de Trivy.
type Adapter struct {
	Masker   *masking.Masker
	Version  string
	CacheDir string
	// Binary es la ruta absoluta al binario (runner global) o vacía en Docker.
	Binary string
	// RunnerKind es "docker" o "global".
	RunnerKind string
}

// New construye el adaptador con la sal de enmascarado.
func New(m *masking.Masker) *Adapter {
	return &Adapter{Masker: m, Version: Version}
}

func (a *Adapter) ID() string { return ID }

// Applies informa si la unidad se analiza con Trivy. Trivy recorre el árbol del
// proyecto una sola vez (unidad "repository"); los módulos no se escanean por
// separado para no duplicar trabajo ni hallazgos.
func (a *Adapter) Applies(u discovery.Unit) bool { return u.Kind == "repository" }

// Requirements declara los prerrequisitos globales del adaptador.
func (a *Adapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	return nil
}

// Args construye los argumentos del escaneo. Es la referencia que se valida
// contra la versión fijada (H1-05, T-01). El destino debe ser "." para que las
// rutas del reporte sean relativas.
func Args(cacheDir string, skipDirs, skipFiles []string) []string {
	args := []string{
		"fs",
		"--format", "json",
		"--scanners", "vuln,secret,misconfig",
		"--skip-db-update",
		"--skip-java-db-update",
		"--offline-scan",
		"--skip-check-update",
		"--skip-version-check",
		"--disable-telemetry",
		"--no-progress",
		"--cache-dir", cacheDir,
	}
	sort.Strings(skipDirs)
	sort.Strings(skipFiles)
	for _, d := range skipDirs {
		args = append(args, "--skip-dirs", d)
	}
	for _, f := range skipFiles {
		args = append(args, "--skip-files", f)
	}
	return append(args, ".")
}

// Invocations produce una ejecución de Trivy para la unidad.
func (a *Adapter) Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error) {
	inv := runner.Invocation{
		Engine:    ID,
		Binary:    a.Binary,
		Dir:       filepath.Join(p.Root, u.Path),
		ProjectRO: p.Root,
		Args:      Args(a.CacheDir, skipDirs(p), skipFiles(p)),
		Env:       map[string]string{"TRIVY_SKIP_VERSION_CHECK": "true"},
	}
	return []runner.Invocation{inv}, nil
}

// skipDirs traduce las exclusiones efectivas a los mecanismos de Trivy. Los
// patrones de archivo (`**/*.min.js`) van a --skip-files.
func skipDirs(p plan.Plan) []string {
	var out []string
	for _, e := range p.Exclusions {
		pat := strings.TrimPrefix(e.Pattern, "**/")
		if strings.HasSuffix(pat, "/**") {
			pat = strings.TrimSuffix(pat, "/**")
			if pat != "" {
				out = append(out, pat)
			}
			continue
		}
		if strings.Contains(pat, "*") {
			continue
		}
		out = append(out, pat)
	}
	return dedupe(out)
}

func skipFiles(p plan.Plan) []string {
	var out []string
	for _, e := range p.Exclusions {
		if strings.Contains(e.Pattern, "*") && !strings.HasSuffix(e.Pattern, "/**") {
			out = append(out, e.Pattern)
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Report es el subconjunto del JSON de Trivy que se interpreta.
type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	Results       []Result `json:"Results"`
}

// Result es un objetivo del reporte de Trivy.
type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	Vulnerabilities   []Vulnerability    `json:"Vulnerabilities"`
	Secrets           []Secret           `json:"Secrets"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
}

// Vulnerability es una vulnerabilidad de dependencia.
type Vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Severity         string          `json:"Severity"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	PrimaryURL       string          `json:"PrimaryURL"`
	References       []string        `json:"References"`
	CweIDs           []string        `json:"CweIDs"`
	CVSS             map[string]CVSS `json:"CVSS"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
}

// CVSS es un vector y puntuación de una fuente.
type CVSS struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

// Secret es un secreto detectado.
type Secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
	Code      struct {
		Lines []struct {
			Number  int    `json:"Number"`
			Content string `json:"Content"`
		} `json:"Lines"`
	} `json:"Code"`
}

// Misconfiguration es una configuración insegura.
type Misconfiguration struct {
	ID            string   `json:"ID"`
	AVDID         string   `json:"AVDID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	References    []string `json:"References"`
	CauseMetadata struct {
		StartLine int `json:"StartLine"`
		EndLine   int `json:"EndLine"`
	} `json:"CauseMetadata"`
}

// Parse interpreta la salida de Trivy. Un JSON inválido o truncado devuelve
// error: el orquestador marca la unidad como fallida y la ejecución como
// incompleta, nunca como resultados limpios.
func (a *Adapter) Parse(raw []byte) (adapter.Parsed, error) {
	rep, _, err := a.parse(raw)
	if err != nil {
		return adapter.Parsed{}, err
	}
	return adapter.Parsed{Findings: a.findings(rep)}, nil
}

func (a *Adapter) parse(raw []byte) (Report, []string, error) {
	if len(raw) == 0 {
		return Report{}, nil, fmt.Errorf("salida de trivy vacía")
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return Report{}, nil, fmt.Errorf("salida de trivy no es JSON válido: %w", err)
	}
	if rep.SchemaVersion != 0 && rep.SchemaVersion != 2 {
		return rep, nil, fmt.Errorf("versión de esquema de trivy no soportada: %d", rep.SchemaVersion)
	}
	var secrets []string
	for _, r := range rep.Results {
		for _, s := range r.Secrets {
			if s.Match != "" {
				secrets = append(secrets, s.Match)
			}
		}
	}
	return rep, secrets, nil
}

func (a *Adapter) findings(rep Report) []normalize.Finding {
	out := make([]normalize.Finding, 0, 8)
	for _, r := range rep.Results {
		path := normalizePath(r.Target)
		for _, v := range r.Vulnerabilities {
			out = append(out, a.vulnerability(r, path, v))
		}
		for _, s := range r.Secrets {
			out = append(out, a.secret(path, s))
		}
		for _, m := range r.Misconfigurations {
			out = append(out, a.misconfiguration(path, m))
		}
	}
	normalize.SortFindings(out)
	return out
}

func (a *Adapter) vulnerability(r Result, path string, v Vulnerability) normalize.Finding {
	f := normalize.Finding{
		Kind:  normalize.KindVulnerability,
		Title: firstNonEmpty(v.Title, v.VulnerabilityID, "vulnerabilidad"),
		Severity: normalize.SeverityInfo{
			Original:   v.Severity,
			Normalized: normalize.NormalizeSeverity(ID, v.Severity),
			Source:     ID,
		},
		Sources:  []normalize.SourceRef{{Engine: ID, Version: a.Version}},
		Evidence: normalize.Evidence{Redacted: true},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	if v.Description != "" {
		f.Descriptions = []normalize.Description{{Text: v.Description, Source: ID}}
	}
	f.AddID(idType(v.VulnerabilityID), v.VulnerabilityID)
	for _, c := range v.CweIDs {
		f.AddID("CWE", c)
	}
	f.Package = &normalize.PackageRef{
		Ecosystem:    ecosystem(r.Type, v.PkgIdentifier.PURL),
		Name:         v.PkgName,
		Version:      v.InstalledVersion,
		FixedVersion: stringPtr(v.FixedVersion),
	}
	f.AddLocation(normalize.Location{Path: path})
	if v.FixedVersion != "" {
		f.Remediation = []normalize.Remediation{{
			Description: fmt.Sprintf("Actualizar %s de %s a %s o superior", v.PkgName, v.InstalledVersion, v.FixedVersion),
			Source:      "advisory",
		}}
	}
	f.Priority = cvssPriority(v.CVSS)
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

func (a *Adapter) secret(path string, s Secret) normalize.Finding {
	original := firstNonEmpty(s.Severity, "UNKNOWN")
	f := normalize.Finding{
		Kind:  normalize.KindSecret,
		Title: firstNonEmpty(s.Title, s.RuleID, "secreto expuesto"),
		Severity: normalize.SeverityInfo{
			Original:   original,
			Normalized: normalize.NormalizeSeverity(ID, original),
			Source:     ID,
		},
		Sources: []normalize.SourceRef{{Engine: ID, Version: a.Version, Rule: s.RuleID}},
		Evidence: normalize.Evidence{
			Snippet:  a.Masker.Redact(secretSnippet(s), []string{s.Match}),
			Redacted: true,
		},
		Policy: normalize.FindingPolicy{Status: "active"},
	}
	f.AddID("RULE", s.RuleID)
	loc := normalize.Location{Path: path}
	if s.StartLine > 0 {
		loc.StartLine = intPtr(s.StartLine)
	}
	if s.EndLine > 0 {
		loc.EndLine = intPtr(s.EndLine)
	}
	f.AddLocation(loc)
	f.Remediation = []normalize.Remediation{{
		Description: "Revocar y rotar la credencial, retirarla del código y del historial; borrarla no basta",
		Source:      "cgc-scan",
	}}
	if s.Match != "" {
		f.Fingerprint = normalize.FingerprintSecret(a.Masker, s.RuleID, path, s.Match)
	} else {
		f.Fingerprint = normalize.Fingerprint(&f)
	}
	return f
}

func (a *Adapter) misconfiguration(path string, m Misconfiguration) normalize.Finding {
	f := normalize.Finding{
		Kind:  normalize.KindMisconfig,
		Title: firstNonEmpty(m.Title, m.ID, "configuración insegura"),
		Severity: normalize.SeverityInfo{
			Original:   m.Severity,
			Normalized: normalize.NormalizeSeverity(ID, m.Severity),
			Source:     ID,
		},
		Sources: []normalize.SourceRef{{Engine: ID, Version: a.Version, Rule: m.ID}},
		Evidence: normalize.Evidence{
			Snippet:  masking.Sanitize(m.Message),
			Redacted: true,
		},
		Policy: normalize.FindingPolicy{Status: "active"},
	}
	if m.Description != "" {
		f.Descriptions = []normalize.Description{{Text: masking.Sanitize(m.Description), Source: ID}}
	}
	f.AddID("RULE", m.ID)
	if m.AVDID != "" {
		f.AddID("OTHER", m.AVDID)
	}
	loc := normalize.Location{Path: path}
	if m.CauseMetadata.StartLine > 0 {
		loc.StartLine = intPtr(m.CauseMetadata.StartLine)
		loc.EndLine = intPtr(m.CauseMetadata.EndLine)
	}
	f.AddLocation(loc)
	if m.Resolution != "" {
		f.Remediation = []normalize.Remediation{{Description: masking.Sanitize(m.Resolution), Source: ID}}
	}
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

// Redact enmascara los secretos conocidos en la salida original y sanea el
// texto antes de persistirla (design §5.2, CA-13).
func (a *Adapter) Redact(raw []byte) []byte {
	_, secrets, err := a.parse(raw)
	if err != nil {
		return masking.SanitizeBytes(raw)
	}
	return a.Masker.RedactBytes(raw, secrets)
}

func secretSnippet(s Secret) string {
	var lines []string
	for _, l := range s.Code.Lines {
		lines = append(lines, l.Content)
	}
	if len(lines) > 0 {
		return strings.Join(lines, "\n")
	}
	return s.Category
}

func normalizePath(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/src/")
	if p == "" {
		return "."
	}
	return p
}

func ecosystem(trivyType, purl string) string {
	if i := strings.Index(purl, "/"); strings.HasPrefix(purl, "pkg:") && i > 4 {
		kind := purl[4:i]
		if j := strings.Index(kind, ":"); j >= 0 {
			kind = kind[:j]
		}
		switch kind {
		case "golang":
			return "Go"
		case "npm":
			return "npm"
		case "composer":
			return "Packagist"
		case "cargo":
			return "crates.io"
		case "pypi":
			return "PyPI"
		}
	}
	switch trivyType {
	case "gomod":
		return "Go"
	case "npm", "yarn", "pnpm":
		return "npm"
	case "composer":
		return "Packagist"
	case "cargo":
		return "crates.io"
	case "pip", "poetry", "pipenv", "uv", "requirements":
		return "PyPI"
	}
	if trivyType == "" {
		return "unknown"
	}
	return trivyType
}

func idType(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GHSA"
	case strings.HasPrefix(id, "GO-"):
		return "GO"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "RUSTSEC"
	case strings.HasPrefix(id, "CWE-"):
		return "CWE"
	}
	return "OTHER"
}

func cvssPriority(scores map[string]CVSS) *normalize.Priority {
	if len(scores) == 0 {
		return nil
	}
	keys := make([]string, 0, len(scores))
	for k := range scores {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var best CVSS
	for _, k := range keys {
		c := scores[k]
		if c.V3Score > best.V3Score {
			best = c
		}
	}
	if best.V3Score == 0 && best.V3Vector == "" {
		return nil
	}
	score := best.V3Score
	p := &normalize.Priority{CVSSScore: &score}
	if best.V3Vector != "" {
		v := best.V3Vector
		p.CVSSVector = &v
	}
	return p
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func intPtr(i int) *int { return &i }
