// Package psalm implementa el adaptador de PHP con análisis de taint y una
// configuración generada por la CLI (nunca la del repositorio).
package psalm

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
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// ID identifica el motor.
const ID = "psalm"

// Adapter ejecuta Psalm.
type Adapter struct {
	Install provision.AdapterInstall
	Root    string
	RunDir  string
	Masker  *masking.Masker
}

// New construye el adaptador.
func New(install provision.AdapterInstall, root, runDir string, m *masking.Masker) *Adapter {
	return &Adapter{Install: install, Root: root, RunDir: runDir, Masker: m}
}

func (a *Adapter) ID() string { return ID }

// Applies cubre unidades PHP.
func (a *Adapter) Applies(u discovery.Unit) bool {
	if u.Kind == "repository" {
		return false
	}
	for _, l := range u.Languages {
		if l == discovery.PHP {
			return true
		}
	}
	return false
}

// Requirements comprueba PHP, el phar y las dependencias de Composer.
func (a *Adapter) Requirements(_ context.Context, u discovery.Unit) []adapter.Requirement {
	var reqs []adapter.Requirement
	if _, err := exec.LookPath("php"); err != nil {
		reqs = append(reqs, adapter.Requirement{Kind: "toolchain", Name: "php", Detail: "no está en PATH", Missing: true})
	}
	if a.Install.Dir == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "binary", Name: "psalm", Detail: "no aprovisionado", Missing: true})
	}
	unitDir := filepath.Join(a.Root, u.Path)
	if _, err := os.Stat(filepath.Join(unitDir, "composer.json")); err == nil {
		if _, err := os.Stat(filepath.Join(unitDir, "vendor", "autoload.php")); err != nil {
			reqs = append(reqs, adapter.Requirement{
				Kind: "dependencies", Name: "composer vendor/autoload.php",
				Detail: "ejecuta composer install en la unidad", Missing: true,
			})
		}
	}
	return reqs
}

// Invocations genera la configuración y ejecuta Psalm con taint analysis.
func (a *Adapter) Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error) {
	php, err := exec.LookPath("php")
	if err != nil {
		return nil, fmt.Errorf("psalm: php no está en PATH")
	}
	if err := os.MkdirAll(a.RunDir, 0o700); err != nil {
		return nil, err
	}
	unitDir := filepath.Join(a.Root, u.Path)
	cfg := filepath.Join(a.RunDir, "psalm-"+safeName(u.ID)+".xml")
	if err := os.WriteFile(cfg, psalmConfig(unitDir, p.Exclusions), 0o600); err != nil {
		return nil, err
	}
	args := []string{
		filepath.Join(a.Install.Dir, "psalm.phar"),
		"--config=" + cfg, "--no-cache", "--taint-analysis",
		"--output-format=json", "--no-progress",
	}
	return []runner.Invocation{{
		Engine:  ID,
		Binary:  php,
		Args:    args,
		Dir:     unitDir,
		Timeout: 15 * time.Minute,
		Env:     map[string]string{"NO_COLOR": "1"},
	}}, nil
}

// psalmConfig genera un XML con el directorio de la unidad y las exclusiones
// expresables. Un patrón que Psalm no puede expresar no se silencia: la CLI lo
// declara en la cobertura y el adaptador no promete cobertura completa.
func psalmConfig(unitDir string, exclusions []discovery.Exclusion) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n")
	b.WriteString(`<psalm errorLevel="1" resolveFromConfigFile="true" findUnusedBaselineEntry="false" findUnusedCode="false">` + "\n")
	b.WriteString("  <projectFiles>\n")
	b.WriteString(`    <directory name="` + xmlEscape(unitDir) + `"/>` + "\n")
	var ignored []string
	for _, e := range exclusions {
		pat := strings.TrimPrefix(e.Pattern, "**/")
		pat = strings.TrimSuffix(pat, "/**")
		if pat == "" || strings.Contains(pat, "*") {
			continue
		}
		p := filepath.Join(unitDir, filepath.FromSlash(pat))
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			ignored = append(ignored, p)
		}
	}
	if len(ignored) > 0 {
		b.WriteString("    <ignoreFiles>\n")
		for _, p := range ignored {
			b.WriteString(`      <directory name="` + xmlEscape(p) + `"/>` + "\n")
		}
		b.WriteString("    </ignoreFiles>\n")
	}
	b.WriteString("  </projectFiles>\n")
	b.WriteString("</psalm>\n")
	return []byte(b.String())
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func safeName(s string) string {
	r := strings.NewReplacer("/", "_", ".", "_", string(filepath.Separator), "_")
	return r.Replace(s)
}

// AcceptExit acepta 0 (limpio), 1 y 2 (problemas encontrados).
func (a *Adapter) AcceptExit(code int) bool { return code >= 0 && code <= 2 }

// Issue es un problema de Psalm.
type Issue struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	FileName   string `json:"file_name"`
	FilePath   string `json:"file_path"`
	LineFrom   int    `json:"line_from"`
	LineTo     int    `json:"line_to"`
	ColumnFrom int    `json:"column_from"`
	ColumnTo   int    `json:"column_to"`
	Snippet    string `json:"snippet"`
	Link       string `json:"link"`
	TaintTrace []struct {
		Label    string `json:"label"`
		FileName string `json:"file_name"`
		LineFrom int    `json:"line_from"`
	} `json:"taint_trace"`
}

// Parse interpreta el arreglo JSON de Psalm.
func (a *Adapter) Parse(raw []byte) (adapter.Parsed, error) {
	if len(raw) == 0 {
		return adapter.Parsed{}, fmt.Errorf("salida de psalm vacía")
	}
	var issues []Issue
	if err := json.Unmarshal(raw, &issues); err != nil {
		return adapter.Parsed{}, fmt.Errorf("salida de psalm no es JSON válido: %w", err)
	}
	out := make([]normalize.Finding, 0, len(issues))
	for _, is := range issues {
		out = append(out, a.toFinding(is))
	}
	normalize.SortFindings(out)
	return adapter.Parsed{Findings: out}, nil
}

func (a *Adapter) toFinding(is Issue) normalize.Finding {
	sev := severityFor(is.Type, is.Severity)
	path := a.relative(firstNonEmpty(is.FilePath, is.FileName))
	f := normalize.Finding{
		Kind:  normalize.KindCode,
		Title: masking.Sanitize(firstNonEmpty(is.Message, is.Type)),
		Severity: normalize.SeverityInfo{
			Original: is.Type, Normalized: sev, Source: ID,
		},
		Sources:  []normalize.SourceRef{{Engine: ID, Version: a.Install.Version, Rule: is.Type}},
		Evidence: normalize.Evidence{Snippet: masking.Sanitize(is.Snippet), Redacted: true},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	f.AddID("RULE", is.Type)
	if is.Link != "" {
		f.References = append(f.References, masking.Sanitize(is.Link))
	}
	if len(is.TaintTrace) > 0 {
		labels := make([]string, 0, len(is.TaintTrace))
		for _, t := range is.TaintTrace {
			if t.Label != "" {
				labels = append(labels, masking.Sanitize(t.Label))
			}
		}
		if len(labels) > 0 {
			f.Descriptions = append(f.Descriptions, normalize.Description{
				Text: "Flujo de datos: " + strings.Join(labels, " -> "), Source: ID,
			})
		}
	}
	loc := normalize.Location{Path: path}
	if is.LineFrom > 0 {
		line := is.LineFrom
		loc.StartLine = &line
	}
	if is.LineTo > 0 {
		end := is.LineTo
		loc.EndLine = &end
	}
	if is.ColumnFrom > 0 {
		c := is.ColumnFrom
		loc.StartColumn = &c
	}
	if is.ColumnTo > 0 {
		c := is.ColumnTo
		loc.EndColumn = &c
	}
	f.AddLocation(loc)
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

func (a *Adapter) relative(path string) string {
	if path == "" {
		return "."
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.Root, path)
	}
	rel, err := filepath.Rel(a.Root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// Redact sanea la salida antes de persistirla.
func (a *Adapter) Redact(raw []byte) []byte { return a.Masker.RedactBytes(raw, nil) }

// severityFor aplica la tabla de categorías de design §8.3.
func severityFor(issueType, original string) normalize.Severity {
	switch issueType {
	case "TaintedShell", "TaintedCommand", "TaintedEval", "TaintedInclude", "TaintedUnserialize":
		return normalize.SeverityHigh
	case "TaintedSql", "TaintedHeader", "TaintedLdap", "TaintedHtml", "TaintedText",
		"TaintedFile", "TaintedPath", "TaintedCookie", "TaintedSSRF", "TaintedTextWithQuotes":
		return normalize.SeverityMedium
	case "PossiblyUnusedMethod", "UnusedVariable", "MissingReturnType":
		return normalize.SeverityInformational
	}
	switch strings.ToLower(original) {
	case "error":
		return normalize.SeverityMedium
	case "info":
		return normalize.SeverityInformational
	}
	return normalize.SeverityUnknown
}

// RecipeCandidates lee los scripts de composer.json.
func (a *Adapter) RecipeCandidates(u discovery.Unit) []adapter.RecipeCandidate {
	dir := filepath.Join(a.Root, u.Path)
	data, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]any `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var out []adapter.RecipeCandidate
	for _, kind := range []string{"test", "build"} {
		if _, ok := pkg.Scripts[kind]; ok {
			out = append(out, adapter.RecipeCandidate{
				Unit: u.ID, Kind: kind, Command: "composer run-script " + kind,
				Workdir: u.Path, Origin: "composer.json",
			})
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
