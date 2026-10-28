// Package eslint implementa el adaptador de JavaScript y TypeScript con una
// configuración propia y sin cargar configuración del repositorio (T-05).
package eslint

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
const ID = "eslint"

// Adapter ejecuta ESLint sobre unidades JavaScript y TypeScript.
type Adapter struct {
	Install provision.AdapterInstall
	Root    string
	Masker  *masking.Masker
}

// New construye el adaptador.
func New(install provision.AdapterInstall, root string, m *masking.Masker) *Adapter {
	return &Adapter{Install: install, Root: root, Masker: m}
}

func (a *Adapter) ID() string { return ID }

// Applies cubre unidades con JavaScript o TypeScript.
func (a *Adapter) Applies(u discovery.Unit) bool {
	if u.Kind == "repository" {
		return false
	}
	for _, l := range u.Languages {
		if l == discovery.JavaScript || l == discovery.TypeScript {
			return true
		}
	}
	return false
}

// Requirements comprueba Node y el árbol npm fijado.
func (a *Adapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	var reqs []adapter.Requirement
	if _, err := exec.LookPath("node"); err != nil {
		reqs = append(reqs, adapter.Requirement{Kind: "toolchain", Name: "node", Detail: "no está en PATH", Missing: true})
	}
	if a.Install.Dir == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "binary", Name: "eslint", Detail: "no aprovisionado", Missing: true})
	}
	return reqs
}

// Invocations ejecuta ESLint con la configuración generada y propaga las
// exclusiones al motor (T-08).
func (a *Adapter) Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error) {
	node, err := exec.LookPath("node")
	if err != nil {
		return nil, fmt.Errorf("eslint: node no está en PATH")
	}
	script := filepath.Join(a.Install.Dir, "node_modules", "eslint", "bin", "eslint.js")
	config := filepath.Join(a.Install.Dir, "cgc-eslint.config.mjs")
	args := []string{
		script, "--no-config-lookup", "--config", config, "--format", "json",
	}
	for _, e := range p.Exclusions {
		if pat := expressible(e.Pattern); pat != "" {
			args = append(args, "--ignore-pattern", pat)
		}
	}
	args = append(args, ".")
	return []runner.Invocation{{
		Engine:  ID,
		Binary:  node,
		Args:    args,
		Dir:     filepath.Join(a.Root, u.Path),
		Timeout: 10 * time.Minute,
		Env:     map[string]string{"NO_COLOR": "1", "CI": "1"},
	}}, nil
}

// expressible traduce un patrón de exclusión a la sintaxis de ESLint.
func expressible(pattern string) string {
	p := strings.TrimPrefix(pattern, "**/")
	p = strings.TrimSuffix(p, "/**")
	if p == "" {
		return ""
	}
	return p + "/**"
}

// AcceptExit acepta 0 (limpio) y 1 (errores de lint). Un 2 es un fallo del
// motor o de la configuración.
func (a *Adapter) AcceptExit(code int) bool { return code == 0 || code == 1 }

// Result es el JSON de ESLint por archivo.
type Result struct {
	FilePath   string    `json:"filePath"`
	Messages   []Message `json:"messages"`
	ErrorCount int       `json:"errorCount"`
}

// Message es un mensaje de ESLint.
type Message struct {
	RuleID    string `json:"ruleId"`
	Severity  int    `json:"severity"`
	Message   string `json:"message"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"endLine"`
	EndColumn int    `json:"endColumn"`
	Fatal     bool   `json:"fatal"`
}

// Parse interpreta el arreglo JSON.
func (a *Adapter) Parse(raw []byte) (adapter.Parsed, error) {
	if len(raw) == 0 {
		return adapter.Parsed{}, fmt.Errorf("salida de eslint vacía")
	}
	var results []Result
	if err := json.Unmarshal(raw, &results); err != nil {
		return adapter.Parsed{}, fmt.Errorf("salida de eslint no es JSON válido: %w", err)
	}
	var (
		findings []normalize.Finding
		diags    []adapter.Diagnostic
	)
	for _, r := range results {
		path := a.relative(r.FilePath)
		for _, m := range r.Messages {
			if m.RuleID == "" || m.Fatal {
				diags = append(diags, adapter.Diagnostic{
					Engine: ID, Message: fmt.Sprintf("%s:%d: %s", path, m.Line, masking.Sanitize(m.Message)),
				})
				continue
			}
			findings = append(findings, a.toFinding(path, m))
		}
	}
	normalize.SortFindings(findings)
	return adapter.Parsed{Findings: findings, Diagnostics: diags}, nil
}

func (a *Adapter) toFinding(path string, m Message) normalize.Finding {
	sev, category := ruleSeverity(m.RuleID)
	rule := m.RuleID
	original := "warning"
	if m.Severity == 2 {
		original = "error"
	}
	f := normalize.Finding{
		Kind:  normalize.KindCode,
		Title: masking.Sanitize(m.Message),
		Severity: normalize.SeverityInfo{
			Original: original, Normalized: sev, Source: ID,
		},
		Sources:  []normalize.SourceRef{{Engine: ID, Version: a.Install.Version, Rule: m.RuleID}},
		Evidence: normalize.Evidence{Snippet: masking.Sanitize(m.Message), Redacted: true},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	f.AddID("RULE", rule)
	f.Descriptions = append(f.Descriptions, normalize.Description{
		Text: "Categoría de riesgo: " + category, Source: "cgc-scan",
	})
	loc := normalize.Location{Path: path}
	if m.Line > 0 {
		line := m.Line
		loc.StartLine = &line
	}
	if m.EndLine > 0 {
		end := m.EndLine
		loc.EndLine = &end
	}
	if m.Column > 0 {
		col := m.Column
		loc.StartColumn = &col
	}
	if m.EndColumn > 0 {
		end := m.EndColumn
		loc.EndColumn = &end
	}
	f.AddLocation(loc)
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

func (a *Adapter) relative(path string) string {
	rel, err := filepath.Rel(a.Root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// Redact sanea la salida antes de persistirla.
func (a *Adapter) Redact(raw []byte) []byte { return a.Masker.RedactBytes(raw, nil) }

// ruleSeverity aplica la tabla de categorías de design §8.3. Una regla sin
// categoría no está habilitada; si aparece igual, queda unknown.
func ruleSeverity(rule string) (normalize.Severity, string) {
	switch rule {
	case "security/detect-eval-with-expression", "security/detect-child-process":
		return normalize.SeverityHigh, "ejecución-de-código"
	case "security/detect-non-literal-require", "security/detect-object-injection",
		"security/detect-non-literal-fs-filename":
		return normalize.SeverityMedium, "resolución-dinámica"
	case "security/detect-non-literal-regexp", "security/detect-possible-timing-attacks",
		"security/detect-pseudoRandomBytes":
		return normalize.SeverityLow, "denegación-de-servicio"
	case "security/detect-bidi-characters":
		return normalize.SeverityMedium, "manipulación-de-texto"
	}
	return normalize.SeverityUnknown, "sin-categoría"
}

// RecipeCandidates lee los scripts de package.json de la unidad.
func (a *Adapter) RecipeCandidates(u discovery.Unit) []adapter.RecipeCandidate {
	for _, m := range u.Manifests {
		if filepath.Base(m) != "package.json" {
			continue
		}
		full := filepath.Join(a.Root, m)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil
		}
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}
		var out []adapter.RecipeCandidate
		dir := filepath.Dir(m)
		for _, kind := range []string{"test", "build"} {
			if cmd, ok := pkg.Scripts[kind]; ok && strings.TrimSpace(cmd) != "" {
				out = append(out, adapter.RecipeCandidate{
					Unit: u.ID, Kind: kind, Command: "npm run " + kind,
					Workdir: dir, Origin: "package.json",
				})
			}
		}
		return out
	}
	return nil
}
