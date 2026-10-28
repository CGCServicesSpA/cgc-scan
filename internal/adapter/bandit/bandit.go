// Package bandit implementa el adaptador de Python con Bandit.
package bandit

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
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
const ID = "bandit"

// Adapter ejecuta Bandit sobre unidades Python.
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

// Applies cubre unidades Python.
func (a *Adapter) Applies(u discovery.Unit) bool {
	if u.Kind == "repository" {
		return false
	}
	for _, l := range u.Languages {
		if l == discovery.Python {
			return true
		}
	}
	return false
}

// Requirements comprueba el entorno de Bandit.
func (a *Adapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	if a.Install.Dir == "" {
		return []adapter.Requirement{{Kind: "binary", Name: "bandit", Detail: "no aprovisionado", Missing: true}}
	}
	return nil
}

// Invocations ejecuta Bandit con salida JSON.
func (a *Adapter) Invocations(u discovery.Unit, _ plan.Plan) ([]runner.Invocation, error) {
	bin := filepath.Join(a.Install.Dir, "venv", "bin", "bandit")
	return []runner.Invocation{{
		Engine:  ID,
		Binary:  bin,
		Args:    []string{"-r", ".", "-f", "json", "-q"},
		Dir:     filepath.Join(a.Root, u.Path),
		Timeout: 10 * time.Minute,
		Env:     map[string]string{"NO_COLOR": "1"},
	}}, nil
}

// AcceptExit acepta 0 (limpio) y 1 (hallazgos).
func (a *Adapter) AcceptExit(code int) bool { return code == 0 || code == 1 }

// Report es el JSON de Bandit.
type Report struct {
	Results []Result `json:"results"`
	Errors  []struct {
		Filename string `json:"filename"`
		Reason   string `json:"reason"`
	} `json:"errors"`
}

// Result es un hallazgo de Bandit.
type Result struct {
	Code            string `json:"code"`
	Filename        string `json:"filename"`
	IssueConfidence string `json:"issue_confidence"`
	IssueSeverity   string `json:"issue_severity"`
	IssueText       string `json:"issue_text"`
	LineNumber      int    `json:"line_number"`
	LineRange       []int  `json:"line_range"`
	MoreInfo        string `json:"more_info"`
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	IssueCWE        struct {
		ID int `json:"id"`
	} `json:"issue_cwe"`
}

// Parse interpreta el JSON.
func (a *Adapter) Parse(raw []byte) (adapter.Parsed, error) {
	if len(raw) == 0 {
		return adapter.Parsed{}, fmt.Errorf("salida de bandit vacía")
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return adapter.Parsed{}, fmt.Errorf("salida de bandit no es JSON válido: %w", err)
	}
	secrets := reportSecrets(rep)
	out := make([]normalize.Finding, 0, len(rep.Results))
	for _, r := range rep.Results {
		out = append(out, a.toFinding(r, secrets))
	}
	var diags []adapter.Diagnostic
	for _, e := range rep.Errors {
		diags = append(diags, adapter.Diagnostic{Engine: ID, Message: e.Filename + ": " + e.Reason})
	}
	normalize.SortFindings(out)
	return adapter.Parsed{Findings: out, Diagnostics: diags}, nil
}

var quoted = regexp.MustCompile(`["']([^"']{4,})["']`)

func (a *Adapter) toFinding(r Result, secrets []string) normalize.Finding {
	path := a.relative(r.Filename)
	sev := normalize.NormalizeSeverity(ID, r.IssueSeverity)
	conf := normalize.Confidence(strings.ToLower(r.IssueConfidence))
	f := normalize.Finding{
		Kind:       normalize.KindCode,
		Title:      masking.Sanitize(r.IssueText),
		Severity:   normalize.SeverityInfo{Original: r.IssueSeverity, Normalized: sev, Source: ID},
		Confidence: &conf,
		Sources:    []normalize.SourceRef{{Engine: ID, Version: a.Install.Version, Rule: r.TestID}},
		Evidence: normalize.Evidence{
			Snippet:  a.Masker.Redact(r.Code, secrets),
			Redacted: true,
		},
		Policy: normalize.FindingPolicy{Status: "active"},
	}
	f.AddID("RULE", r.TestID)
	if r.IssueCWE.ID > 0 {
		f.AddID("CWE", fmt.Sprintf("CWE-%d", r.IssueCWE.ID))
	}
	loc := normalize.Location{Path: path}
	if r.LineNumber > 0 {
		line := r.LineNumber
		loc.StartLine = &line
	}
	if len(r.LineRange) > 0 {
		end := r.LineRange[len(r.LineRange)-1]
		loc.EndLine = &end
	}
	f.AddLocation(loc)
	if r.MoreInfo != "" {
		f.Remediation = []normalize.Remediation{{Description: "Revisar la recomendación del motor", Source: r.MoreInfo}}
	}
	// El texto del hallazgo puede contener el valor del secreto (B105).
	if strings.HasPrefix(r.TestID, "B10") {
		f.Title = a.Masker.Redact(r.IssueText, secrets)
	}
	f.Fingerprint = normalize.Fingerprint(&f)
	return f
}

// reportSecrets extrae los valores que Bandit incluye en reglas de secretos
// embebidos (B105-B107) para enmascararlos en todas las evidencias.
func reportSecrets(rep Report) []string {
	var out []string
	for _, r := range rep.Results {
		if !strings.HasPrefix(r.TestID, "B10") {
			continue
		}
		for _, m := range quoted.FindAllStringSubmatch(r.IssueText, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

func (a *Adapter) relative(path string) string {
	rel, err := filepath.Rel(a.Root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// Redact enmascara y sanea la salida.
func (a *Adapter) Redact(raw []byte) []byte {
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return a.Masker.RedactBytes(raw, nil)
	}
	return a.Masker.RedactBytes(raw, reportSecrets(rep))
}

// RecipeCandidates propone pytest.
func (a *Adapter) RecipeCandidates(u discovery.Unit) []adapter.RecipeCandidate {
	return []adapter.RecipeCandidate{
		{Unit: u.ID, Kind: "test", Command: "pytest", Workdir: u.Path, Origin: "adapter"},
	}
}
