package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func newTestPaths(t *testing.T) platform.Paths {
	t.Helper()
	dir := t.TempDir()
	return platform.Paths{
		ConfigDir: filepath.Join(dir, "config"),
		DataDir:   filepath.Join(dir, "data"),
		CacheDir:  filepath.Join(dir, "cache"),
	}
}

func finding(fp, engine, path string, kind normalize.Kind) normalize.Finding {
	return normalize.Finding{
		Fingerprint: fp, Kind: kind, Title: "x",
		Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: engine},
		Sources:   []normalize.SourceRef{{Engine: engine}},
		Locations: []normalize.Location{{Path: path}},
		Policy:    normalize.FindingPolicy{Status: "active"},
	}
}

func verifyDoc(id string, findings ...normalize.Finding) *report.Document {
	d := &report.Document{
		Run: report.Run{ID: id, CLIVersion: "0.1.0"},
		Target: report.Target{Root: "/p", Units: []report.UnitInfo{
			{ID: "project", Path: ".", Kind: "repository"},
			{ID: "svc", Path: "svc", Kind: "module"},
			{ID: "other", Path: "other", Kind: "module"},
		}},
		Coverage: report.Coverage{
			Units: []report.UnitCoverage{
				{ID: "project", Path: ".", Status: "completed", Engines: []report.EngineState{}},
				{ID: "svc", Path: "svc", Status: "completed", Engines: []report.EngineState{}},
				{ID: "other", Path: "other", Status: "completed", Engines: []report.EngineState{}},
			},
			Limitations: []string{},
		},
		Tools: report.Tools{Engines: []report.EngineReport{
			{ID: "eslint", Version: "10", Status: "completed", Mode: "global", Units: []report.EngineState{
				{ID: "svc", Status: "completed"}, {ID: "other", Status: "completed"},
			}},
		}},
		Isolation:  report.Isolation{Level: "configured"},
		Validation: report.Validation{Recipes: []report.Recipe{}, Unresolved: []report.Unresolved{}},
		Findings:   findings, Policy: report.Policy{FailOn: "high", Exceptions: []report.ExceptionReport{}},
		Errors: []report.Error{},
	}
	d.Normalize()
	return d
}

func TestMergeVerificationKeepsOtherUnits(t *testing.T) {
	a := strings.Repeat("a", 32)
	b := strings.Repeat("b", 32)
	c := strings.Repeat("c", 32)
	prev := verifyDoc("prev",
		finding(a, "trivy", "svc/go.mod", normalize.KindVulnerability),
		finding(b, "eslint", "svc/a.js", normalize.KindCode),
		finding(c, "eslint", "other/a.js", normalize.KindCode),
	)
	cur := verifyDoc("cur")
	cur.Tools.Engines = []report.EngineReport{{
		ID: "eslint", Version: "10", Status: "completed", Mode: "global",
		Units: []report.EngineState{{ID: "svc", Status: "completed"}},
	}}
	cur.Coverage.Units = []report.UnitCoverage{{ID: "svc", Path: "svc", Status: "completed", Engines: []report.EngineState{}}}
	sel := selectorInfo{ID: "fp-b", Kind: "fingerprint", Unit: "svc", Engines: []string{"eslint"}, Fixes: []string{b}}
	merged := mergeVerification(prev, cur, sel)
	if len(merged.Findings) != 2 {
		t.Fatalf("hallazgos = %+v", merged.Findings)
	}
	got := map[string]bool{}
	for _, f := range merged.Findings {
		got[f.Fingerprint] = true
	}
	if !got[a] || !got[c] || got[b] {
		t.Fatalf("fusión incorrecta: %v", got)
	}
}

func TestMergeVerificationReplacesChangedFinding(t *testing.T) {
	b := strings.Repeat("b", 32)
	d := strings.Repeat("d", 32)
	prev := verifyDoc("prev", finding(b, "eslint", "svc/a.js", normalize.KindCode))
	cur := verifyDoc("cur", finding(d, "eslint", "svc/a.js", normalize.KindCode))
	cur.Tools.Engines = []report.EngineReport{{
		ID: "eslint", Version: "10", Status: "completed", Mode: "global",
		Units: []report.EngineState{{ID: "svc", Status: "completed"}},
	}}
	sel := selectorInfo{ID: "rg-code-svc", Kind: "group", Unit: "svc", Engines: []string{"eslint"}, Fixes: []string{b}}
	merged := mergeVerification(prev, cur, sel)
	if len(merged.Findings) != 1 || merged.Findings[0].Fingerprint != d {
		t.Fatalf("hallazgos = %+v", merged.Findings)
	}
	store, _ := projectstate.Open(newTestPaths(t), "/p")
	out := buildVerifyDocument(store, merged, sel, cur)
	if out.Status != "resolved" || out.Fixes[0].Status != "resolved" {
		t.Fatalf("resultado = %+v", out)
	}
}

func TestResolveSelectorFingerprintAndGroup(t *testing.T) {
	a := strings.Repeat("a", 32)
	doc := verifyDoc("x", finding(a, "eslint", "svc/a.js", normalize.KindCode))
	doc.RemediationGroups = []report.RemediationGroup{{
		ID: "rg-code-svc", Kind: "code_fix", Unit: "svc", Fixes: []string{a},
	}}
	idx := projectstate.BuildIndex(doc)
	sel, err := resolveSelector(doc, nil, idx, a)
	if err != nil || sel.Kind != "fingerprint" || sel.Unit != "svc" {
		t.Fatalf("selector = %+v, %v", sel, err)
	}
	sel, err = resolveSelector(doc, nil, idx, "rg-code-svc")
	if err != nil || sel.Kind != "group" || len(sel.Fixes) != 1 {
		t.Fatalf("selector grupo = %+v, %v", sel, err)
	}
	if _, err := resolveSelector(doc, nil, idx, "no-existe"); err == nil {
		t.Fatal("se esperaba error")
	}
}
