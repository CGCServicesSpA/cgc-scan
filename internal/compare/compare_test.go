package compare

import (
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func fp(s string) string { return strings.Repeat(s, 32)[:32] }

func doc(id string, partial bool, findings ...normalize.Finding) *report.Document {
	d := &report.Document{
		SchemaVersion: "1.0.0",
		Run:           report.Run{ID: id},
		Target:        report.Target{Root: "/p", LocalID: "local:p", Units: []report.UnitInfo{}},
		Coverage:      report.Coverage{Partial: partial, Exclusions: []report.ExclusionReport{}, NotAnalyzed: []report.NotAnalyzedReport{}, Units: []report.UnitCoverage{}, Limitations: []string{}},
		Tools:         report.Tools{Engines: []report.EngineReport{}},
		Isolation:     report.Isolation{Level: "configured"},
		Validation:    report.Validation{Recipes: []report.Recipe{}, Unresolved: []report.Unresolved{}},
		Findings:      findings,
		Policy:        report.Policy{FailOn: "high", Exceptions: []report.ExceptionReport{}},
		Errors:        []report.Error{},
	}
	d.Normalize()
	return d
}

func finding(f string, sev normalize.Severity) normalize.Finding {
	return normalize.Finding{
		Fingerprint: f, Kind: normalize.KindVulnerability, Title: "t",
		Severity:  normalize.SeverityInfo{Normalized: sev, Source: "trivy"},
		Locations: []normalize.Location{{Path: "go.mod"}},
		Sources:   []normalize.SourceRef{{Engine: "trivy"}},
	}
}

func TestCompareNewPersistentResolved(t *testing.T) {
	prev := doc("p", false, finding(fp("a"), normalize.SeverityHigh), finding(fp("b"), normalize.SeverityLow))
	cur := doc("c", false, finding(fp("b"), normalize.SeverityLow), finding(fp("c"), normalize.SeverityCritical))
	res := Compare(prev, cur)
	if len(res.New) != 1 || res.New[0].Fingerprint != fp("c") {
		t.Fatalf("nuevos = %+v", res.New)
	}
	if len(res.Persistent) != 1 || res.Persistent[0].Fingerprint != fp("b") {
		t.Fatalf("persistentes = %+v", res.Persistent)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].Fingerprint != fp("a") {
		t.Fatalf("resueltos = %+v", res.Resolved)
	}
	if !res.CoverageComparable {
		t.Fatal("la cobertura debería ser comparable")
	}
}

func TestComparePartialDoesNotResolve(t *testing.T) {
	prev := doc("p", false, finding(fp("a"), normalize.SeverityHigh))
	cur := doc("c", true)
	res := Compare(prev, cur)
	if len(res.Resolved) != 0 {
		t.Fatalf("un escaneo parcial resolvió hallazgos: %+v", res.Resolved)
	}
	if len(res.NotEvaluated) != 1 {
		t.Fatalf("no evaluados = %+v", res.NotEvaluated)
	}
	if res.CoverageComparable {
		t.Fatal("la cobertura no debería ser comparable")
	}
}

func TestCompareErrorsPreventResolution(t *testing.T) {
	prev := doc("p", false, finding(fp("a"), normalize.SeverityHigh))
	cur := doc("c", false)
	cur.Errors = []report.Error{{Code: "engine_failed", Scope: "trivy", Message: "x", Retryable: true}}
	res := Compare(prev, cur)
	if len(res.Resolved) != 0 || len(res.NotEvaluated) != 1 {
		t.Fatalf("resultado = %+v", res)
	}
}
