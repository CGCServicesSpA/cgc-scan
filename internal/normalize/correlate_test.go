package normalize

import (
	"testing"
)

func dep(fingerprint, engine, severity string, version string, ids ...string) Finding {
	f := Finding{
		Fingerprint: fingerprint,
		Kind:        KindVulnerability,
		Title:       "CVE en componente",
		Severity:    SeverityInfo{Original: severity, Normalized: Severity(severity), Source: engine},
		Package:     &PackageRef{Ecosystem: "Go", Name: "golang.org/x/text", Version: version},
		Locations:   []Location{{Path: "go.mod"}},
		Sources:     []SourceRef{{Engine: engine}},
		Evidence:    Evidence{Redacted: true},
	}
	for _, id := range ids {
		f.AddID("CVE", id)
	}
	return f
}

func TestCorrelateDependencies(t *testing.T) {
	a := dep("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "trivy", "high", "v0.3.0", "CVE-2021-1")
	b := dep("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "govulncheck", "medium", "v0.3.0", "CVE-2021-1")
	out := Correlate([]Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("hallazgos = %d", len(out))
	}
	got := out[0]
	if got.Severity.Normalized != SeverityHigh {
		t.Fatalf("severidad = %s", got.Severity.Normalized)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("fuentes = %+v", got.Sources)
	}
	if len(got.SeverityOthers) != 1 || got.SeverityOthers[0].Source != "govulncheck" {
		t.Fatalf("diferencias = %+v", got.SeverityOthers)
	}
	if got.Correlation == nil || len(got.Correlation.MergedFingerprints) != 1 {
		t.Fatalf("correlación = %+v", got.Correlation)
	}
}

func TestCorrelateKeepsDifferentVersions(t *testing.T) {
	a := dep("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "trivy", "high", "v0.3.0", "CVE-2021-1")
	b := dep("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "trivy", "high", "v0.4.0", "CVE-2021-1")
	if out := Correlate([]Finding{a, b}); len(out) != 2 {
		t.Fatalf("se fusionaron versiones distintas: %d", len(out))
	}
}

func TestCorrelateCodeByContext(t *testing.T) {
	base := func(fp, msg string) Finding {
		f := Finding{
			Fingerprint: fp, Kind: KindCode, Title: msg,
			Severity:  SeverityInfo{Original: "error", Normalized: SeverityHigh, Source: "eslint"},
			Locations: []Location{{Path: "src/a.js"}},
			Sources:   []SourceRef{{Engine: "eslint", Rule: "security/detect-eval-with-expression"}},
			Evidence:  Evidence{Snippet: msg},
		}
		f.AddID("CWE", "CWE-95")
		return f
	}
	same := Correlate([]Finding{base("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "eval(x)"), base("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "eval(x)")})
	if len(same) != 1 {
		t.Fatalf("mismo contexto no se fusionó: %d", len(same))
	}
	diff := Correlate([]Finding{base("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "eval(x)"), base("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "eval(y)")})
	if len(diff) != 2 {
		t.Fatalf("contextos distintos se fusionaron: %d", len(diff))
	}
}

func TestCorrelateDoesNotMergeSecrets(t *testing.T) {
	a := Finding{Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: KindSecret, Title: "a", Severity: SeverityInfo{Normalized: SeverityHigh}, Locations: []Location{{Path: "x"}}}
	b := Finding{Fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Kind: KindSecret, Title: "b", Severity: SeverityInfo{Normalized: SeverityHigh}, Locations: []Location{{Path: "x"}}}
	if out := Correlate([]Finding{a, b}); len(out) != 2 {
		t.Fatal("se fusionaron secretos distintos")
	}
}
