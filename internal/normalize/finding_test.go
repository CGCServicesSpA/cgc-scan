package normalize

import (
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
)

func findingAt(line int, snippet, path string) *Finding {
	l := line
	return &Finding{
		Kind:  KindCode,
		Title: "eval con expresión",
		Severity: SeverityInfo{
			Original: "2", Normalized: SeverityHigh, Source: "eslint",
		},
		Locations: []Location{{Path: path, StartLine: &l}},
		Evidence:  Evidence{Snippet: snippet, Redacted: true},
		Sources:   []SourceRef{{Engine: "eslint", Rule: "security/detect-eval-with-expression"}},
	}
}

func TestFingerprintIgnoresLineNumber(t *testing.T) {
	a := findingAt(3, "eval(req.body.code)", "src/app.js")
	b := findingAt(99, "eval(req.body.code)", "src/app.js")
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("la huella cambió al mover el hallazgo de línea")
	}
}

func TestFingerprintChangesWithContext(t *testing.T) {
	a := findingAt(3, "eval(x)", "src/app.js")
	b := findingAt(3, "eval(y)", "src/app.js")
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("dos contextos distintos produjeron la misma huella")
	}
}

func TestFingerprintChangesWithPath(t *testing.T) {
	a := findingAt(3, "eval(x)", "src/a.js")
	b := findingAt(3, "eval(x)", "src/b.js")
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("dos rutas distintas produjeron la misma huella")
	}
	if len(Fingerprint(a)) != 32 {
		t.Fatalf("huella de longitud %d", len(Fingerprint(a)))
	}
}

func TestFingerprintVulnerabilityUsesCanonicalAdvisory(t *testing.T) {
	pkg := &PackageRef{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.0"}
	a := &Finding{
		Kind: KindVulnerability, Package: pkg,
		IDs:       []Identifier{{Type: "GHSA", Value: "GHSA-xxxx"}, {Type: "CVE", Value: "CVE-2021-0001"}},
		Locations: []Location{{Path: "go.mod"}},
	}
	b := &Finding{
		Kind: KindVulnerability, Package: pkg,
		IDs:       []Identifier{{Type: "CVE", Value: "CVE-2021-0001"}, {Type: "GHSA", Value: "GHSA-xxxx"}},
		Locations: []Location{{Path: "go.mod"}},
	}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("el orden de los identificadores cambió la huella")
	}
}

func TestFingerprintSecretUsesSalt(t *testing.T) {
	m1, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	m2, _ := masking.NewMasker([]byte("ffffffffffffffffffffffffffffffff"))
	a := FingerprintSecret(m1, "github-pat", "app.env", "ghp_secreto")
	b := FingerprintSecret(m2, "github-pat", "app.env", "ghp_secreto")
	if a == b {
		t.Fatal("la huella de secreto no depende de la sal")
	}
	if a != FingerprintSecret(m1, "github-pat", "app.env", "ghp_secreto") {
		t.Fatal("la huella de secreto no es determinista con la misma sal")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		engine, original string
		want             Severity
	}{
		{"trivy", "CRITICAL", SeverityCritical},
		{"trivy", "HIGH", SeverityHigh},
		{"trivy", "UNKNOWN", SeverityUnknown},
		{"trivy", "", SeverityUnknown},
		{"bandit", "MEDIUM", SeverityMedium},
		{"bandit", "UNDEFINED", SeverityUnknown},
		{"semgrep", "ERROR", SeverityHigh},
		{"semgrep", "WARNING", SeverityMedium},
		{"semgrep", "INFO", SeverityInformational},
		{"cargo-audit", "low", SeverityLow},
		{"govulncheck", "HIGH", SeverityHigh},
	}
	for _, tt := range tests {
		if got := NormalizeSeverity(tt.engine, tt.original); got != tt.want {
			t.Errorf("NormalizeSeverity(%q,%q) = %q, want %q", tt.engine, tt.original, got, tt.want)
		}
	}
}

func TestSeverityRankAndMax(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() || SeverityHigh.Rank() <= SeverityMedium.Rank() {
		t.Fatal("el orden de severidad no es el esperado")
	}
	if SeverityInformational.Rank() >= SeverityLow.Rank() {
		t.Fatal("info debe quedar por debajo de low")
	}
	if got := Max(SeverityLow, SeverityHigh); got != SeverityHigh {
		t.Fatalf("Max = %q", got)
	}
	if got := Max(SeverityCritical, SeverityLow); got != SeverityCritical {
		t.Fatalf("Max = %q", got)
	}
}

func TestSortFindingsIsDeterministic(t *testing.T) {
	low := Finding{Fingerprint: "b", Severity: SeverityInfo{Normalized: SeverityLow}}
	high := Finding{Fingerprint: "a", Severity: SeverityInfo{Normalized: SeverityHigh}}
	critical := Finding{Fingerprint: "c", Severity: SeverityInfo{Normalized: SeverityCritical}}
	kev := true
	highKev := Finding{Fingerprint: "d", Severity: SeverityInfo{Normalized: SeverityHigh}, Priority: &Priority{KEV: &kev}}
	list := []Finding{low, high, critical, highKev}
	SortFindings(list)
	got := []string{list[0].Fingerprint, list[1].Fingerprint, list[2].Fingerprint, list[3].Fingerprint}
	want := []string{"c", "d", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orden = %v, want %v", got, want)
		}
	}
}
