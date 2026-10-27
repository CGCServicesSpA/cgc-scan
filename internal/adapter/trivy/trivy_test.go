package trivy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
)

func testAdapter(t *testing.T) *Adapter {
	t.Helper()
	m, err := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return New(m)
}

func TestArgsAreStable(t *testing.T) {
	got := Args("/cache/trivy", []string{"b", "a"}, []string{"**/*.min.js"})
	want := []string{
		"fs", "--format", "json", "--scanners", "vuln,secret,misconfig",
		"--skip-db-update", "--skip-java-db-update", "--offline-scan",
		"--skip-check-update", "--skip-version-check", "--disable-telemetry",
		"--no-progress", "--cache-dir", "/cache/trivy",
		"--skip-dirs", "a", "--skip-dirs", "b", "--skip-files", "**/*.min.js",
		".",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args =\n%q\nwant\n%q", got, want)
	}
}

func TestArgsAlwaysDisableVersionCheck(t *testing.T) {
	// P-09: sin este flag Trivy abre conexiones a check.trivy.dev.
	found := false
	for _, a := range Args("/tmp/c", nil, nil) {
		if a == "--skip-version-check" {
			found = true
		}
	}
	if !found {
		t.Fatal("falta --skip-version-check")
	}
}

func TestInvocationsPropagateExclusions(t *testing.T) {
	a := testAdapter(t)
	p := plan.Plan{
		Root: "/proyecto",
		Exclusions: []discovery.Exclusion{
			{Pattern: "docs/**", Origin: discovery.OriginUser},
			{Pattern: "**/*.min.js", Origin: discovery.OriginCLI},
		},
	}
	u := discovery.Unit{ID: "svc", Path: "svc/api"}
	invs, err := a.Invocations(u, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 1 {
		t.Fatalf("invocaciones = %d", len(invs))
	}
	joined := strings.Join(invs[0].Args, " ")
	for _, want := range []string{"--skip-dirs docs", "--skip-files **/*.min.js"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args no contienen %q: %v", want, invs[0].Args)
		}
	}
	if invs[0].Dir != filepath.Join("/proyecto", "svc/api") {
		t.Errorf("Dir = %q", invs[0].Dir)
	}
}

func TestParseRealTrivyOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "trivy-0.76.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := testAdapter(t)
	parsed, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Findings) != 8 {
		t.Fatalf("hallazgos = %d, want 8", len(parsed.Findings))
	}
	byKind := map[normalize.Kind]int{}
	for _, f := range parsed.Findings {
		byKind[f.Kind]++
		if len(f.Fingerprint) != 32 {
			t.Errorf("fingerprint inválido: %q", f.Fingerprint)
		}
		if !f.Severity.Normalized.Valid() {
			t.Errorf("severidad inválida: %q", f.Severity.Normalized)
		}
		if len(f.Sources) == 0 || f.Sources[0].Engine != ID {
			t.Errorf("fuente ausente en %s", f.Fingerprint)
		}
	}
	if byKind[normalize.KindVulnerability] != 5 || byKind[normalize.KindMisconfig] != 2 || byKind[normalize.KindSecret] != 1 {
		t.Fatalf("conteo por tipo = %v", byKind)
	}
	// Orden: el secreto CRITICAL va primero.
	if parsed.Findings[0].Kind != normalize.KindSecret {
		t.Errorf("el primer hallazgo no es el secreto crítico: %+v", parsed.Findings[0])
	}
	var vuln *normalize.Finding
	for i := range parsed.Findings {
		if parsed.Findings[i].Kind == normalize.KindVulnerability && containsID(parsed.Findings[i], "CVE-2021-38561") {
			vuln = &parsed.Findings[i]
			break
		}
	}
	if vuln == nil {
		t.Fatal("no se encontró CVE-2021-38561")
	}
	if vuln.Package == nil || vuln.Package.Ecosystem != "Go" || vuln.Package.Name != "golang.org/x/text" {
		t.Errorf("paquete = %+v", vuln.Package)
	}
	if vuln.Package.FixedVersion == nil || *vuln.Package.FixedVersion != "0.3.7" {
		t.Errorf("versión corregida = %v", vuln.Package.FixedVersion)
	}
	if vuln.Priority == nil || vuln.Priority.CVSSScore == nil {
		t.Error("no se conservó CVSS")
	}
	if vuln.Locations[0].Path != "app/go.mod" {
		t.Errorf("ruta = %q", vuln.Locations[0].Path)
	}
	var secret *normalize.Finding
	var misconfig *normalize.Finding
	for i := range parsed.Findings {
		switch parsed.Findings[i].Kind {
		case normalize.KindSecret:
			secret = &parsed.Findings[i]
		case normalize.KindMisconfig:
			if parsed.Findings[i].Title == "Image user should not be 'root'" {
				misconfig = &parsed.Findings[i]
			}
		}
	}
	if secret == nil || !secret.Evidence.Redacted {
		t.Fatal("el secreto no está marcado como redactado")
	}
	if strings.Contains(secret.Evidence.Snippet, "ghp_") {
		t.Fatalf("la evidencia expone el secreto: %q", secret.Evidence.Snippet)
	}
	if secret.Locations[0].Path != "secrets.txt" || secret.Locations[0].StartLine == nil || *secret.Locations[0].StartLine != 1 {
		t.Errorf("ubicación del secreto = %+v", secret.Locations[0])
	}
	if misconfig == nil || misconfig.Locations[0].StartLine == nil || *misconfig.Locations[0].StartLine != 2 {
		t.Errorf("ubicación de la misconfiguración = %+v", misconfig)
	}
	if misconfig.Evidence.Snippet != "Last USER command in Dockerfile should not be 'root'" {
		t.Errorf("evidencia de misconfiguración = %q", misconfig.Evidence.Snippet)
	}
	if strings.Contains(misconfig.Evidence.Snippet, "\x1b") {
		t.Errorf("la evidencia conserva ANSI: %q", misconfig.Evidence.Snippet)
	}
}

func TestParseRejectsInvalidJSON(t *testing.T) {
	a := testAdapter(t)
	if _, err := a.Parse([]byte(`{"Results":[`)); err == nil {
		t.Fatal("se aceptó JSON truncado")
	}
	if _, err := a.Parse(nil); err == nil {
		t.Fatal("se aceptó salida vacía")
	}
	if _, err := a.Parse([]byte(`{"SchemaVersion":99,"Results":[]}`)); err == nil {
		t.Fatal("se aceptó un esquema desconocido")
	}
}

func TestRedactRemovesUnmaskedSecret(t *testing.T) {
	a := testAdapter(t)
	secret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	raw := []byte(`{"SchemaVersion":2,"Results":[{"Target":"app.env","Class":"secret","Secrets":[{"RuleID":"github-pat","Severity":"CRITICAL","StartLine":1,"EndLine":1,"Match":"` + secret + `","Code":{"Lines":[{"Number":1,"Content":"TOKEN=` + secret + `"}]}}]}]}`)
	out := a.Redact(raw)
	if strings.Contains(string(out), secret) {
		t.Fatalf("Redact dejó el secreto: %s", out)
	}
	if !strings.Contains(string(out), "<secret:") {
		t.Fatalf("no se aplicó la máscara: %s", out)
	}
}

func TestRedactSanitizesANSIEvenIfParseFails(t *testing.T) {
	a := testAdapter(t)
	out := a.Redact([]byte("texto\x1b[31m rojo"))
	if strings.Contains(string(out), "\x1b") {
		t.Fatalf("quedó ANSI: %q", out)
	}
}

func TestParseEmptyReportIsClean(t *testing.T) {
	a := testAdapter(t)
	parsed, err := a.Parse([]byte(`{"SchemaVersion":2,"Results":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 0 {
		t.Fatalf("hallazgos = %d", len(parsed.Findings))
	}
}

func FuzzParse(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("testdata", "trivy-0.76.1.json"))
	if err == nil {
		f.Add(raw)
	}
	f.Add([]byte(`{"SchemaVersion":2,"Results":[]}`))
	f.Add([]byte(`{"Results":[{"Target":"x","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH"}]}]}`))
	f.Add([]byte(`{"Results":[`))
	f.Add([]byte("\x00\xff"))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New(m)
	f.Fuzz(func(t *testing.T, b []byte) {
		parsed, err := a.Parse(b)
		if err != nil {
			return
		}
		for _, finding := range parsed.Findings {
			if len(finding.Fingerprint) != 32 {
				t.Fatalf("fingerprint inválido para entrada %q", b)
			}
			if finding.Severity.Normalized == "" {
				t.Fatalf("severidad vacía para entrada %q", b)
			}
		}
		// Redact no debe entrar en pánico ni dejar ANSI.
		_ = a.Redact(b)
	})
}

func containsID(f normalize.Finding, id string) bool {
	for _, i := range f.IDs {
		if i.Value == id {
			return true
		}
	}
	return false
}

var _ = context.Background
