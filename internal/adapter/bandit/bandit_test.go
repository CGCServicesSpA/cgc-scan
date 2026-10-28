package bandit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
)

func testAdapter(t *testing.T) *Adapter {
	t.Helper()
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	return New(provision.AdapterInstall{ID: ID, Version: "1.9.4"}, "/proyecto", m)
}

func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "bandit-1.9.4.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := testAdapter(t).Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 5 {
		t.Fatalf("hallazgos = %d", len(parsed.Findings))
	}
	byID := map[string]normalize.Finding{}
	for _, f := range parsed.Findings {
		byID[f.Sources[0].Rule] = f
		if f.Confidence == nil {
			t.Errorf("%s sin confianza", f.Sources[0].Rule)
		}
	}
	if byID["B602"].Severity.Normalized != normalize.SeverityHigh {
		t.Errorf("B602 = %s", byID["B602"].Severity.Normalized)
	}
	if byID["B105"].Severity.Normalized != normalize.SeverityLow {
		t.Errorf("B105 = %s", byID["B105"].Severity.Normalized)
	}
	for _, f := range parsed.Findings {
		if strings.Contains(f.Title, "hunter2-super-secret") || strings.Contains(f.Evidence.Snippet, "hunter2-super-secret") {
			t.Fatalf("se expuso el secreto en %s", f.Sources[0].Rule)
		}
	}
	if len(byID["B602"].IDs) < 2 {
		t.Errorf("faltan CWE: %+v", byID["B602"].IDs)
	}
}

func TestAcceptExitAndApplies(t *testing.T) {
	a := testAdapter(t)
	if !a.AcceptExit(0) || !a.AcceptExit(1) || a.AcceptExit(2) {
		t.Fatal("política de salida inesperada")
	}
	if !a.Applies(discovery.Unit{Kind: "package", Languages: []discovery.Language{discovery.Python}}) {
		t.Fatal("no aplica a Python")
	}
}

func TestRedactMasksQuotedSecrets(t *testing.T) {
	a := testAdapter(t)
	raw := []byte(`{"results":[{"test_id":"B105","issue_text":"Possible hardcoded password: 'secreto-largo-123'","code":"password = 'secreto-largo-123'"}]}`)
	out := a.Redact(raw)
	if strings.Contains(string(out), "secreto-largo-123") {
		t.Fatalf("no se enmascaró: %s", out)
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "bandit-1.9.4.json"))
	f.Add(raw)
	f.Add([]byte(`{"results":[]}`))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New(provision.AdapterInstall{ID: ID, Version: "1.9.4"}, "/proyecto", m)
	f.Fuzz(func(t *testing.T, b []byte) {
		parsed, err := a.Parse(b)
		if err != nil {
			return
		}
		for _, finding := range parsed.Findings {
			if len(finding.Fingerprint) != 32 {
				t.Fatalf("huella inválida")
			}
		}
	})
}
