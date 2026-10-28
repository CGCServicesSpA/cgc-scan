package eslint

import (
	"encoding/json"
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
	raw, err := os.ReadFile(filepath.Join("testdata", "eslint-10.13.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results []Result
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatal(err)
	}
	root := strings.TrimSuffix(results[0].FilePath, "/fixture/"+filepath.Base(results[0].FilePath))
	return New(provision.AdapterInstall{ID: ID, Version: "10.13.0"}, root, m)
}

func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "eslint-10.13.0.json"))
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
	byRule := map[string]normalize.Finding{}
	for _, f := range parsed.Findings {
		byRule[f.Sources[0].Rule] = f
		if !strings.HasPrefix(f.Locations[0].Path, "fixture/") {
			t.Errorf("ruta no relativa: %q", f.Locations[0].Path)
		}
		if len(f.Fingerprint) != 32 {
			t.Errorf("huella inválida: %q", f.Fingerprint)
		}
	}
	if got := byRule["security/detect-eval-with-expression"].Severity.Normalized; got != normalize.SeverityHigh {
		t.Errorf("eval = %s", got)
	}
	if got := byRule["security/detect-non-literal-require"].Severity.Normalized; got != normalize.SeverityMedium {
		t.Errorf("require = %s", got)
	}
	if got := byRule["security/detect-non-literal-regexp"].Severity.Normalized; got != normalize.SeverityLow {
		t.Errorf("regexp = %s", got)
	}
	if len(byRule["security/detect-eval-with-expression"].IDs) == 0 {
		t.Error("falta el identificador de regla")
	}
}

func TestAcceptExit(t *testing.T) {
	a := testAdapter(t)
	if !a.AcceptExit(0) || !a.AcceptExit(1) {
		t.Fatal("0 y 1 son ejecuciones completas")
	}
	if a.AcceptExit(2) {
		t.Fatal("2 es un fallo del motor")
	}
}

func TestApplies(t *testing.T) {
	a := testAdapter(t)
	if !a.Applies(discovery.Unit{Kind: "package", Languages: []discovery.Language{discovery.TypeScript}}) {
		t.Fatal("no aplica a TypeScript")
	}
	if a.Applies(discovery.Unit{Kind: "repository", Languages: []discovery.Language{discovery.JavaScript}}) {
		t.Fatal("no debe aplicarse a la unidad de proyecto")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	a := testAdapter(t)
	if _, err := a.Parse([]byte("no-json")); err == nil {
		t.Fatal("se aceptó basura")
	}
	if _, err := a.Parse(nil); err == nil {
		t.Fatal("se aceptó salida vacía")
	}
}

func TestParseIgnoresFatal(t *testing.T) {
	a := testAdapter(t)
	raw := []byte(`[{"filePath":"/x/a.js","messages":[{"ruleId":null,"fatal":true,"message":"Parsing error","line":1},{"ruleId":"security/detect-eval-with-expression","severity":2,"message":"eval","line":2}]}]`)
	parsed, err := a.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 1 || len(parsed.Diagnostics) != 1 {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "eslint-10.13.0.json"))
	f.Add(raw)
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"filePath":"/x","messages":[{"ruleId":"security/detect-eval-with-expression","severity":2,"line":1}]}]`))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New(provision.AdapterInstall{ID: ID, Version: "10.13.0"}, "/x", m)
	f.Fuzz(func(t *testing.T, b []byte) {
		parsed, err := a.Parse(b)
		if err != nil {
			return
		}
		for _, finding := range parsed.Findings {
			if len(finding.Fingerprint) != 32 {
				t.Fatalf("huella inválida para %q", b)
			}
		}
	})
}
