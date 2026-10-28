package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
)

func testAdapter(t *testing.T) *Adapter {
	t.Helper()
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	dir := filepath.Join(t.TempDir(), "rules")
	if _, err := provision.WriteSemgrepRules(dir); err != nil {
		t.Fatal(err)
	}
	return New("1.157.0", "/proyecto", dir, "semgrep", "global", 3, m)
}

func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "semgrep-1.157.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := testAdapter(t).Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("hallazgos = %d", len(parsed.Findings))
	}
	for _, f := range parsed.Findings {
		if f.Severity.Normalized != normalize.SeverityHigh {
			t.Errorf("severidad = %s", f.Severity.Normalized)
		}
		if f.Sources[0].Rule == "" || strings.Contains(f.Sources[0].Rule, ".") {
			t.Errorf("regla no normalizada: %q", f.Sources[0].Rule)
		}
		if len(f.IDs) < 2 {
			t.Errorf("faltan CWE/regla: %+v", f.IDs)
		}
	}
}

func TestAppliesAndExit(t *testing.T) {
	a := testAdapter(t)
	if a.Applies(discovery.Unit{Kind: "repository"}) {
		t.Fatal("no debe analizar la unidad de proyecto")
	}
	if !a.Applies(discovery.Unit{Kind: "package"}) {
		t.Fatal("debe analizar unidades de código")
	}
	if !a.AcceptExit(0) || !a.AcceptExit(1) || a.AcceptExit(2) {
		t.Fatal("política de salida inesperada")
	}
}

func TestRequirements(t *testing.T) {
	a := testAdapter(t)
	reqs := a.Requirements(context.Background(), discovery.Unit{})
	if len(reqs) != 0 {
		t.Fatalf("requisitos inesperados: %+v", reqs)
	}
	// En Docker el directorio de reglas vive dentro del contenedor.
	d := New("1.157.0", "/proyecto", "/rules", "", "docker", 3, nil)
	if len(d.Requirements(context.Background(), discovery.Unit{})) != 0 {
		t.Fatal("Docker no debe exigir el binario global")
	}
}

func TestWriteRules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rules")
	count, err := provision.WriteSemgrepRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("reglas = %d, want 3", count)
	}
	if _, err := os.Stat(filepath.Join(dir, "javascript.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := testAdapter(t).Parse([]byte("{")); err == nil {
		t.Fatal("se aceptó JSON inválido")
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "semgrep-1.157.0.json"))
	f.Add(raw)
	f.Add([]byte(`{"results":[]}`))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New("1.157.0", "/proyecto", "/rules", "semgrep", "global", 3, m)
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

var _ = adapter.Requirement{}
