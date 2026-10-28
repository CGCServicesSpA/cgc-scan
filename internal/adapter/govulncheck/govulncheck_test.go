package govulncheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

func testAdapter(t *testing.T) *Adapter {
	t.Helper()
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	return New("/proyecto", "/db", "go", m)
}

func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "govulncheck-1.9.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := testAdapter(t).Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) < 5 {
		t.Fatalf("hallazgos = %d", len(parsed.Findings))
	}
	for _, f := range parsed.Findings {
		if f.Kind != normalize.KindVulnerability {
			t.Errorf("tipo = %q", f.Kind)
		}
		if f.Package == nil || f.Package.Ecosystem != "Go" {
			t.Errorf("paquete = %+v", f.Package)
		}
		if f.Priority == nil || f.Priority.Reachable == nil || !*f.Priority.Reachable {
			t.Errorf("no se marcó alcanzabilidad: %+v", f.Priority)
		}
		if len(f.Fingerprint) != 32 || len(f.Sources) == 0 {
			t.Errorf("hallazgo incompleto: %+v", f)
		}
	}
}

func TestParseEmptyAndTruncated(t *testing.T) {
	a := testAdapter(t)
	empty, err := a.Parse([]byte(`{"config":{"scanner_name":"govulncheck"}}`))
	if err != nil || len(empty.Findings) != 0 {
		t.Fatalf("salida sin hallazgos: %+v %v", empty, err)
	}
	raw, _ := os.ReadFile(filepath.Join("testdata", "govulncheck-1.9.0.json"))
	if len(raw) < 1000 {
		t.Fatal("fixture inesperado")
	}
	partial, err := a.Parse(raw[:len(raw)/2])
	if err != nil {
		if len(partial.Findings) > 0 {
			t.Fatal("una salida truncada no debe inventar hallazgos completos")
		}
		return
	}
	for _, f := range partial.Findings {
		if len(f.Fingerprint) != 32 {
			t.Errorf("huella inválida en salida truncada")
		}
	}
}

func TestAppliesOnlyGoUnits(t *testing.T) {
	a := testAdapter(t)
	if !a.Applies(discovery.Unit{Kind: "module", Languages: []discovery.Language{discovery.Go}}) {
		t.Fatal("no aplica a un módulo Go")
	}
	if a.Applies(discovery.Unit{Kind: "repository", Languages: []discovery.Language{discovery.Go}}) {
		t.Fatal("no debe aplicarse dos veces a la unidad de proyecto")
	}
	if a.Applies(discovery.Unit{Kind: "module", Languages: []discovery.Language{discovery.Python}}) {
		t.Fatal("no debe aplicarse a Python")
	}
}

func TestRequirements(t *testing.T) {
	a := testAdapter(t)
	reqs := a.Requirements(context.Background(), discovery.Unit{Kind: "module", Manifests: []string{"go.mod"}})
	for _, r := range reqs {
		if r.Missing {
			t.Errorf("requisito ausente con un adaptador completo: %+v", r)
		}
	}
}
