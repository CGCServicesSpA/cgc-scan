package govulncheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
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

func TestContainerInvocation(t *testing.T) {
	a := testAdapter(t)
	a.ContainerFor = func(discovery.Unit) *adapter.Container {
		return &adapter.Container{
			Image: "cgc-scan/toolchain:go-1.22-govulncheck-1.9.0",
			Root:  adapter.ContainerRoot, CacheDir: "/cache",
			Mounts: []runner.Mount{{Source: "/stage/vulndb", Target: ContainerDBDir, ReadOnly: true}},
		}
	}
	u := discovery.Unit{
		ID: "svc", Path: "svc", Kind: "module",
		Languages: []discovery.Language{discovery.Go},
		Manifests: []string{"svc/go.mod"},
	}
	if reqs := a.Requirements(context.Background(), u); len(reqs) != 0 {
		t.Fatalf("requisitos inesperados: %+v", reqs)
	}
	invs, err := a.Invocations(u, plan.Plan{})
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 1 {
		t.Fatalf("invocaciones = %d", len(invs))
	}
	inv := invs[0]
	if inv.Image == "" || inv.Local != nil {
		t.Fatalf("la invocación debería ser de contenedor: %+v", inv)
	}
	if inv.ProjectRO != "/proyecto" || inv.Dir != filepath.Join("/proyecto", "svc") {
		t.Fatalf("montaje = %q / %q", inv.ProjectRO, inv.Dir)
	}
	if !inv.AllowNetwork || !contains(inv.Args, "file://"+ContainerDBDir) {
		t.Fatalf("args = %v", inv.Args)
	}
	if inv.Env["GOTOOLCHAIN"] != "local" || inv.Env["GOCACHE"] != "/cache/go-build" {
		t.Fatalf("env = %v", inv.Env)
	}

	a.ContainerFor = nil
	invs, err = a.Invocations(u, plan.Plan{})
	if err != nil || len(invs) != 1 || invs[0].Local == nil {
		t.Fatalf("sin contenedor debe usar la biblioteca: %+v %v", invs, err)
	}
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
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

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "govulncheck-1.9.0.json"))
	f.Add(raw)
	f.Add([]byte(`{"config":{}}`))
	f.Add([]byte(`{"finding":{"osv":"GO-2021-0113"}}`))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New("/proyecto", "/db", "go", m)
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

func TestGoEnvironmentDisablesToolchainDownloads(t *testing.T) {
	a := &Adapter{GoEnv: map[string]string{"GOMODCACHE": "/cache"}}
	env := a.env()
	if env["GOPROXY"] != "off" || env["GOSUMDB"] != "sum.golang.org" {
		t.Fatalf("entorno = %v", env)
	}
	if env["GOMODCACHE"] != "/cache" {
		t.Fatalf("se perdió la caché: %v", env)
	}
}
