package cargoaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
)

func testAdapter(t *testing.T) *Adapter {
	t.Helper()
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	return New(provision.AdapterInstall{ID: ID, Version: "0.22.2"}, "/proyecto", "/rustsec", m)
}

func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "cargo-audit-0.22.2.json"))
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
	f := parsed.Findings[0]
	if f.Package == nil || f.Package.Name != "time" || f.Package.Version != "0.1.44" {
		t.Fatalf("paquete = %+v", f.Package)
	}
	if f.Package.FixedVersion == nil || *f.Package.FixedVersion != "0.2.23" {
		t.Fatalf("corregida = %v", f.Package.FixedVersion)
	}
	if f.Severity.Normalized != normalize.SeverityUnknown {
		t.Fatalf("severidad = %s", f.Severity.Normalized)
	}
	found := false
	for _, id := range f.IDs {
		if id.Value == "RUSTSEC-2020-0071" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ids = %+v", f.IDs)
	}
}

func TestAcceptExitAndApplies(t *testing.T) {
	a := testAdapter(t)
	if !a.AcceptExit(0) || !a.AcceptExit(1) || a.AcceptExit(2) {
		t.Fatal("política de salida inesperada")
	}
	if !a.Applies(discovery.Unit{Kind: "module", Languages: []discovery.Language{discovery.Rust}}) {
		t.Fatal("no aplica a Rust")
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "cargo-audit-0.22.2.json"))
	f.Add(raw)
	f.Add([]byte(`{"vulnerabilities":{"list":[]}}`))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New(provision.AdapterInstall{ID: ID, Version: "0.22.2"}, "/proyecto", "/rustsec", m)
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
