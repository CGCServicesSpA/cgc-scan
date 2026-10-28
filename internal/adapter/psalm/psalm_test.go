package psalm

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
	raw, err := os.ReadFile(filepath.Join("testdata", "psalm-6.20.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var issues []Issue
	if err := json.Unmarshal(raw, &issues); err != nil {
		t.Fatal(err)
	}
	root := strings.TrimSuffix(issues[0].FilePath, "/fixture/index.php")
	return New(provision.AdapterInstall{ID: ID, Version: "6.20.3"}, root, t.TempDir(), m)
}

func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "psalm-6.20.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := testAdapter(t).Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 4 {
		t.Fatalf("hallazgos = %d", len(parsed.Findings))
	}
	sev := map[string]normalize.Severity{}
	for _, f := range parsed.Findings {
		sev[f.Sources[0].Rule] = f.Severity.Normalized
		if f.Locations[0].Path != "fixture/index.php" {
			t.Errorf("ruta = %q", f.Locations[0].Path)
		}
		if f.Locations[0].StartLine == nil {
			t.Error("falta línea")
		}
	}
	if sev["TaintedShell"] != normalize.SeverityHigh {
		t.Errorf("TaintedShell = %s", sev["TaintedShell"])
	}
	if sev["TaintedHtml"] != normalize.SeverityMedium {
		t.Errorf("TaintedHtml = %s", sev["TaintedHtml"])
	}
}

func TestAcceptExit(t *testing.T) {
	a := testAdapter(t)
	for _, c := range []int{0, 1, 2} {
		if !a.AcceptExit(c) {
			t.Errorf("código %d debería aceptarse", c)
		}
	}
	if a.AcceptExit(3) {
		t.Fatal("3 no es un código de Psalm")
	}
}

func TestPsalmConfigEscapesPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a&b")
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := string(psalmConfig(dir, []discovery.Exclusion{{Pattern: "docs/**"}}))
	if strings.Contains(cfg, `name="`+dir+`"`) {
		t.Fatal("no se escapó el XML")
	}
	if !strings.Contains(cfg, "&amp;") {
		t.Fatalf("config = %s", cfg)
	}
	if !strings.Contains(cfg, "<ignoreFiles>") {
		t.Fatal("no se propagaron las exclusiones")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	a := testAdapter(t)
	if _, err := a.Parse([]byte("{")); err == nil {
		t.Fatal("se aceptó JSON inválido")
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "psalm-6.20.3.json"))
	f.Add(raw)
	f.Add([]byte(`[]`))
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New(provision.AdapterInstall{ID: ID, Version: "6.20.3"}, "/x", "/tmp", m)
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
