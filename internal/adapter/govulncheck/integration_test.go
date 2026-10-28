//go:build integration

package govulncheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

func TestInProcessRunIntegration(t *testing.T) {
	db := os.Getenv("CGC_SCAN_TEST_GOVULN_DB")
	if db == "" {
		t.Skip("define CGC_SCAN_TEST_GOVULN_DB con el espejo local")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go no está en PATH")
	}
	base := t.TempDir()
	paths := platform.Paths{
		ConfigDir: filepath.Join(base, "cfg"),
		DataDir:   filepath.Join(base, "data"),
		CacheDir:  filepath.Join(base, "cache"),
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	m, _ := masking.NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	a := New(base, db, goBin, m)
	unit := discovery.Unit{ID: "app", Path: ".", Kind: "module", Languages: []discovery.Language{discovery.Go}, Manifests: []string{"go.mod"}}
	files := map[string]string{
		"go.mod":  "module example.com/vulnapp\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.0\n",
		"go.sum":  "golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\ngolang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=\n",
		"main.go": "package main\n\nimport \"golang.org/x/text/language\"\n\nfunc main() { _ = language.English }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	invs, err := a.Invocations(unit, plan.Plan{Root: base})
	if err != nil {
		t.Fatal(err)
	}
	lib := &runner.Library{Global: &runner.Global{Paths: paths}}
	res, err := lib.Run(context.Background(), invs[0])
	if err != nil {
		t.Fatalf("ejecutar govulncheck: %v", err)
	}
	parsed, err := a.Parse(res.Stdout)
	if err != nil {
		t.Fatalf("parsear: %v (stderr %s)", err, res.Stderr)
	}
	if len(parsed.Findings) == 0 {
		t.Fatalf("sin hallazgos; stderr: %s", res.Stderr)
	}
}
