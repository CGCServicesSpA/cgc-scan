package recipes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDetectCandidates(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "svc", "package.json"), `{"scripts":{"test":"jest","build":"tsc"}}`)
	write(t, filepath.Join(root, "api", "go.mod"), "module x\n")
	write(t, filepath.Join(root, "py", "pyproject.toml"), "[project]\nname=\"x\"\n")
	units := []discovery.Unit{
		{ID: "project", Path: ".", Kind: "repository"},
		{ID: "svc", Path: "svc", Kind: "package", Manifests: []string{"svc/package.json"}},
		{ID: "api", Path: "api", Kind: "module", Manifests: []string{"api/go.mod"}},
		{ID: "py", Path: "py", Kind: "package", Manifests: []string{"py/pyproject.toml"}},
	}
	got := Detect(root, units)
	kinds := map[string]map[string]string{}
	for _, c := range got {
		if kinds[c.Unit] == nil {
			kinds[c.Unit] = map[string]string{}
		}
		kinds[c.Unit][c.Kind] = c.Command
	}
	if kinds["svc"]["test"] != "npm run test" || kinds["svc"]["build"] != "npm run build" {
		t.Errorf("svc = %v", kinds["svc"])
	}
	if kinds["api"]["test"] != "go test ./..." || kinds["api"]["build"] != "go build ./..." {
		t.Errorf("api = %v", kinds["api"])
	}
	if kinds["py"]["test"] != "pytest" {
		t.Errorf("py = %v", kinds["py"])
	}
	if _, ok := kinds["project"]; ok {
		t.Error("se propusieron recetas para la unidad de proyecto")
	}
}

func TestMergeAndClear(t *testing.T) {
	cfg := config.Config{Recipes: []config.Recipe{
		{Project: "/otro", Unit: "x"},
		{Project: "/proj", Unit: "viejo"},
	}}
	entries := []config.Recipe{{Project: "/proj", Unit: "svc", Test: &config.Command{Command: "go test ./..."}}}
	Merge(&cfg, "/proj", entries)
	if len(Confirmed(cfg, "/proj")) != 1 || Confirmed(cfg, "/proj")[0].Unit != "svc" {
		t.Fatalf("recetas = %+v", cfg.Recipes)
	}
	if len(Confirmed(cfg, "/otro")) != 1 {
		t.Fatal("se perdieron recetas de otro proyecto")
	}
	if n := Clear(&cfg, "/proj"); n != 1 {
		t.Fatalf("eliminadas = %d", n)
	}
	if len(Confirmed(cfg, "/proj")) != 0 {
		t.Fatal("quedaron recetas del proyecto")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recetas.toml")
	write(t, path, `
[[recipes]]
unit = "svc/api"
[recipes.test]
command = "npm test"
workdir = "svc/api"
`)
	entries, err := LoadFile(path, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Project != "/proj" || entries[0].Unit != "svc/api" {
		t.Fatalf("entradas = %+v", entries)
	}
	if entries[0].Test == nil || entries[0].Test.Command != "npm test" {
		t.Fatalf("test = %+v", entries[0].Test)
	}

	bad := filepath.Join(dir, "malo.toml")
	write(t, bad, "[[recipes]]\nunit = \"x\"\n")
	if _, err := LoadFile(bad, "/proj"); err == nil {
		t.Fatal("se aceptó una receta sin test ni build")
	}
}
