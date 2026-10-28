package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverFindsModulesAndProjectUnit(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/root\n")
	write(t, filepath.Join(dir, "main.go"), "package main\n")
	write(t, filepath.Join(dir, "svc", "api", "go.mod"), "module example.com/api\n")
	write(t, filepath.Join(dir, "svc", "api", "main.go"), "package main\n")
	write(t, filepath.Join(dir, "node_modules", "x", "go.mod"), "module evil\n")
	write(t, filepath.Join(dir, ".git", "config"), "x")

	res, err := Discover(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Root != dir {
		t.Fatalf("root = %q, want %q", res.Root, dir)
	}
	var ids []string
	for _, u := range res.Units {
		ids = append(ids, u.ID+":"+u.Path)
	}
	want := map[string]bool{"project:.": true, "root:.": true, "svc/api:svc/api": true}
	if len(res.Units) != len(want) {
		t.Fatalf("unidades = %v", ids)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unidad inesperada %q", id)
		}
	}
	if res.Partial {
		t.Fatal("las exclusiones intrínsecas no deben marcar parcialidad")
	}
	if len(res.Exclusions) == 0 {
		t.Fatal("no se registraron exclusiones intrínsecas")
	}
}

func TestDetectRootUsesGit(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n")
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectRoot(sub); got != dir {
		t.Fatalf("root = %q, want %q", got, dir)
	}
}

func TestDetectRootUsesPackageWorkspaces(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{"workspaces":["packages/*"]}`)
	sub := filepath.Join(dir, "packages", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectRoot(sub); got != dir {
		t.Fatalf("root = %q, want %q", got, dir)
	}
}

func TestDiscoverOutsideRootRejected(t *testing.T) {
	root := t.TempDir()
	// La ruta objetivo fuera de la raíz no es un error de descubrimiento: la
	// raíz se detecta desde el objetivo. Se verifica que Rel rechace.
	if _, err := Rel(root, filepath.Join(root, "..", "otro")); err == nil {
		t.Fatal("Rel aceptó una ruta fuera de la raíz")
	}
}

func TestDiscoverRejectsFileAndMissingPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "x.txt")
	write(t, file, "x")
	if _, err := Discover(context.Background(), Options{Target: file}); err == nil {
		t.Fatal("se aceptó un archivo como objetivo")
	}
	if _, err := Discover(context.Background(), Options{Target: filepath.Join(dir, "no-existe")}); err == nil {
		t.Fatal("se aceptó una ruta inexistente")
	}
}

func TestElectedExclusionMarksPartial(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module x\n")
	res, err := Discover(context.Background(), Options{
		Target:  dir,
		Exclude: []Exclusion{{Pattern: "docs/**", Origin: OriginCLI}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial {
		t.Fatal("una exclusión elegida debe marcar coverage.partial")
	}
}

func TestDiscoverMonorepoLanguages(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n")
	write(t, filepath.Join(dir, "services", "api", "package.json"), `{"name":"api","scripts":{"test":"jest"}}`)
	write(t, filepath.Join(dir, "services", "api", "tsconfig.json"), `{}`)
	write(t, filepath.Join(dir, "services", "api", "index.tsx"), "export const x = 1\n")
	write(t, filepath.Join(dir, "services", "web", "package.json"), `{"name":"web"}`)
	write(t, filepath.Join(dir, "services", "web", "index.js"), "module.exports = 1\n")
	write(t, filepath.Join(dir, "backend", "composer.json"), `{"name":"cgc/backend"}`)
	write(t, filepath.Join(dir, "backend", "index.php"), "<?php echo 1;\n")
	write(t, filepath.Join(dir, "tools", "Cargo.toml"), "[package]\nname=\"tools\"\n")
	write(t, filepath.Join(dir, "tools", "src", "main.rs"), "fn main() {}\n")
	write(t, filepath.Join(dir, "scripts", "pyproject.toml"), "[project]\nname=\"scripts\"\n")
	write(t, filepath.Join(dir, "scripts", "app.py"), "print(1)\n")

	res, err := Discover(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	langs := map[string][]Language{}
	for _, u := range res.Units {
		langs[u.Path] = u.Languages
	}
	if got := langs["services/api"]; len(got) != 2 || got[0] != JavaScript || got[1] != TypeScript {
		t.Errorf("services/api = %v", got)
	}
	if got := langs["services/web"]; len(got) != 1 || got[0] != JavaScript {
		t.Errorf("services/web = %v", got)
	}
	if got := langs["backend"]; len(got) != 1 || got[0] != PHP {
		t.Errorf("backend = %v", got)
	}
	if got := langs["tools"]; len(got) != 1 || got[0] != Rust {
		t.Errorf("tools = %v", got)
	}
	if got := langs["scripts"]; len(got) != 1 || got[0] != Python {
		t.Errorf("scripts = %v", got)
	}
}

func TestDiscoverSourceWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "src", "main.py"), "print(1)\n")
	res, err := Discover(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range res.Units {
		for _, l := range u.Languages {
			if l == Python && u.Kind == "directory" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no se detectó Python sin manifiesto: %+v", res.Units)
	}
}

func TestDiscoverSubdirectoryDoesNotEscapeToRoot(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main\n")
	write(t, filepath.Join(root, "a", "go.mod"), "module example.com/a\n")
	write(t, filepath.Join(root, "a", "main.go"), "package main\n")
	write(t, filepath.Join(root, "b", "go.mod"), "module example.com/b\n")
	write(t, filepath.Join(root, "b", "main.go"), "package main\n")
	res, err := Discover(context.Background(), Options{Target: filepath.Join(root, "a")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Root != root {
		t.Fatalf("root = %q", res.Root)
	}
	for _, u := range res.Units {
		if u.Path != "a" && u.Path != "." && !strings.HasPrefix(u.Path, "a/") {
			t.Fatalf("unidad fuera del objetivo: %q", u.Path)
		}
	}
	foundProject := false
	for _, u := range res.Units {
		if u.ID == "project" {
			foundProject = true
			if u.Path != "a" {
				t.Errorf("unidad de proyecto = %q, want a", u.Path)
			}
		}
	}
	if !foundProject {
		t.Fatal("falta la unidad de proyecto")
	}
}
