package discovery

import (
	"context"
	"os"
	"path/filepath"
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
