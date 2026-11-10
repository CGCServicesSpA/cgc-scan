package toolchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

// unitWith crea una unidad con los manifiestos dados y escribe su contenido.
func unitWith(t *testing.T, files map[string]string) (string, discovery.Unit) {
	t.Helper()
	root := t.TempDir()
	u := discovery.Unit{ID: "root", Path: ".", Kind: "module"}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, ".mod") || strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".toml") || strings.HasSuffix(name, ".txt") {
			u.Manifests = append(u.Manifests, name)
		}
	}
	return root, u
}

func TestDetectGoUsesHighestDirective(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		"go.mod": "module example.com/x\n\ngo 1.22.3\n\ntoolchain go1.23.1\n",
	})
	u.Languages = []discovery.Language{discovery.Go}
	got := Detect(root, u)
	if got.Version != "1.23.1" {
		t.Fatalf("versión = %q, want 1.23.1", got.Version)
	}
	if got.Family() != "go" || got.Source != "go.mod" {
		t.Fatalf("spec = %+v", got)
	}
}

func TestDetectGoIgnoresInvalidVersion(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		"go.mod": "module example.com/x\n\ngo 1.22; curl evil\n",
	})
	u.Languages = []discovery.Language{discovery.Go}
	got := Detect(root, u)
	if got.Version != "" {
		t.Fatalf("se aceptó una versión no numérica: %q", got.Version)
	}
	if got.Family() != "go" {
		t.Fatalf("family = %q", got.Family())
	}
}

func TestDetectNodePreferences(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		".nvmrc":       "v20.11.0\n",
		"package.json": `{"engines":{"node":"^22.4.0"}}`,
	})
	u.Languages = []discovery.Language{discovery.JavaScript}
	got := Detect(root, u)
	if got.Version != "20.11.0" || got.Source != ".nvmrc" {
		t.Fatalf("spec = %+v", got)
	}

	root2, u2 := unitWith(t, map[string]string{
		"package.json": `{"engines":{"node":">=20.11 <21"}}`,
	})
	u2.Languages = []discovery.Language{discovery.TypeScript}
	got2 := Detect(root2, u2)
	if got2.Version != "20.11" || got2.Family() != "node" {
		t.Fatalf("spec = %+v", got2)
	}
}

func TestDetectPHP(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		"composer.json": `{"require":{"php":"^8.2"},"config":{"platform":{"php":"8.3.4"}}}`,
	})
	u.Languages = []discovery.Language{discovery.PHP}
	got := Detect(root, u)
	if got.Version != "8.3.4" || !strings.Contains(got.Source, "platform") {
		t.Fatalf("spec = %+v", got)
	}
}

func TestDetectRust(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"x\"\nrust-version = \"1.75\"\n",
	})
	u.Languages = []discovery.Language{discovery.Rust}
	if got := Detect(root, u); got.Version != "1.75" {
		t.Fatalf("spec = %+v", got)
	}

	root2, u2 := unitWith(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"x\"\nedition = \"2021\"\n",
	})
	u2.Languages = []discovery.Language{discovery.Rust}
	if got := Detect(root2, u2); got.Version != "1.56" {
		t.Fatalf("edición 2021 = %+v", got)
	}
}

func TestDetectPython(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"x\"\nrequires-python = \">=3.11,<4\"\n",
	})
	u.Languages = []discovery.Language{discovery.Python}
	if got := Detect(root, u); got.Version != "3.11" {
		t.Fatalf("spec = %+v", got)
	}

	root2, u2 := unitWith(t, map[string]string{".python-version": "3.12.1\n"})
	u2.Languages = []discovery.Language{discovery.Python}
	if got := Detect(root2, u2); got.Version != "3.12.1" {
		t.Fatalf("spec = %+v", got)
	}
}

func TestImagesFromPreciseToGeneral(t *testing.T) {
	got := Spec{Language: discovery.Go, Version: "1.22.3"}.Images()
	want := []string{"golang:1.22.3", "golang:1.22", "golang:1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("images = %v, want %v", got, want)
	}
	if refs := (Spec{Language: discovery.Python, Version: "3.11"}.Images()); len(refs) == 0 || refs[0] != "python:3.11-slim" {
		t.Fatalf("python images = %v", refs)
	}
	if refs := (Spec{Language: discovery.PHP}.Images()); len(refs) == 0 || refs[0] != "php:8.3-cli" {
		t.Fatalf("php por defecto = %v", refs)
	}
}

func TestCacheVolumeIsPerUserAndVersion(t *testing.T) {
	a := Spec{Language: discovery.Go, Version: "1.22.3"}.CacheVolume(501)
	b := Spec{Language: discovery.Go, Version: "1.22.3"}.CacheVolume(502)
	if a == b {
		t.Fatal("dos usuarios comparten volumen")
	}
	if !strings.HasPrefix(a, "cgc-scan-toolchain-go-1.22.3-") {
		t.Fatalf("volumen = %q", a)
	}
}

func TestDetectForRestrictsToAdapterLanguage(t *testing.T) {
	root, u := unitWith(t, map[string]string{
		"go.mod":       "module example.com/x\n\ngo 1.22.3\n",
		"package.json": `{"engines":{"node":"20.11.0"}}`,
	})
	u.Languages = []discovery.Language{discovery.Go, discovery.JavaScript}
	if got := DetectFor(root, u, discovery.JavaScript); got.Family() != "node" || got.Version != "20.11.0" {
		t.Fatalf("node = %+v", got)
	}
	if got := DetectFor(root, u, discovery.Go); got.Family() != "go" || got.Version != "1.22.3" {
		t.Fatalf("go = %+v", got)
	}
	if got := DetectFor(root, u, discovery.PHP); got.Family() != "" {
		t.Fatalf("php = %+v", got)
	}
}

func TestFamilyForUnsupportedLanguage(t *testing.T) {
	if got := (Spec{}).Family(); got != "" {
		t.Fatalf("family = %q", got)
	}
}
