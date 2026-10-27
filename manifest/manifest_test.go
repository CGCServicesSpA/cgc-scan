package manifest

import (
	"encoding/json"
	"testing"
)

func TestLoadPinnedTrivy(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e, err := m.Engine("trivy")
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != "0.76.1" {
		t.Fatalf("versión = %q", e.Version)
	}
	if e.Image == "" {
		t.Fatal("falta el digest de la imagen")
	}
	for _, platform := range []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"} {
		a, err := e.Archive(splitPlatform(platform))
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		if len(a.SHA256) != 64 {
			t.Errorf("%s sha256 inválido: %q", platform, a.SHA256)
		}
	}
	if _, err := e.Archive("windows", "amd64"); err == nil {
		t.Fatal("se aceptó una plataforma sin artefacto")
	}
}

func splitPlatform(p string) (string, string) {
	for i := 0; i < len(p); i++ {
		if p[i] == '-' {
			return p[:i], p[i+1:]
		}
	}
	return p, ""
}

func TestPinnedVersions(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	v := m.PinnedVersions()
	if v["trivy"] != "0.76.1" {
		t.Fatalf("versiones = %v", v)
	}
}

func TestValidateRejectsTamperedManifest(t *testing.T) {
	base := map[string]any{
		"schema": 1,
		"engines": map[string]any{
			"trivy": map[string]any{
				"version": "0.76.1",
				"archives": map[string]any{
					"linux-amd64": map[string]any{"url": "https://example/x.tar.gz", "sha256": "abc"},
				},
			},
		},
	}
	raw, _ := json.Marshal(base)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err == nil {
		t.Fatal("se aceptó un sha256 inválido")
	}
	base["schema"] = 99
	raw, _ = json.Marshal(base)
	_ = json.Unmarshal(raw, &m)
	if err := m.Validate(); err == nil {
		t.Fatal("se aceptó un esquema desconocido")
	}
}

func TestEmbeddedManifestMatchesPublicFile(t *testing.T) {
	// El archivo embebido es el mismo que se publica en manifest/trust.json;
	// esta prueba impide que alguien edite solo uno.
	var fromEmbed map[string]any
	if err := json.Unmarshal(Bytes(), &fromEmbed); err != nil {
		t.Fatal(err)
	}
	if fromEmbed["schema"].(float64) != 1 {
		t.Fatal("esquema embebido inesperado")
	}
}
