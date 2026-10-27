package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WarnAfter() != 72*time.Hour || cfg.BlockAfterOffline() != 168*time.Hour {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.SemgrepEnabled {
		t.Fatal("Semgrep debe estar desactivado por defecto")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := Config{
		TrivyMode:      "docker",
		SemgrepEnabled: true,
		DB:             DB{WarnAfter: "48h", BlockAfterOffline: "240h"},
		Recipes: []Recipe{{
			Project: "/tmp/proyecto",
			Unit:    "svc/api",
			Test:    &Command{Command: "npm test", Workdir: "svc/api"},
			Build:   &Command{Command: "npm run build"},
		}},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrivyMode != "docker" || !got.SemgrepEnabled || got.WarnAfter() != 48*time.Hour {
		t.Fatalf("configuración = %+v", got)
	}
	if len(got.Recipes) != 1 || got.Recipes[0].Test.Command != "npm test" {
		t.Fatalf("recetas = %+v", got.Recipes)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o", info.Mode().Perm())
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("trivy_mode = \"docker\"\nmalicioso = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("se aceptó una clave desconocida")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	tests := []Config{
		{TrivyMode: "podman"},
		{Cache: Cache{Dir: "relativa"}},
		{DB: DB{WarnAfter: "mucho", BlockAfterOffline: "168h"}},
		{DB: DB{WarnAfter: "72h", BlockAfterOffline: "siempre"}},
		{Recipes: []Recipe{{Project: "relativo", Unit: "x"}}},
		{Recipes: []Recipe{{Project: "/tmp/x", Unit: ""}}},
		{Recipes: []Recipe{{Project: "/tmp/x", Unit: "u", Test: &Command{Command: " "}}}},
	}
	for i, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Errorf("caso %d: Validate aceptó %+v", i, cfg)
		}
	}
}

func TestCacheDir(t *testing.T) {
	if got := (Config{}).CacheDir("/default"); got != "/default" {
		t.Fatalf("CacheDir = %q", got)
	}
	if got := (Config{Cache: Cache{Dir: "/otra"}}).CacheDir("/default"); got != "/otra" {
		t.Fatalf("CacheDir = %q", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Schema != StateSchema || len(st.Installs) != 0 {
		t.Fatalf("estado inicial = %+v", st)
	}
	now := time.Now().UTC().Truncate(time.Second)
	st.RecordInstall(Install{Engine: "trivy", Version: "0.76.1", Path: "/x", SHA256: strings.Repeat("a", 64), InstalledAt: now})
	st.RecordProfileEdit(ProfileEdit{File: "/home/u/.zshrc", Marker: "cgc-scan", BackupPath: "/home/u/.zshrc.bak", AppliedAt: now})
	st.DockerVolume = "cgc-scan-trivy-cache-1"
	if err := SaveState(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Installs) != 1 || got.Installs[0].Version != "0.76.1" {
		t.Fatalf("instalaciones = %+v", got.Installs)
	}
	if len(got.ProfileEdits) != 1 || got.ProfileEdits[0].Marker != "cgc-scan" {
		t.Fatalf("perfiles = %+v", got.ProfileEdits)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o", info.Mode().Perm())
	}
}

func TestStateRejectsUnknownSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schema":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("se aceptó un esquema desconocido")
	}
}

func TestRecordInstallUpdates(t *testing.T) {
	st := &State{}
	st.RecordInstall(Install{Engine: "trivy", Version: "0.76.1", Path: "/a"})
	st.RecordInstall(Install{Engine: "trivy", Version: "0.76.1", Path: "/b"})
	if len(st.Installs) != 1 || st.Installs[0].Path != "/b" {
		t.Fatalf("instalaciones = %+v", st.Installs)
	}
}
