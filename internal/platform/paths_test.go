package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEnvOverrides(t *testing.T) {
	base := t.TempDir()
	cfg := filepath.Join(base, "cfg")
	data := filepath.Join(base, "data")
	cache := filepath.Join(base, "cache")
	t.Setenv(EnvConfigDir, cfg)
	t.Setenv(EnvDataDir, data)
	t.Setenv(EnvCacheDir, cache)

	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.ConfigDir != cfg || p.DataDir != data || p.CacheDir != cache {
		t.Fatalf("rutas = %+v, se esperaban %q %q %q", p, cfg, data, cache)
	}
	if got, want := p.ConfigFile(), filepath.Join(cfg, "config.toml"); got != want {
		t.Errorf("ConfigFile() = %q, want %q", got, want)
	}
	if got, want := p.StateFile(), filepath.Join(data, "state.json"); got != want {
		t.Errorf("StateFile() = %q, want %q", got, want)
	}
	if got, want := p.EngineDir("trivy", "0.76.1"), filepath.Join(data, "engines", "trivy", "0.76.1"); got != want {
		t.Errorf("EngineDir() = %q, want %q", got, want)
	}
}

func TestResolveRelativeOverrideRejected(t *testing.T) {
	t.Setenv(EnvConfigDir, "relative/dir")
	if _, err := Resolve(); err == nil {
		t.Fatal("Resolve aceptó una ruta relativa")
	}
}

func TestResolveDefaultsAreAbsolute(t *testing.T) {
	t.Setenv(EnvConfigDir, "")
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvCacheDir, "")
	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for name, dir := range map[string]string{"config": p.ConfigDir, "data": p.DataDir, "cache": p.CacheDir} {
		if !filepath.IsAbs(dir) {
			t.Errorf("%s no es absoluta: %q", name, dir)
		}
		if !strings.HasSuffix(dir, "cgc-scan") {
			t.Errorf("%s no termina en cgc-scan: %q", name, dir)
		}
	}
}

func TestEnsureDirsPermissions(t *testing.T) {
	base := t.TempDir()
	p := Paths{
		ConfigDir: filepath.Join(base, "cfg"),
		DataDir:   filepath.Join(base, "data"),
		CacheDir:  filepath.Join(base, "cache"),
	}
	if err := p.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	for _, dir := range []string{p.ConfigDir, p.DataDir, p.CacheDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s permisos = %o, want 700", dir, got)
		}
	}
}
