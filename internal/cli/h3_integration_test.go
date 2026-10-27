//go:build integration

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// TestSetupGlobalIntegration ejecuta setup global real (descarga verificada de
// Trivy) en un HOME temporal. Requiere red y CGC_SCAN_TEST_SETUP=1.
func TestSetupGlobalIntegration(t *testing.T) {
	if os.Getenv("CGC_SCAN_TEST_SETUP") == "" {
		t.Skip("define CGC_SCAN_TEST_SETUP=1 para probar setup con descarga real")
	}
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	paths := platformPaths(t, base)

	run := func(args []string) (string, int) {
		var stdout, stderr bytes.Buffer
		app, err := New(&stdout, &stderr, WithTTY(false), WithPaths(paths))
		if err != nil {
			t.Fatal(err)
		}
		code := app.Execute(context.Background(), args)
		return stderr.String(), code
	}

	out, code := run([]string{"setup", "--trivy-mode", "global", "--semgrep", "disable", "--non-interactive"})
	if code != 0 {
		t.Fatalf("setup global = %d: %s", code, out)
	}
	cfg, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `trivy_mode = 'global'`) {
		t.Fatalf("config = %s", cfg)
	}
	link := filepath.Join(home, ".local", "bin", "trivy")
	if _, err := os.Readlink(link); err != nil {
		t.Fatalf("enlace global: %v", err)
	}
	profile, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(profile), "cgc-scan (no editar") != 1 {
		t.Fatalf("perfil = %s", profile)
	}

	// Segunda ejecución: no duplica el bloque y conserva la elección.
	out, code = run([]string{"setup", "--non-interactive"})
	if code != 0 {
		t.Fatalf("segundo setup = %d: %s", code, out)
	}
	profile, _ = os.ReadFile(filepath.Join(home, ".zshrc"))
	if strings.Count(string(profile), "cgc-scan (no editar") != 1 {
		t.Fatal("el bloque de PATH se duplicó")
	}
}

func platformPaths(t *testing.T, base string) platform.Paths {
	t.Helper()
	return platform.Paths{
		ConfigDir: filepath.Join(base, "cfg"),
		DataDir:   filepath.Join(base, "data"),
		CacheDir:  filepath.Join(base, "cache"),
	}
}
