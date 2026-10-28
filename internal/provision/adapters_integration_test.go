//go:build integration

package provision

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// TestEnsureAdapterIntegration descarga e instala las herramientas reales de
// los adaptadores. Requiere red y CGC_SCAN_TEST_ADAPTERS=1.
func TestEnsureAdapterIntegration(t *testing.T) {
	if os.Getenv("CGC_SCAN_TEST_ADAPTERS") == "" {
		t.Skip("define CGC_SCAN_TEST_ADAPTERS=1 para instalar adaptadores reales")
	}
	ms, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	for _, id := range []string{"eslint", "psalm", "cargo-audit", "bandit"} {
		t.Run(id, func(t *testing.T) {
			res, err := EnsureAdapter(ctx, AdapterOptions{Paths: paths, Manifest: ms}, id)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if !res.Installed {
				t.Fatalf("%s no se instaló", id)
			}
			if ok, detail := VerifyAdapter(ctx, res); !ok {
				t.Fatalf("%s no verifica: %s", id, detail)
			}
			// Idempotencia: la segunda llamada no reinstala.
			again, err := EnsureAdapter(ctx, AdapterOptions{Paths: paths, Manifest: ms}, id)
			if err != nil {
				t.Fatal(err)
			}
			if again.Installed {
				t.Errorf("%s se reinstaló", id)
			}
		})
	}
}
