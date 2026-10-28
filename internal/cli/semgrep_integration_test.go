//go:build integration

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// TestSemgrepIntegration comprueba el tercer nivel opcional con la imagen
// fijada y las reglas propias. Requiere Docker y CGC_SCAN_TEST_SEMGREP=1.
func TestSemgrepIntegration(t *testing.T) {
	if os.Getenv("CGC_SCAN_TEST_SEMGREP") == "" {
		t.Skip("define CGC_SCAN_TEST_SEMGREP=1 con datos preparados")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "monorepo"))
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			paths := platform.Paths{
				ConfigDir: filepath.Join(base, "cfg"),
				DataDir:   filepath.Join(base, "data"),
				CacheDir:  filepath.Join(base, "cache"),
			}
			if err := paths.EnsureDirs(); err != nil {
				t.Fatal(err)
			}
			cfg := config.Config{TrivyMode: "docker", SemgrepEnabled: enabled,
				DB: config.DB{WarnAfter: "72h", BlockAfterOffline: "168h"}}
			if err := config.Save(paths.ConfigFile(), cfg); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			app, err := New(&stdout, &stderr, WithTTY(false), WithPaths(paths))
			if err != nil {
				t.Fatal(err)
			}
			// El DATA dir debe contener los motores ya aprovisionados.
			app.Paths.DataDir = os.Getenv("CGC_SCAN_TEST_DATA_DIR")
			app.Paths.CacheDir = os.Getenv("CGC_SCAN_TEST_CACHE_DIR")
			code := app.Execute(context.Background(), []string{"scan", root, "--trivy-mode", "docker", "--offline", "--format", "json"})
			if code != 0 && code != 1 {
				t.Fatalf("código = %d: %s", code, stderr.String())
			}
			var doc map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			var sem map[string]any
			for _, e := range doc["tools"].(map[string]any)["engines"].([]any) {
				m := e.(map[string]any)
				if m["id"] == "semgrep" {
					sem = m
				}
			}
			if sem == nil {
				t.Fatal("falta la entrada de Semgrep en tools")
			}
			if enabled {
				if sem["status"] != "completed" {
					t.Fatalf("semgrep = %v", sem)
				}
				rules := sem["rules"].(map[string]any)
				if rules["count"].(float64) != 3 {
					t.Fatalf("reglas = %v", rules)
				}
				found := false
				for _, f := range doc["findings"].([]any) {
					for _, s := range f.(map[string]any)["sources"].([]any) {
						if s.(map[string]any)["engine"] == "semgrep" {
							found = true
						}
					}
				}
				if !found {
					t.Fatal("Semgrep no produjo hallazgos con las reglas propias")
				}
			} else {
				if sem["status"] != "disabled" {
					t.Fatalf("semgrep = %v", sem)
				}
				if doc["coverage"].(map[string]any)["partial"] == true {
					t.Fatal("Semgrep desactivado no debe marcar cobertura parcial")
				}
			}
		})
	}
}
