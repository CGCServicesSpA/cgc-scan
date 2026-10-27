//go:build integration

// Las pruebas de integración ejecutan Trivy real y una base local real. Se
// activan con:
//
//	CGC_SCAN_TRIVY_BIN=/ruta/trivy \
//	CGC_SCAN_TRIVY_CACHE=/ruta/cache \
//	go test -tags=integration ./internal/cli
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func TestScanGoFixtureIntegration(t *testing.T) {
	bin := os.Getenv("CGC_SCAN_TRIVY_BIN")
	cache := os.Getenv("CGC_SCAN_TRIVY_CACHE")
	if bin == "" || cache == "" {
		t.Skip("define CGC_SCAN_TRIVY_BIN y CGC_SCAN_TRIVY_CACHE para la prueba de integración")
	}

	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Setup: func(env *testscript.Env) error {
			work := env.Getenv("WORK")
			paths := platform.Paths{
				ConfigDir: filepath.Join(work, "cfg"),
				DataDir:   filepath.Join(work, "data"),
				CacheDir:  filepath.Join(work, "cache"),
			}
			if err := paths.EnsureDirs(); err != nil {
				return err
			}
			engineDir := paths.EngineDir("trivy", "0.76.1")
			if err := os.MkdirAll(engineDir, 0o700); err != nil {
				return err
			}
			if err := copyFile(bin, filepath.Join(engineDir, "trivy")); err != nil {
				return err
			}
			trivyCache := paths.TrivyCacheDir()
			if err := os.MkdirAll(trivyCache, 0o700); err != nil {
				return err
			}
			if err := os.Symlink(filepath.Join(cache, "db"), filepath.Join(trivyCache, "db")); err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(cache, "policy")); err == nil {
				if err := os.Symlink(filepath.Join(cache, "policy"), filepath.Join(trivyCache, "policy")); err != nil {
					return err
				}
			}
			env.Setenv("CGC_SCAN_CONFIG_DIR", paths.ConfigDir)
			env.Setenv("CGC_SCAN_DATA_DIR", paths.DataDir)
			env.Setenv("CGC_SCAN_CACHE_DIR", paths.CacheDir)
			return nil
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"scanjson": func(ts *testscript.TestScript, neg bool, args []string) {
				if neg {
					ts.Fatalf("scanjson no admite negación")
				}
				if len(args) != 2 {
					ts.Fatalf("uso: scanjson <reporte.json> <fixture>")
				}
				out := ts.MkAbs(args[0])
				fixture := ts.MkAbs(args[1])

				first, code := runScanJSON(ts, fixture)
				if code != 1 {
					ts.Fatalf("código de salida = %d, want 1 por hallazgos sobre el umbral", code)
				}
				if err := report.Validate(first); err != nil {
					ts.Fatalf("el reporte no cumple el esquema: %v", err)
				}
				var doc map[string]any
				if err := json.Unmarshal(first, &doc); err != nil {
					ts.Fatalf("JSON inválido: %v", err)
				}
				findings := doc["findings"].([]any)
				if len(findings) < 6 {
					ts.Fatalf("hallazgos = %d, se esperaban al menos 6", len(findings))
				}
				kinds := map[string]int{}
				for _, f := range findings {
					kinds[f.(map[string]any)["kind"].(string)]++
				}
				for _, want := range []string{"vulnerability", "secret", "misconfig"} {
					if kinds[want] == 0 {
						ts.Fatalf("faltan hallazgos de tipo %s: %v", want, kinds)
					}
				}
				if err := os.WriteFile(out, first, 0o600); err != nil {
					ts.Fatalf("escribir reporte: %v", err)
				}

				second, _ := runScanJSON(ts, fixture)
				if !sameExceptRun(first, second) {
					ts.Fatalf("dos ejecuciones con las mismas entradas produjeron documentos distintos fuera de run")
				}
			},
		},
	})
}

func runScanJSON(ts *testscript.TestScript, fixture string) ([]byte, int) {
	var stdout, stderr bytes.Buffer
	paths := platform.Paths{
		ConfigDir: ts.Getenv("CGC_SCAN_CONFIG_DIR"),
		DataDir:   ts.Getenv("CGC_SCAN_DATA_DIR"),
		CacheDir:  ts.Getenv("CGC_SCAN_CACHE_DIR"),
	}
	app, err := New(&stdout, &stderr, WithTTY(false), WithPaths(paths))
	if err != nil {
		ts.Fatalf("crear App: %v", err)
	}
	code := app.Execute(context.Background(), []string{"scan", fixture, "--offline", "--format", "json"})
	if code != 0 && code != 1 {
		ts.Fatalf("scan falló con %d: %s", code, stderr.String())
	}
	return stdout.Bytes(), code
}

func sameExceptRun(a, b []byte) bool {
	normalize := func(data []byte) string {
		var doc map[string]any
		_ = json.Unmarshal(data, &doc)
		delete(doc, "run")
		if tools, ok := doc["tools"].(map[string]any); ok {
			if engines, ok := tools["engines"].([]any); ok {
				for _, e := range engines {
					m := e.(map[string]any)
					delete(m, "duration_ms")
					if db, ok := m["db"].(map[string]any); ok {
						delete(db, "age_seconds")
					}
				}
			}
		}
		out, _ := json.Marshal(doc)
		return string(out)
	}
	return normalize(a) == normalize(b)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}
