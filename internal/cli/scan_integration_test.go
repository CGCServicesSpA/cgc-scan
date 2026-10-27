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
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
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

// TestScanDockerIntegration ejecuta el runner Docker real. Requiere
// CGC_SCAN_TEST_DOCKER=1 y un volumen con base preparada (cgc-scan update-db).
func TestScanDockerIntegration(t *testing.T) {
	if os.Getenv("CGC_SCAN_TEST_DOCKER") == "" {
		t.Skip("define CGC_SCAN_TEST_DOCKER=1 para probar el runner Docker")
	}
	ctx := context.Background()
	if _, err := runner.DetectDocker(ctx); err != nil {
		t.Skipf("Docker no disponible: %v", err)
	}
	volume := runner.VolumeName(os.Getuid())
	if _, err := provision.EnsureVolume(ctx, "docker", volume); err != nil {
		t.Fatalf("volumen: %v", err)
	}
	d := &runner.Docker{Image: "ghcr.io/aquasecurity/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c", Volume: volume}
	if _, err := provision.DockerDBMetadata(ctx, d); err != nil {
		t.Skipf("el volumen no tiene base; ejecuta cgc-scan update-db: %v", err)
	}

	fixture := t.TempDir()
	writeFixture(t, fixture)
	paths := platform.Paths{
		ConfigDir: filepath.Join(t.TempDir(), "cfg"),
		DataDir:   filepath.Join(t.TempDir(), "data"),
		CacheDir:  filepath.Join(t.TempDir(), "cache"),
	}
	var stdout, stderr bytes.Buffer
	app, err := New(&stdout, &stderr, WithTTY(false), WithPaths(paths))
	if err != nil {
		t.Fatal(err)
	}
	code := app.Execute(ctx, []string{"scan", fixture, "--trivy-mode", "docker", "--offline", "--format", "json"})
	if code != 1 {
		t.Fatalf("código = %d, want 1: %s", code, stderr.String())
	}
	if err := report.Validate(stdout.Bytes()); err != nil {
		t.Fatalf("reporte inválido: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(stdout.Bytes(), &doc)
	eng := doc["tools"].(map[string]any)["engines"].([]any)[0].(map[string]any)
	if eng["mode"] != "docker" || eng["isolation"] != "enforced" {
		t.Fatalf("motor = %v", eng)
	}
	if doc["isolation"].(map[string]any)["level"] != "enforced" {
		t.Fatalf("isolation = %v", doc["isolation"])
	}
	if n := len(doc["findings"].([]any)); n < 6 {
		t.Fatalf("hallazgos = %d", n)
	}
}

func writeFixture(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"go.mod":     "module example.com/vulnapp\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.0\n",
		"go.sum":     "golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\ngolang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=\n",
		"main.go":    "package main\n\nimport \"golang.org/x/text/language\"\n\nfunc main() { _ = language.English }\n",
		"Dockerfile": "FROM alpine:3.20\nUSER root\n",
		".env":       "GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
