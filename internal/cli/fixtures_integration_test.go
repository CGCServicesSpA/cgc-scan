//go:build integration

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFixturesVulnerableAndFixedIntegration escanea los pares reales de
// fixtures y comprueba que el vulnerable detecta y el corregido no. Requiere
// Docker, las bases preparadas y CGC_SCAN_TEST_FIXTURES=1.
func TestFixturesVulnerableAndFixedIntegration(t *testing.T) {
	if os.Getenv("CGC_SCAN_TEST_FIXTURES") == "" {
		t.Skip("define CGC_SCAN_TEST_FIXTURES=1 con CGC_SCAN_*_DIR apuntando a datos preparados")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path         string
		wantFindings bool
	}{
		{"go/vulnerable", true}, {"go/fixed", false},
		{"javascript/vulnerable", true}, {"javascript/fixed", false},
		{"typescript/vulnerable", true}, {"typescript/fixed", false},
		{"php/vulnerable", true}, {"php/fixed", false},
		{"rust/vulnerable", true}, {"rust/fixed", false},
		{"python/vulnerable", true}, {"python/fixed", false},
		{"monorepo", true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			dir := filepath.Join(root, tc.path)
			before := hashTree(t, dir)
			var stdout, stderr bytes.Buffer
			app, err := New(&stdout, &stderr, WithTTY(false))
			if err != nil {
				t.Fatal(err)
			}
			code := app.Execute(context.Background(), []string{"scan", dir, "--trivy-mode", "docker", "--offline", "--format", "json"})
			if code != 0 && code != 1 {
				t.Fatalf("código = %d: %s", code, stderr.String())
			}
			var doc map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
				t.Fatalf("JSON inválido: %v", err)
			}
			findings := doc["findings"].([]any)
			if tc.wantFindings && len(findings) == 0 {
				t.Fatalf("el fixture vulnerable no produjo hallazgos")
			}
			if !tc.wantFindings && len(findings) != 0 {
				t.Fatalf("el fixture corregido conserva %d hallazgos: %v", len(findings), findings)
			}
			if after := hashTree(t, dir); after != before {
				t.Fatal("el escaneo modificó el proyecto")
			}
		})
	}
}

func hashTree(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h.Write([]byte(path))
		h.Write([]byte(info.Mode().String()))
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}
