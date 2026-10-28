//go:build integration

package provision

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestVulnDBIntegration descarga el espejo de Go y el snapshot de RustSec.
func TestVulnDBIntegration(t *testing.T) {
	if os.Getenv("CGC_SCAN_TEST_VULNDB") == "" {
		t.Skip("define CGC_SCAN_TEST_VULNDB=1 para descargar las bases reales")
	}
	base := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	goDir := filepath.Join(base, "go-vulndb")
	info, err := EnsureGoVulnDB(ctx, nil, goDir, false)
	if err != nil {
		t.Fatalf("go-vulndb: %v", err)
	}
	if info.Status != "updated" {
		t.Fatalf("estado = %+v", info)
	}
	if _, err := os.Stat(filepath.Join(goDir, "ID", "GO-2021-0113.json")); err != nil {
		t.Fatalf("falta un aviso esperado: %v", err)
	}
	// Reutilización y modo offline.
	reused, err := EnsureGoVulnDB(ctx, nil, goDir, true)
	if err != nil || reused.Status != "reused" {
		t.Fatalf("reutilización = %+v %v", reused, err)
	}

	rustDir := filepath.Join(base, "rustsec")
	if _, err := EnsureRustSecDB(ctx, nil, rustDir, false); err != nil {
		t.Fatalf("rustsec: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rustDir, "crates")); err != nil {
		t.Fatalf("RustSec sin crates: %v", err)
	}
	if _, err := EnsureRustSecDB(ctx, nil, rustDir, true); err != nil {
		t.Fatalf("rustsec offline: %v", err)
	}
}
