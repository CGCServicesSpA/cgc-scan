package provision

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeMetadata(t *testing.T, cacheDir string, updated time.Time) {
	t.Helper()
	dir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{
		"Version":      2,
		"UpdatedAt":    updated.UTC().Format(time.RFC3339Nano),
		"DownloadedAt": updated.UTC().Format(time.RFC3339Nano),
	})
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadDBInfo(t *testing.T) {
	cache := t.TempDir()
	updated := time.Now().Add(-4 * time.Hour)
	writeMetadata(t, cache, updated)
	info, err := ReadDBInfo(cache)
	if err != nil {
		t.Fatal(err)
	}
	if info.Schema != 2 || info.Source != "trivy-db" {
		t.Fatalf("info = %+v", info)
	}
	if info.AgeSeconds < 3*3600 || info.AgeSeconds > 5*3600 {
		t.Fatalf("edad = %d", info.AgeSeconds)
	}
}

func TestReadDBInfoMissing(t *testing.T) {
	if _, err := ReadDBInfo(t.TempDir()); !errors.Is(err, ErrDBAbsent) {
		t.Fatalf("err = %v, want ErrDBAbsent", err)
	}
}

func TestCheckDBOfflinePolicy(t *testing.T) {
	tests := []struct {
		name    string
		age     time.Duration
		wantErr bool
		status  string
	}{
		{"reciente", time.Hour, false, "offline"},
		{"con aviso", 100 * time.Hour, false, "stale"},
		{"bloqueada", 8 * 24 * time.Hour, true, "stale"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := t.TempDir()
			writeMetadata(t, cache, time.Now().Add(-tt.age))
			info, err := CheckDBOffline(cache, 72*time.Hour, 7*24*time.Hour)
			if tt.wantErr {
				if err == nil {
					t.Fatal("se esperaba error por antigüedad")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.Status != tt.status {
				t.Fatalf("status = %q, want %q", info.Status, tt.status)
			}
		})
	}
}

func TestCheckDBOfflineMissing(t *testing.T) {
	if _, err := CheckDBOffline(t.TempDir(), time.Hour, 2*time.Hour); !errors.Is(err, ErrDBAbsent) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDBMetadataInvalid(t *testing.T) {
	if _, err := parseDBMetadata([]byte("no-json")); err == nil {
		t.Fatal("se aceptaron metadatos inválidos")
	}
	if _, err := parseDBMetadata([]byte(`{"Version":2}`)); err == nil {
		t.Fatal("se aceptaron metadatos sin fecha")
	}
}
