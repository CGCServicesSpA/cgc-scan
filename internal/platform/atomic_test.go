package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "report.json")
	want := []byte(`{"ok":true}`)

	if err := WriteFileAtomic(path, want, 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("contenido = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permisos = %o, want 600", perm)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("quedó un temporal: %s", e.Name())
		}
	}
}

func TestWriteFileAtomicOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("contenido = %q, want second", got)
	}
}

func TestWriteFileAtomicFailureLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// Renombrar un archivo sobre un directorio no vacío falla en todos los
	// sistemas soportados; el temporal debe limpiarse.
	if err := WriteFileAtomic(target, []byte("x"), 0o600); err == nil {
		t.Fatal("se esperaba error al escribir sobre un directorio")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("quedó un temporal tras el fallo: %s", e.Name())
		}
	}
}

func TestEnsureFileModeRestricts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFileMode(path, 0o600); err != nil {
		t.Fatalf("EnsureFileMode: %v", err)
	}
	info, _ := os.Stat(path)
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permisos = %o, want 600", got)
	}
}

func TestReadFileBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileBounded(path, 4); err == nil {
		t.Fatal("se esperaba error por límite")
	}
	got, err := ReadFileBounded(path, 5)
	if err != nil {
		t.Fatalf("ReadFileBounded: %v", err)
	}
	if string(got) != "12345" {
		t.Fatalf("contenido = %q", got)
	}
}
