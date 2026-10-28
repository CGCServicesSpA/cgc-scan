package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileIsPrivateAndValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "report.json")
	if err := WriteFile(path, minimalDoc()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if err := Validate(data); err != nil {
		t.Fatalf("el archivo escrito no valida: %v", err)
	}
}
