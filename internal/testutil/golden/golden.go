// Package golden compara documentos JSON con archivos de referencia tras
// eliminar los campos volátiles declarados en design §10.1.
package golden

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Update actualiza los archivos de referencia. Se activa con -update.
var Update = flag.Bool("update", false, "actualizar los archivos golden")

// volatileKeys son claves cuyo valor cambia entre ejecuciones equivalentes.
var volatileTopLevel = []string{"id", "started_at", "finished_at", "duration_ms", "cancelled"}

// Normalize elimina los campos volátiles de run, la duración de cada motor y
// las rutas absolutas conocidas, y devuelve el JSON ordenado e indentado.
func Normalize(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("documento no es JSON: %v", err)
	}
	if run, ok := doc["run"].(map[string]any); ok {
		for _, k := range volatileTopLevel {
			delete(run, k)
		}
	}
	if tools, ok := doc["tools"].(map[string]any); ok {
		if engines, ok := tools["engines"].([]any); ok {
			for _, e := range engines {
				if m, ok := e.(map[string]any); ok {
					delete(m, "duration_ms")
				}
			}
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("serializar documento: %v", err)
	}
	return append(out, '\n')
}

// Assert compara got (normalizado) con dir/name. Si -update está activo,
// escribe el archivo en lugar de comparar.
func Assert(t *testing.T, dir, name string, got []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	normalized := Normalize(t, got)
	if *Update {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("crear %s: %v", dir, err)
		}
		if err := os.WriteFile(path, normalized, 0o600); err != nil {
			t.Fatalf("actualizar golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("leer golden %s (usa -update para crearlo): %v", path, err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(normalized)) {
		t.Fatalf("golden %s no coincide.\n--- got ---\n%s\n--- want ---\n%s", path, normalized, want)
	}
}
