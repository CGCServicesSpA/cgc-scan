package golden

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeRemovesVolatileFields(t *testing.T) {
	in := []byte(`{
	  "run": {"id":"a","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:01Z","duration_ms":5,"cli_version":"1"},
	  "tools": {"engines":[{"id":"trivy","duration_ms":7,"status":"completed"}]},
	  "findings": []
	}`)
	out := Normalize(t, in)
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["run"].(map[string]any)
	for _, k := range []string{"id", "started_at", "finished_at", "duration_ms", "cancelled"} {
		if _, ok := run[k]; ok {
			t.Errorf("run.%s no se eliminó", k)
		}
	}
	if run["cli_version"] != "1" {
		t.Errorf("se eliminó un campo estable")
	}
	engine := doc["tools"].(map[string]any)["engines"].([]any)[0].(map[string]any)
	if _, ok := engine["duration_ms"]; ok {
		t.Error("duration_ms del motor no se eliminó")
	}
}

func TestAssertRoundTrip(t *testing.T) {
	dir := t.TempDir()
	doc := []byte(`{"run":{"id":"x","duration_ms":1},"findings":[]}`)
	old := *Update
	*Update = true
	Assert(t, dir, "caso.json", doc)
	*Update = old
	Assert(t, dir, "caso.json", doc)
	if _, err := os.Stat(filepath.Join(dir, "caso.json")); err != nil {
		t.Fatalf("no se creó el golden: %v", err)
	}
}
