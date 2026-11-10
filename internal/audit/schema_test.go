package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicSchemasMatchEmbedded(t *testing.T) {
	cases := []struct {
		embedded []byte
		path     string
	}{
		{LedgerSchemaJSON, "audit-ledger.schema.json"},
		{FindingsSchemaJSON, "findings.schema.json"},
	}
	for _, c := range cases {
		public, err := os.ReadFile(filepath.Join("..", "..", "schemas", c.path))
		if err != nil {
			t.Fatalf("leer schemas/%s: %v", c.path, err)
		}
		if !bytes.Equal(public, c.embedded) {
			t.Fatalf("schemas/%s y el esquema embebido divergen", c.path)
		}
	}
}

func TestSchemasCompile(t *testing.T) {
	if _, err := compiledLedgerSchema(); err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if _, err := compiledFindingsSchema(); err != nil {
		t.Fatalf("findings: %v", err)
	}
}
