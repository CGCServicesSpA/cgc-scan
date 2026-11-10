package agent

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaJSON es el contrato embebido del documento de agente.
//
//go:embed agent.schema.json
var SchemaJSON []byte

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

// Schema compila el contrato agent-1.0.0 una sola vez.
func Schema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(SchemaJSON))
		if err != nil {
			schemaErr = fmt.Errorf("esquema de agente inválido: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("cgc-scan-agent.json", doc); err != nil {
			schemaErr = err
			return
		}
		schema, schemaErr = c.Compile("cgc-scan-agent.json")
	})
	return schema, schemaErr
}

// Validate comprueba un documento contra el contrato agent-1.0.0.
func Validate(data []byte) error {
	sch, err := Schema()
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("el documento de agente no cumple agent-1.0.0: %w", err)
	}
	return nil
}
