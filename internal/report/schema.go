// Package report define el contrato del reporte: el esquema embebido y, más
// adelante, los renderizadores JSON, texto y prompt.
package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// SchemaJSON es el esquema público embebido. La copia de schemas/ se verifica
// contra este archivo en las pruebas para evitar divergencias.
//
//go:embed report.schema.json
var SchemaJSON []byte

var (
	compiledOnce sync.Once
	compiled     *jsonschema.Schema
	compileErr   error
)

// Schema compila y devuelve el esquema una sola vez.
func Schema() (*jsonschema.Schema, error) {
	compiledOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(SchemaJSON))
		if err != nil {
			compileErr = fmt.Errorf("esquema del reporte no es JSON válido: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("cgc-scan-report.json", doc); err != nil {
			compileErr = fmt.Errorf("registrar esquema: %w", err)
			return
		}
		compiled, compileErr = c.Compile("cgc-scan-report.json")
		if compileErr != nil {
			compileErr = fmt.Errorf("compilar esquema del reporte: %w", compileErr)
		}
	})
	return compiled, compileErr
}

// Validate comprueba que data sea un documento JSON válido contra el esquema.
func Validate(data []byte) error {
	if !json.Valid(data) {
		return errors.New("el reporte no es JSON válido")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decodificar reporte: %w", err)
	}
	sch, err := Schema()
	if err != nil {
		return err
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("el reporte no cumple el esquema v%s: %w", version.SchemaVersion, err)
	}
	return nil
}
