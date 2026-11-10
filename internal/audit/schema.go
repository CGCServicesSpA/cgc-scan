package audit

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// LedgerSchemaJSON es el esquema público embebido del ledger. La copia de
// schemas/ se verifica contra este archivo en las pruebas.
//
//go:embed audit-ledger.schema.json
var LedgerSchemaJSON []byte

// FindingsSchemaJSON es el esquema público embebido de hallazgos.
//
//go:embed findings.schema.json
var FindingsSchemaJSON []byte

var (
	ledgerOnce   sync.Once
	ledgerSchema *jsonschema.Schema
	ledgerErr    error

	findingsOnce   sync.Once
	findingsSchema *jsonschema.Schema
	findingsErr    error
)

func compiledLedgerSchema() (*jsonschema.Schema, error) {
	ledgerOnce.Do(func() {
		ledgerSchema, ledgerErr = compileSchema("cgc-scan-audit-ledger.json", LedgerSchemaJSON)
	})
	return ledgerSchema, ledgerErr
}

func compiledFindingsSchema() (*jsonschema.Schema, error) {
	findingsOnce.Do(func() {
		findingsSchema, findingsErr = compileSchema("cgc-scan-findings.json", FindingsSchemaJSON)
	})
	return findingsSchema, findingsErr
}

func compileSchema(name string, raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("esquema %s no es JSON válido: %w", name, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		return nil, fmt.Errorf("registrar esquema %s: %w", name, err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		return nil, fmt.Errorf("compilar esquema %s: %w", name, err)
	}
	return sch, nil
}

// ValidateLedger comprueba que data cumpla la estructura del contrato.
func ValidateLedger(data []byte) error {
	return validateAgainst(data, compiledLedgerSchema, "el ledger no cumple el esquema audit-ledger-1.0.0")
}

// ValidateFindings comprueba que data cumpla la estructura del contrato.
func ValidateFindings(data []byte) error {
	return validateAgainst(data, compiledFindingsSchema, "los hallazgos no cumplen el esquema findings-1.0.0")
}

func validateAgainst(data []byte, schemaFn func() (*jsonschema.Schema, error), msg string) error {
	if !json.Valid(data) {
		return errors.New("el documento no es JSON válido")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decodificar documento: %w", err)
	}
	sch, err := schemaFn()
	if err != nil {
		return err
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

// DecodeLedger valida y decodifica un ledger.
func DecodeLedger(data []byte) (*Ledger, error) {
	if err := checkSize(data, MaxLedgerBytes, "el ledger"); err != nil {
		return nil, err
	}
	if err := ValidateLedger(data); err != nil {
		return nil, err
	}
	if err := checkJSONDepth(data, MaxJSONDepth); err != nil {
		return nil, fmt.Errorf("ledger inválido: %w", err)
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("ledger inválido: %w", err)
	}
	return &l, nil
}

// DecodeFindings valida y decodifica el documento de hallazgos.
func DecodeFindings(data []byte) (*Findings, error) {
	if err := checkSize(data, MaxFindingsBytes, "los hallazgos"); err != nil {
		return nil, err
	}
	if err := ValidateFindings(data); err != nil {
		return nil, err
	}
	if err := checkJSONDepth(data, MaxJSONDepth); err != nil {
		return nil, fmt.Errorf("hallazgos inválidos: %w", err)
	}
	var f Findings
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("hallazgos inválidos: %w", err)
	}
	return &f, nil
}
