package report

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// RenderJSON serializa el documento canónico.
func RenderJSON(doc *Document) ([]byte, error) {
	return doc.MarshalJSON()
}

// ValidateDocument comprueba el documento contra el esquema público.
func ValidateDocument(doc *Document) error {
	data, err := RenderJSON(doc)
	if err != nil {
		return err
	}
	return Validate(data)
}

// WriteFile escribe el JSON de forma atómica y con permisos 0600.
func WriteFile(path string, doc *Document) error {
	data, err := RenderJSON(doc)
	if err != nil {
		return err
	}
	if err := platform.WritePrivateFile(path, data); err != nil {
		return fmt.Errorf("escribir reporte en %s: %w", path, err)
	}
	return nil
}

// Decode interpreta un reporte desde JSON.
func Decode(data []byte) (*Document, error) {
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("reporte inválido: %w", err)
	}
	return &doc, nil
}
