// Package adapter define el contrato común de los motores.
package adapter

import (
	"context"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// Requirement describe un prerrequisito de un adaptador. Si no se cumple, el
// adaptador se omite con requirement_missing y la ejecución es incompleta.
type Requirement struct {
	Kind    string // toolchain | database | rules | binary
	Name    string
	Detail  string
	Missing bool
}

// Diagnostic es una limitación o error de parsing del propio motor.
type Diagnostic struct {
	Engine  string `json:"engine"`
	Message string `json:"message"`
}

// Parsed es el resultado de interpretar la salida de un motor.
type Parsed struct {
	Findings    []normalize.Finding
	Diagnostics []Diagnostic
}

// ExitPolicy permite que un adaptador declare códigos de salida que significan
// "ejecución completa con hallazgos" en lugar de fallo.
type ExitPolicy interface {
	AcceptExit(code int) bool
}

// RecipeCandidate es una propuesta de comando de validación detectada en el
// proyecto. Nunca es una receta de confianza hasta que el usuario la confirma.
type RecipeCandidate struct {
	Unit    string `json:"unit"`
	Kind    string `json:"kind"` // test | build
	Command string `json:"command"`
	Workdir string `json:"workdir"`
	Origin  string `json:"origin"` // package.json | composer.json | Makefile | pyproject.toml | adapter
}

// RecipeProvider expone los candidatos que conoce el adaptador.
type RecipeProvider interface {
	RecipeCandidates(u discovery.Unit) []RecipeCandidate
}

// Adapter es el contrato de un motor específico.
type Adapter interface {
	// ID identifica el motor en el reporte.
	ID() string
	// Applies informa si el adaptador cubre la unidad.
	Applies(u discovery.Unit) bool
	// Requirements declara lo que necesita para ejecutarse.
	Requirements(ctx context.Context, u discovery.Unit) []Requirement
	// Invocations produce las ejecuciones necesarias para la unidad.
	Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error)
	// Parse interpreta la salida; es tolerante a salida parcial.
	Parse(raw []byte) (Parsed, error)
	// Redact enmascara secretos antes de persistir la salida original.
	Redact(raw []byte) []byte
}
