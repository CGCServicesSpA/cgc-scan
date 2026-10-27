// Package plan construye el plan de cobertura: qué unidades se analizan, con
// qué motores y qué quedó fuera (RF-02, RF-14).
package plan

import (
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

// Estados de una unidad o de un motor dentro de la unidad.
const (
	StatusRequested = "requested"
	StatusCompleted = "completed"
	StatusSkipped   = "skipped"
	StatusFailed    = "failed"
)

// EnginePlan declara qué se espera de un motor en una unidad.
type EnginePlan struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// UnitPlan es una unidad con sus motores aplicables.
type UnitPlan struct {
	Unit    discovery.Unit `json:"unit"`
	Engines []EnginePlan   `json:"engines"`
}

// NotAnalyzed enumera una unidad que no se analizó y por qué.
type NotAnalyzed struct {
	Unit     string   `json:"unit"`
	Path     string   `json:"path"`
	Reason   string   `json:"reason"`
	Patterns []string `json:"patterns,omitempty"`
}

// Plan es el contrato entre descubrimiento, orquestador y reporte.
type Plan struct {
	Root        string                `json:"root"`
	Units       []UnitPlan            `json:"units"`
	Exclusions  []discovery.Exclusion `json:"exclusions"`
	NotAnalyzed []NotAnalyzed         `json:"not_analyzed"`
	Partial     bool                  `json:"partial"`
	Include     []string              `json:"include"`
	Exclude     []string              `json:"exclude"`
}
