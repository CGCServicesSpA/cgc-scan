// Package policy decide el código de salida y, más adelante, evalúa el umbral
// y las excepciones de un reporte.
package policy

// Códigos de salida públicos de la CLI (PRD §8.1).
const (
	ExitOK         = 0
	ExitViolation  = 1
	ExitUsage      = 2
	ExitIncomplete = 3
	ExitCanceled   = 130
)

// RunOutcome describe el resultado de ejecución, independiente de la política
// de hallazgos. Complete es falso cuando falta un motor, una base, una
// herramienta o el aislamiento exigido.
type RunOutcome struct {
	Canceled    bool
	InvalidArgs bool
	Complete    bool
}

// PolicyOutcome describe si el umbral se incumplió. La decisión de qué
// severidad cuenta la toma Evaluate, no Decide.
type PolicyOutcome struct {
	Violated bool
}

// Decide es una función pura: aplica la prioridad
// cancelación (130) → argumentos inválidos (2) → ejecución incompleta (3) →
// incumplimiento (1) → éxito (0).
func Decide(r RunOutcome, p PolicyOutcome) int {
	switch {
	case r.Canceled:
		return ExitCanceled
	case r.InvalidArgs:
		return ExitUsage
	case !r.Complete:
		return ExitIncomplete
	case p.Violated:
		return ExitViolation
	default:
		return ExitOK
	}
}
