package policy

import (
	"fmt"
)

// Valores válidos de --fail-on para la auditoría: veredictos aplicables y
// severidades auditadas. La política difiere de scan --fail-on: el escaneo
// cuenta hallazgos del motor por su severidad normalizada; la auditoría
// cuenta veredictos auditados sellados con la escala propia del contrato de
// hallazgos (informational|low|medium|high|critical).
const (
	AuditFailOnConfirmed       = "confirmed"
	AuditFailOnNeedsValidation = "needs_validation"
)

// auditSeverityRank es la escala de severidad del contrato de hallazgos de
// auditoría; es distinta de la escala normalizada del escaneo.
var auditSeverityRank = map[string]int{
	"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

// AuditFailOnValid informa si value es un umbral de auditoría válido.
func AuditFailOnValid(value string) bool {
	switch value {
	case AuditFailOnConfirmed, AuditFailOnNeedsValidation:
		return true
	}
	_, ok := auditSeverityRank[value]
	return ok
}

// AuditFindingsSummary es el resumen mínimo de hallazgos sellados que el
// umbral de auditoría necesita: confirmados por severidad overall y registros
// pendientes de validación.
type AuditFindingsSummary struct {
	ConfirmedBySeverity map[string]int
	NeedsValidation     int
}

// AuditThresholdViolated evalúa el umbral --fail-on contra el resumen sellado.
// Es una función pura: la política de salida no altera hallazgos ni estado.
// La severidad del umbral se compara contra la severidad overall auditada
// (>= umbral cuenta); un error de umbral es un diagnóstico útil, no un silencio.
func AuditThresholdViolated(failOn string, s AuditFindingsSummary) (bool, error) {
	switch failOn {
	case AuditFailOnConfirmed:
		total := 0
		for _, n := range s.ConfirmedBySeverity {
			total += n
		}
		return total > 0, nil
	case AuditFailOnNeedsValidation:
		return s.NeedsValidation > 0, nil
	}
	rank, ok := auditSeverityRank[failOn]
	if !ok {
		return false, fmt.Errorf("umbral --fail-on desconocido: %q (confirmed, needs_validation o una severidad: informational|low|medium|high|critical)", failOn)
	}
	total := 0
	for severity, n := range s.ConfirmedBySeverity {
		if auditSeverityRank[severity] >= rank {
			total += n
		}
	}
	return total > 0, nil
}
