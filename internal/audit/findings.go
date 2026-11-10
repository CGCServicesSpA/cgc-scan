package audit

import (
	"encoding/json"
	"fmt"
)

// FindingsSchemaVersion es la versión del contrato de hallazgos de auditoría.
const FindingsSchemaVersion = "findings-1.0.0"

// Veredictos. Son estados distintos, no grados de confianza.
const (
	VerdictConfirmed       = "confirmed"
	VerdictNeedsValidation = "needs_validation"
	VerdictRejected        = "rejected"
)

// Atribución de procedencia del documento. El motor valida estructura y
// consistencia, no verdad; declararlo evita que el reporte se arrogue una
// autoridad que no tiene.
const (
	AttestedByCaller    = "caller"
	EngineRoleStructure = "structure-and-consistency"
)

// TraceStep es un paso de la traza de origen a sumidero.
type TraceStep struct {
	Kind        string `json:"kind"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// Evidence es una ubicación que sostiene la afirmación.
type Evidence struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
}

// Condition es una precondición del hallazgo.
type Condition struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// Execution documenta la reproducción en la interfaz nativa del objetivo.
type Execution struct {
	AttackerPerspective string   `json:"attacker_perspective"`
	Payloads            []string `json:"payloads"`
	Instructions        []string `json:"instructions"`
	ObservedResult      string   `json:"observed_result"`
}

// CodeChange es un cambio de código sugerido.
type CodeChange struct {
	FileName  string `json:"file_name"`
	FixedCode string `json:"fixed_code"`
}

// Remediation describe la corrección más pequeña que restablece el invariante.
type Remediation struct {
	Strategy    string       `json:"strategy"`
	CodeChanges []CodeChange `json:"code_changes,omitempty"`
}

// Score es una puntuación con su razón.
type Score struct {
	Score  string `json:"score"`
	Reason string `json:"reason"`
}

// Severity separa probabilidad de impacto. El overall nunca puede superar al
// impacto demostrado.
type Severity struct {
	Likelihood Score  `json:"likelihood"`
	Impact     Score  `json:"impact"`
	Overall    string `json:"overall_severity"`
}

// Confidence es la confianza del agente, con su razón.
type Confidence struct {
	Score  string `json:"score"`
	Reason string `json:"reason"`
}

// ValidationPlan resuelve un bloqueo local o de despliegue.
type ValidationPlan struct {
	Local      string `json:"local,omitempty"`
	Deployment string `json:"deployment,omitempty"`
}

// Record es un hallazgo en uno de los tres veredictos. Los campos no
// aplicables a un veredicto quedan vacíos y no se emiten.
type Record struct {
	Verdict     string `json:"verdict"`
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	Description string `json:"description"`

	// confirmed
	RootCause        string       `json:"root_cause,omitempty"`
	IntendedBehavior string       `json:"intended_behavior,omitempty"`
	Conditions       []Condition  `json:"conditions,omitempty"`
	Execution        *Execution   `json:"execution,omitempty"`
	Remediation      *Remediation `json:"remediation,omitempty"`
	Severity         *Severity    `json:"severity,omitempty"`
	Confidence       *Confidence  `json:"confidence,omitempty"`

	// needs_validation y rejected
	ClaimedRootCause string          `json:"claimed_root_cause,omitempty"`
	Blockers         []string        `json:"blockers,omitempty"`
	ValidationPlan   *ValidationPlan `json:"validation_plan,omitempty"`
	Reason           string          `json:"reason,omitempty"`

	// comunes
	Trace    []TraceStep `json:"trace"`
	Evidence []Evidence  `json:"evidence"`
}

// MarshalJSON emite solo los campos del veredicto. El contrato público no
// admite mezclas: un needs_validation con severidad sería un hallazgo
// confirmado disfrazado.
func (r Record) MarshalJSON() ([]byte, error) {
	switch r.Verdict {
	case VerdictConfirmed:
		return json.Marshal(struct {
			Verdict          string       `json:"verdict"`
			Fingerprint      string       `json:"fingerprint"`
			Title            string       `json:"title"`
			Description      string       `json:"description"`
			RootCause        string       `json:"root_cause"`
			IntendedBehavior string       `json:"intended_behavior"`
			Trace            []TraceStep  `json:"trace"`
			Evidence         []Evidence   `json:"evidence"`
			Conditions       []Condition  `json:"conditions"`
			Execution        *Execution   `json:"execution"`
			Remediation      *Remediation `json:"remediation"`
			Severity         *Severity    `json:"severity"`
			Confidence       *Confidence  `json:"confidence"`
		}{
			Verdict: r.Verdict, Fingerprint: r.Fingerprint, Title: r.Title,
			Description: r.Description, RootCause: r.RootCause,
			IntendedBehavior: r.IntendedBehavior, Trace: nonNilTrace(r.Trace),
			Evidence: nonNilEvidence(r.Evidence), Conditions: nonNilConditions(r.Conditions),
			Execution: r.Execution, Remediation: r.Remediation, Severity: r.Severity,
			Confidence: r.Confidence,
		})
	case VerdictNeedsValidation:
		return json.Marshal(struct {
			Verdict          string          `json:"verdict"`
			Fingerprint      string          `json:"fingerprint"`
			Title            string          `json:"title"`
			Description      string          `json:"description"`
			ClaimedRootCause string          `json:"claimed_root_cause"`
			Trace            []TraceStep     `json:"trace"`
			Evidence         []Evidence      `json:"evidence"`
			Blockers         []string        `json:"blockers"`
			ValidationPlan   *ValidationPlan `json:"validation_plan"`
		}{
			Verdict: r.Verdict, Fingerprint: r.Fingerprint, Title: r.Title,
			Description: r.Description, ClaimedRootCause: r.ClaimedRootCause,
			Trace: nonNilTrace(r.Trace), Evidence: nonNilEvidence(r.Evidence),
			Blockers: nonNil(r.Blockers), ValidationPlan: r.ValidationPlan,
		})
	case VerdictRejected:
		return json.Marshal(struct {
			Verdict          string      `json:"verdict"`
			Fingerprint      string      `json:"fingerprint"`
			Title            string      `json:"title"`
			Description      string      `json:"description"`
			ClaimedRootCause string      `json:"claimed_root_cause"`
			Trace            []TraceStep `json:"trace"`
			Evidence         []Evidence  `json:"evidence"`
			Reason           string      `json:"reason"`
		}{
			Verdict: r.Verdict, Fingerprint: r.Fingerprint, Title: r.Title,
			Description: r.Description, ClaimedRootCause: r.ClaimedRootCause,
			Trace: nonNilTrace(r.Trace), Evidence: nonNilEvidence(r.Evidence), Reason: r.Reason,
		})
	default:
		return nil, fmt.Errorf("veredicto desconocido: %q", r.Verdict)
	}
}

// Provenance declara quién aporta la evidencia.
type Provenance struct {
	AttestedBy     string `json:"attested_by"`
	EngineVerified bool   `json:"engine_verified"`
	EngineRole     string `json:"engine_role"`
}

// CallerProvenance es la procedencia correcta en v1: el agente llamador
// aporta la evidencia y el motor solo valida estructura y consistencia.
func CallerProvenance() Provenance {
	return Provenance{
		AttestedBy:     AttestedByCaller,
		EngineVerified: false,
		EngineRole:     EngineRoleStructure,
	}
}

// SeverityCounts cuenta hallazgos confirmados por severidad.
type SeverityCounts struct {
	Informational int `json:"informational"`
	Low           int `json:"low"`
	Medium        int `json:"medium"`
	High          int `json:"high"`
	Critical      int `json:"critical"`
}

// FindingsSummary cuenta registros por veredicto.
type FindingsSummary struct {
	Confirmed       int            `json:"confirmed"`
	NeedsValidation int            `json:"needs_validation"`
	Rejected        int            `json:"rejected"`
	BySeverity      SeverityCounts `json:"confirmed_by_severity"`
}

// Findings es el documento de hallazgos de una corrida.
type Findings struct {
	SchemaVersion string          `json:"schema_version"`
	Run           Run             `json:"run"`
	Target        Target          `json:"target"`
	Provenance    Provenance      `json:"provenance"`
	Summary       FindingsSummary `json:"summary"`
	Findings      []Record        `json:"findings"`
}

// Recompute normaliza el documento y recalcula el resumen.
func (f *Findings) Recompute() {
	if f.SchemaVersion == "" {
		f.SchemaVersion = FindingsSchemaVersion
	}
	if f.Findings == nil {
		f.Findings = []Record{}
	}
	sortRecords(f.Findings)
	f.Summary = FindingsSummary{}
	for _, r := range f.Findings {
		switch r.Verdict {
		case VerdictConfirmed:
			f.Summary.Confirmed++
			if r.Severity != nil {
				switch r.Severity.Overall {
				case "informational":
					f.Summary.BySeverity.Informational++
				case "low":
					f.Summary.BySeverity.Low++
				case "medium":
					f.Summary.BySeverity.Medium++
				case "high":
					f.Summary.BySeverity.High++
				case "critical":
					f.Summary.BySeverity.Critical++
				}
			}
		case VerdictNeedsValidation:
			f.Summary.NeedsValidation++
		case VerdictRejected:
			f.Summary.Rejected++
		}
	}
}

func nonNilTrace(in []TraceStep) []TraceStep {
	if in == nil {
		return []TraceStep{}
	}
	return in
}

func nonNilEvidence(in []Evidence) []Evidence {
	if in == nil {
		return []Evidence{}
	}
	return in
}

func nonNilConditions(in []Condition) []Condition {
	if in == nil {
		return []Condition{}
	}
	return in
}
