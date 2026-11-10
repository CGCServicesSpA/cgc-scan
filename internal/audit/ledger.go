// Package audit define el protocolo determinista de auditoría asistida por un
// agente externo: ledger de cobertura, contrato de hallazgos con tres
// veredictos, catálogo de clases de ataque y derivación de reportes.
//
// El motor no caza ni verifica: reparte asignaciones, valida estructura y
// consistencia, contabiliza el presupuesto y deja constancia de lo que no se
// cubrió. La verdad de un hallazgo sigue siendo responsabilidad del agente
// llamador (ver Provenance).
package audit

import (
	"encoding/json"
	"sort"
)

// LedgerSchemaVersion es la versión del contrato del ledger de cobertura.
const LedgerSchemaVersion = "audit-ledger-1.0.0"

// Perfiles de ejecución. Cambian la amplitud del reparto, nunca el listón de
// evidencia.
const (
	ProfileQuick    = "quick"
	ProfileStandard = "standard"
	ProfileDeep     = "deep"
)

// Estados de una unidad de cobertura.
const (
	StatePlanned    = "planned"
	StateInProgress = "in_progress"
	StateCandidate  = "candidate"
	StateCovered    = "covered"
	StateBlocked    = "blocked"
	StateDeferred   = "deferred"
	StateOutOfScope = "out_of_scope"
)

// Estados del ledger completo.
const (
	StatusInProgress = "in_progress"
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// Run identifica la ejecución y la fuente revisada.
type Run struct {
	ID         string `json:"id"`
	StartedAt  string `json:"started_at"`
	CLIVersion string `json:"cli_version"`
	SourceRef  string `json:"source_ref"`
	Dirty      bool   `json:"dirty"`
}

// Target identifica el proyecto analizado.
type Target struct {
	Root    string `json:"root"`
	LocalID string `json:"local_id"`
}

// Budget declara el máximo de invocaciones de agente permitidas. Nil significa
// sin presupuesto explícito.
type Budget struct {
	MaxAgentInvocations int `json:"max_agent_invocations"`
	Used                int `json:"used"`
}

// Check es una comprobación concreta de una unidad, con su dueño. Un verificador
// puede agregar checks propios sin quitarle la unidad al cazador.
type Check struct {
	AgentID       string   `json:"agent_id"`
	ReviewedPaths []string `json:"reviewed_paths"`
	Invariant     string   `json:"invariant"`
	Method        string   `json:"method"`
	Result        string   `json:"result"`
	// Artifact es la ruta relativa al directorio de la corrida para evidencia
	// local; nil en una comprobación solo de fuente.
	Artifact *string `json:"artifact"`
}

// Attempt archiva el estado terminal de una unidad reasignada.
type Attempt struct {
	Wave          int      `json:"wave"`
	AgentID       string   `json:"agent_id"`
	State         string   `json:"state"`
	ReviewedPaths []string `json:"reviewed_paths"`
	Checks        []Check  `json:"checks"`
	Candidates    []string `json:"candidate_fingerprints"`
	Unresolved    []string `json:"unresolved"`
	Reason        string   `json:"reason"`
}

// Unit es una unidad de cobertura: un subsistema, una frontera y una clase de
// ataque concreta.
type Unit struct {
	CoverageID    string   `json:"coverage_id"`
	Subsystem     string   `json:"subsystem"`
	Domain        string   `json:"domain"`
	Boundary      string   `json:"boundary"`
	AttackClass   string   `json:"attack_class"`
	StartingPaths []string `json:"starting_paths"`
	State         string   `json:"state"`
	Wave          int      `json:"wave"`
	// Owner es el agente que recibió la asignación vigente.
	Owner         string    `json:"owner,omitempty"`
	ReviewedPaths []string  `json:"reviewed_paths"`
	Checks        []Check   `json:"checks"`
	Candidates    []string  `json:"candidate_fingerprints"`
	Unresolved    []string  `json:"unresolved"`
	Attempts      []Attempt `json:"attempts"`
	// Reason explica un estado deferred u out_of_scope.
	Reason    string   `json:"reason,omitempty"`
	Hardening []string `json:"hardening,omitempty"`
}

// Summary cuenta unidades por estado. Se deriva; nunca se escribe a mano.
type Summary struct {
	UnitsTotal int `json:"units_total"`
	Planned    int `json:"planned"`
	InProgress int `json:"in_progress"`
	Covered    int `json:"covered"`
	Candidate  int `json:"candidate"`
	Blocked    int `json:"blocked"`
	Deferred   int `json:"deferred"`
	OutOfScope int `json:"out_of_scope"`
}

// PriorRun expone, como contexto, lo que una corrida anterior dejó. Nunca
// suprime trabajo: una fuente igual y limpia solo orienta la prioridad, porque
// una referencia de fuente por sí sola no prueba que el código no cambió.
type PriorRun struct {
	RunID                       string   `json:"run_id"`
	SourceRef                   string   `json:"source_ref"`
	SameRevisionClean           bool     `json:"same_revision_clean"`
	CoveredSameSource           []string `json:"covered_same_source"`
	RejectedFingerprints        []string `json:"rejected_fingerprints"`
	NeedsValidationFingerprints []string `json:"needs_validation_fingerprints"`
}

// CritiqueState archiva las rondas de crítica de cobertura de una corrida.
type CritiqueState struct {
	// Pending declara que hay una tarea de crítica emitida y sin respuesta.
	Pending bool `json:"pending,omitempty"`
	// IssuedTo es el agente que recibió la crítica pendiente.
	IssuedTo string `json:"issued_to,omitempty"`
	// FinalClean declara que la última crítica completó sin trabajo nuevo.
	FinalClean bool `json:"final_clean,omitempty"`
	// Stopped archiva que el crítico pidió detenerse.
	Stopped bool   `json:"stopped,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Rounds cuenta las tareas de crítica emitidas.
	Rounds        int      `json:"rounds,omitempty"`
	ResolvedLeads []string `json:"resolved_leads,omitempty"`
}

// Normalize completa el estado de crítica.
func (s *CritiqueState) Normalize() {
	s.ResolvedLeads = nonNil(s.ResolvedLeads)
	sort.Strings(s.ResolvedLeads)
}

// Ledger es el contrato de cobertura de una corrida de auditoría.
type Ledger struct {
	SchemaVersion    string    `json:"schema_version"`
	Run              Run       `json:"run"`
	Target           Target    `json:"target"`
	Profile          string    `json:"profile"`
	Budget           *Budget   `json:"budget"`
	RunStatus        string    `json:"run_status"`
	IncompleteReason string    `json:"incomplete_reason,omitempty"`
	Summary          Summary   `json:"summary"`
	Units            []Unit    `json:"units"`
	Limitations      []string  `json:"limitations,omitempty"`
	Prior            *PriorRun `json:"prior,omitempty"`
	// Critique archiva las rondas de crítica de cobertura; nil en una corrida
	// que todavía no emitió ninguna.
	Critique *CritiqueState `json:"critique,omitempty"`
}

// Recompute normaliza el ledger: ordena unidades, completa slices y recalcula
// el resumen. Es idempotente y no toca el contenido de las unidades.
func (l *Ledger) Recompute() {
	if l.SchemaVersion == "" {
		l.SchemaVersion = LedgerSchemaVersion
	}
	if l.Units == nil {
		l.Units = []Unit{}
	}
	l.Limitations = nonNil(l.Limitations)
	if l.Critique != nil {
		l.Critique.Normalize()
	}
	sort.SliceStable(l.Units, func(i, j int) bool {
		return l.Units[i].CoverageID < l.Units[j].CoverageID
	})
	l.Summary = Summary{UnitsTotal: len(l.Units)}
	for i := range l.Units {
		u := &l.Units[i]
		u.ReviewedPaths = nonNil(u.ReviewedPaths)
		u.Candidates = nonNil(u.Candidates)
		u.Unresolved = nonNil(u.Unresolved)
		u.Attempts = nonNil(u.Attempts)
		if u.Checks == nil {
			u.Checks = []Check{}
		}
		sort.SliceStable(u.ReviewedPaths, func(a, b int) bool { return u.ReviewedPaths[a] < u.ReviewedPaths[b] })
		sort.Strings(u.Candidates)
		switch u.State {
		case StatePlanned:
			l.Summary.Planned++
		case StateInProgress:
			l.Summary.InProgress++
		case StateCovered:
			l.Summary.Covered++
		case StateCandidate:
			l.Summary.Candidate++
		case StateBlocked:
			l.Summary.Blocked++
		case StateDeferred:
			l.Summary.Deferred++
		case StateOutOfScope:
			l.Summary.OutOfScope++
		}
	}
}

// UnitByID devuelve la unidad con ese coverage_id.
func (l *Ledger) UnitByID(id string) *Unit {
	for i := range l.Units {
		if l.Units[i].CoverageID == id {
			return &l.Units[i]
		}
	}
	return nil
}

func nonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// JSON serializa el ledger de forma estable.
func (l *Ledger) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
