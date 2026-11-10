package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

// Versiones de los documentos internos del protocolo.
const (
	SubmissionSchemaVersion = "audit-submission-1.0.0"
	CandidatesSchemaVersion = "audit-candidates-1.0.0"
	TaskSchemaVersion       = "audit-task-1.0.0"
	OutcomeSchemaVersion    = "audit-submit-1.0.0"
)

// Errores del broker.
var (
	// ErrNoTask indica que no queda trabajo que repartir.
	ErrNoTask = errors.New("auditoría: no hay trabajo pendiente")
	// ErrBudgetExhausted indica que el presupuesto impide asignar más trabajo.
	ErrBudgetExhausted = errors.New("auditoría: presupuesto de invocaciones agotado")
	// ErrAgentIneligible indica que el agente no puede recibir la tarea pendiente.
	ErrAgentIneligible = errors.New("auditoría: el agente no es elegible para la tarea pendiente")
)

// Estados internos de un candidato.
const (
	CandidatePending    = "pending"
	CandidateEscalation = "escalation"
	CandidateDecided    = "decided"
	CandidateDropped    = "dropped"
	// CandidateReviewPending espera la revisión independiente del registro
	// final: la segunda pasada de los perfiles con dos verificaciones.
	CandidateReviewPending = "review_pending"
)

// Tipos de tarea de verificación y revisión.
const (
	ModeVerify          = "verify"
	ModeEscalationCheck = "escalation_check"
	ModeFinalReview     = "final_review"
)

// Decisiones de una revisión de escalación o de la revisión final: verified
// sostiene el registro; replace lo sustituye por el propio del revisor.
const (
	EscalationVerified = "verified"
	EscalationReplace  = "replace"
)

// Disposiciones que un cazador puede devolver por unidad.
const (
	DispositionCovered   = "covered"
	DispositionCandidate = "candidate"
	DispositionBlocked   = "blocked"
)

// VerdictRank ordena los veredictos por fuerza. Un rechazo nunca escala.
func VerdictRank(verdict string) int {
	switch verdict {
	case VerdictRejected:
		return 0
	case VerdictNeedsValidation:
		return 1
	case VerdictConfirmed:
		return 2
	default:
		return -1
	}
}

// Candidate es un hallazgo propuesto que espera verificación independiente.
type Candidate struct {
	Fingerprint string `json:"fingerprint"`
	Unit        string `json:"unit"`
	HunterAgent string `json:"hunter_agent"`
	Proposed    Record `json:"proposed"`
	State       string `json:"state"`
	AssignedTo  string `json:"assigned_to,omitempty"`
	// Escalated es el registro que propuso un verificador y que necesita un
	// segundo verificador independiente antes de aplicarse.
	Escalated *Record               `json:"escalated,omitempty"`
	Attempts  []VerificationAttempt `json:"attempts"`
	Final     *Record               `json:"final,omitempty"`
	// SourceHashes registra, por archivo citado, el hash de la fuente en el
	// momento en que se creó el registro presentable. Las claves tienen la
	// forma "<role>:<file>" con role escalated o final.
	SourceHashes map[string]string `json:"source_hashes,omitempty"`
}

// VerificationAttempt archiva una decisión de verificación.
type VerificationAttempt struct {
	AgentID  string  `json:"agent_id"`
	Mode     string  `json:"mode"`
	Decision string  `json:"decision"`
	Record   *Record `json:"record,omitempty"`
}

// Candidates es el estado de verificación de una corrida. No es un contrato
// público: vive junto al ledger en el directorio de la auditoría.
type Candidates struct {
	SchemaVersion string      `json:"schema_version"`
	RunID         string      `json:"run_id"`
	Items         []Candidate `json:"items"`
}

// Normalize ordena y completa el documento.
func (c *Candidates) Normalize() {
	if c.SchemaVersion == "" {
		c.SchemaVersion = CandidatesSchemaVersion
	}
	if c.Items == nil {
		c.Items = []Candidate{}
	}
	for i := range c.Items {
		if c.Items[i].Attempts == nil {
			c.Items[i].Attempts = []VerificationAttempt{}
		}
	}
	sort.SliceStable(c.Items, func(i, j int) bool {
		return c.Items[i].Fingerprint < c.Items[j].Fingerprint
	})
}

// CandidateByFingerprint devuelve el candidato o nil.
func (c *Candidates) CandidateByFingerprint(fp string) *Candidate {
	for i := range c.Items {
		if c.Items[i].Fingerprint == fp {
			return &c.Items[i]
		}
	}
	return nil
}

// MaterialChange compara dos registros y informa si el paso altera la
// sustancia del hallazgo: veredicto, causa raíz, traza, ejecución, impacto o
// severidad. Un cambio que solo toca la redacción editorial (título,
// descripción, confianza, condiciones) no es material.
func MaterialChange(a, b *Record) bool {
	if a == nil || b == nil {
		return a != b
	}
	if a.Verdict != b.Verdict {
		return true
	}
	if a.RootCause != b.RootCause || a.ClaimedRootCause != b.ClaimedRootCause {
		return true
	}
	if !sameTrace(a.Trace, b.Trace) {
		return true
	}
	if !sameExecution(a.Execution, b.Execution) {
		return true
	}
	if !sameSeverity(a.Severity, b.Severity) {
		return true
	}
	return false
}

// sameTrace compara trazas paso a paso: el orden y las líneas importan.
func sameTrace(a, b []TraceStep) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameExecution(a, b *Execution) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.AttackerPerspective != b.AttackerPerspective || a.ObservedResult != b.ObservedResult {
		return false
	}
	if !sameStrings(a.Payloads, b.Payloads) || !sameStrings(a.Instructions, b.Instructions) {
		return false
	}
	return true
}

func sameSeverity(a, b *Severity) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Likelihood.Score == b.Likelihood.Score && a.Impact.Score == b.Impact.Score &&
		a.Impact.Reason == b.Impact.Reason && a.Overall == b.Overall
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ValidateCandidates comprueba que el estado de verificación sea coherente
// consigo mismo y con el ledger de la corrida. Es la validación que el esquema
// no puede expresar: identificadores canónicos, independencia entre cazador y
// verificadores, ramas de escalated y final permitidas por estado,
// fingerprints coincidentes y referencias que existen en ambas direcciones.
// Cada error identifica al candidato y a la invariante incumplida.
func ValidateCandidates(c *Candidates, l *Ledger) error {
	if c == nil || l == nil {
		return errors.New("auditoría: candidatos y ledger son obligatorios")
	}
	var is Issues
	if c.SchemaVersion != CandidatesSchemaVersion {
		is.addf("schema_version %q, se esperaba %q", c.SchemaVersion, CandidatesSchemaVersion)
	}
	if c.RunID != l.Run.ID {
		is.addf("run_id %q no corresponde a la corrida %q", c.RunID, l.Run.ID)
	}
	known := map[string]bool{}
	for i := range c.Items {
		cand := &c.Items[i]
		where := fmt.Sprintf("candidato %q", cand.Fingerprint)
		if !fingerprintPattern.MatchString(cand.Fingerprint) {
			is.addf("%s: fingerprint no cumple el patrón canónico", where)
		} else if known[cand.Fingerprint] {
			is.addf("fingerprint duplicado en verificación: %s", cand.Fingerprint)
		}
		known[cand.Fingerprint] = true
		validateCandidate(l, cand, where, &is)
	}
	for _, u := range l.Units {
		for _, fp := range u.Candidates {
			if !known[fp] {
				is.addf("unidad %s: declara el fingerprint %s sin candidato en verificación", u.CoverageID, fp)
			}
		}
	}
	return is.err()
}

// validateCandidate aplica las invariantes de un candidato contra el ledger.
func validateCandidate(l *Ledger, cand *Candidate, where string, is *Issues) {
	if unit := l.UnitByID(cand.Unit); unit == nil {
		is.addf("%s: apunta a la unidad inexistente %q", where, cand.Unit)
	} else if !slices.Contains(unit.Candidates, cand.Fingerprint) {
		is.addf("%s: la unidad %s no lo declara en candidate_fingerprints", where, cand.Unit)
	}
	if !ValidAgentID(cand.HunterAgent) {
		is.addf("%s: hunter_agent inválido: %q", where, cand.HunterAgent)
	}
	if cand.Proposed.Fingerprint != cand.Fingerprint {
		is.addf("%s: proposed lleva el fingerprint %q", where, cand.Proposed.Fingerprint)
	}
	switch cand.Proposed.Verdict {
	case VerdictConfirmed, VerdictNeedsValidation:
	default:
		is.addf("%s: proposed tiene el veredicto %q; un cazador solo propone confirmed o needs_validation",
			where, cand.Proposed.Verdict)
	}
	if err := validateRecord(cand.Proposed); err != nil {
		is.addf("%v", err)
	}

	seen := map[string]bool{}
	for i, a := range cand.Attempts {
		validateCandidateAttempt(cand, a, fmt.Sprintf("%s attempt[%d]", where, i), seen, is)
	}
	if cand.AssignedTo != "" {
		if !ValidAgentID(cand.AssignedTo) {
			is.addf("%s: assigned_to inválido: %q", where, cand.AssignedTo)
		}
		if cand.AssignedTo == cand.HunterAgent {
			is.addf("%s: el cazador %q no puede ser su propio verificador", where, cand.AssignedTo)
		}
		if seen[cand.AssignedTo] {
			is.addf("%s: assigned_to %q ya intervino; se pierde la independencia", where, cand.AssignedTo)
		}
	}

	switch cand.State {
	case CandidatePending:
		if len(cand.Attempts) > 0 {
			is.addf("%s: pending no puede tener intentos archivados", where)
		}
		if cand.Escalated != nil {
			is.addf("%s: pending no puede llevar registro escalado", where)
		}
		if cand.Final != nil {
			is.addf("%s: pending no puede llevar registro final", where)
		}
	case CandidateEscalation:
		if cand.Escalated == nil {
			is.addf("%s: escalation requiere escalated", where)
		} else {
			validateEscalatedRecord(cand, where, is)
			if len(cand.Attempts) != 1 || cand.Attempts[0].Mode != ModeVerify ||
				!SameRecord(cand.Attempts[0].Record, cand.Escalated) {
				is.addf("%s: escalation exige exactamente la verificación que produjo el registro escalado", where)
			}
		}
		if cand.Final != nil {
			is.addf("%s: escalation no puede llevar registro final", where)
		}
	case CandidateDecided:
		if cand.AssignedTo != "" {
			is.addf("%s: decided no puede tener verificador asignado", where)
		}
		if cand.Escalated != nil {
			validateEscalatedRecord(cand, where, is)
		}
		if cand.Final == nil {
			is.addf("%s: decided exige final", where)
		} else if err := validateRecord(*cand.Final); err != nil {
			is.addf("%v", err)
		}
		validateDecidedBranch(cand, where, is)
	case CandidateDropped:
		if cand.Escalated != nil || cand.Final != nil {
			is.addf("%s: dropped no puede llevar registro escalado ni final", where)
		}
		if cand.AssignedTo != "" {
			is.addf("%s: dropped no puede tener verificador asignado", where)
		}
	case CandidateReviewPending:
		if cand.Final == nil {
			is.addf("%s: review_pending exige el registro final", where)
		} else if err := validateRecord(*cand.Final); err != nil {
			is.addf("%v", err)
		}
		if len(cand.Attempts) == 0 {
			is.addf("%s: review_pending exige el intento que produjo el final", where)
		}
	default:
		is.addf("%s: estado desconocido: %q", where, cand.State)
	}
}

// validateCandidateAttempt comprueba cada intento archivado: agente canónico,
// independiente del cazador y de los demás, y una decisión coherente con su
// modo y su registro.
func validateCandidateAttempt(cand *Candidate, a VerificationAttempt, at string, seen map[string]bool, is *Issues) {
	if !ValidAgentID(a.AgentID) {
		is.addf("%s: agent_id inválido: %q", at, a.AgentID)
	}
	if a.AgentID == cand.HunterAgent {
		is.addf("%s: el cazador %q no puede verificar su propio candidato", at, a.AgentID)
	}
	if seen[a.AgentID] {
		is.addf("%s: el agente %q interviene más de una vez; se pierde la independencia", at, a.AgentID)
	}
	seen[a.AgentID] = true
	switch a.Mode {
	case ModeVerify:
		switch a.Decision {
		case VerdictConfirmed, VerdictNeedsValidation, VerdictRejected:
		default:
			is.addf("%s: decisión desconocida %q en verificación", at, a.Decision)
		}
		if a.Record == nil {
			is.addf("%s: una verificación requiere record", at)
			return
		}
		if a.Record.Verdict != a.Decision {
			is.addf("%s: la decisión %q no coincide con el veredicto %q", at, a.Decision, a.Record.Verdict)
		}
		if a.Record.Fingerprint != cand.Fingerprint {
			is.addf("%s: el registro verifica %q", at, a.Record.Fingerprint)
		}
		if err := validateRecord(*a.Record); err != nil {
			is.addf("%v", err)
		}
	case ModeEscalationCheck:
		switch a.Decision {
		case EscalationVerified:
			if a.Record != nil {
				is.addf("%s: verified no lleva record", at)
			}
		case EscalationReplace:
			if a.Record == nil {
				is.addf("%s: replace requiere record", at)
				return
			}
			if a.Record.Fingerprint != cand.Fingerprint {
				is.addf("%s: el registro verifica %q", at, a.Record.Fingerprint)
			}
			if err := validateRecord(*a.Record); err != nil {
				is.addf("%v", err)
			}
		default:
			is.addf("%s: decisión desconocida %q en revisión de escalación", at, a.Decision)
		}
	case ModeFinalReview:
		switch a.Decision {
		case EscalationVerified:
			if a.Record != nil {
				is.addf("%s: verified no lleva record", at)
			}
		case EscalationReplace:
			if a.Record == nil {
				is.addf("%s: replace requiere record", at)
				return
			}
			if a.Record.Fingerprint != cand.Fingerprint {
				is.addf("%s: el registro verifica %q", at, a.Record.Fingerprint)
			}
			if err := validateRecord(*a.Record); err != nil {
				is.addf("%v", err)
			}
		default:
			is.addf("%s: decisión desconocida %q en revisión final", at, a.Decision)
		}
	default:
		is.addf("%s: modo desconocido: %q", at, a.Mode)
	}
}

// validateEscalatedRecord comprueba el registro escalado: mismo fingerprint,
// contrato válido y un veredicto que de verdad supera al propuesto.
func validateEscalatedRecord(cand *Candidate, where string, is *Issues) {
	if cand.Escalated.Fingerprint != cand.Fingerprint {
		is.addf("%s: escalated lleva el fingerprint %q", where, cand.Escalated.Fingerprint)
	}
	if err := validateRecord(*cand.Escalated); err != nil {
		is.addf("%v", err)
	}
	if VerdictRank(cand.Escalated.Verdict) <= VerdictRank(cand.Proposed.Verdict) {
		is.addf("%s: el registro escalado no supera al propuesto; no había motivo de escalación", where)
	}
}

// validateDecidedBranch exige que el registro final sea exactamente el que
// produjo el último intento de verificación o revisión de escalación; los
// intentos de revisión final que lo anteceden lo aprueban o lo reemplazan
// editorialmente.
func validateDecidedBranch(cand *Candidate, where string, is *Issues) {
	if cand.Final == nil {
		return
	}
	if len(cand.Attempts) == 0 {
		is.addf("%s: decided sin intentos archivados; el final no tiene origen", where)
		return
	}
	producedBy := len(cand.Attempts) - 1
	if last := cand.Attempts[producedBy]; last.Mode == ModeFinalReview {
		switch last.Decision {
		case EscalationReplace:
			if !SameRecord(last.Record, cand.Final) {
				is.addf("%s: el final no coincide con el reemplazo editorial aprobado", where)
			}
			return
		case EscalationVerified:
			producedBy--
		default:
			is.addf("%s: revisión final con decisión desconocida: %q", where, last.Decision)
			return
		}
	}
	if producedBy < 0 {
		is.addf("%s: el final no tiene intento que lo produzca", where)
		return
	}
	producer := cand.Attempts[producedBy]
	switch producer.Mode {
	case ModeVerify:
		if !SameRecord(producer.Record, cand.Final) {
			is.addf("%s: el final no coincide con la verificación archivada", where)
			return
		}
		if cand.Escalated == nil && VerdictRank(cand.Final.Verdict) > VerdictRank(cand.Proposed.Verdict) {
			is.addf("%s: el final supera al propuesto sin escalación; debió escalar", where)
		}
	case ModeEscalationCheck:
		switch producer.Decision {
		case EscalationVerified:
			if !SameRecord(cand.Escalated, cand.Final) {
				is.addf("%s: verified debe confirmar el registro escalado como final", where)
			}
		case EscalationReplace:
			if !SameRecord(producer.Record, cand.Final) {
				is.addf("%s: el final no coincide con el reemplazo archivado", where)
			}
			if cand.Escalated != nil && VerdictRank(cand.Final.Verdict) > VerdictRank(cand.Escalated.Verdict) {
				is.addf("%s: el reemplazo supera al escalado; debió reescalar en lugar de decidir", where)
			}
		default:
			is.addf("%s: revisión de escalación con decisión desconocida: %q", where, producer.Decision)
		}
	default:
		is.addf("%s: el final lo produce un intento de modo desconocido: %q", where, producer.Mode)
	}
}

// SameRecord compara dos registros por su serialización canónica: el broker
// copia el registro tal cual, así que la forma emitida debe coincidir.
func SameRecord(a, b *Record) bool {
	if a == nil || b == nil {
		return a == b
	}
	ja, err := json.Marshal(a)
	if err != nil {
		return false
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ja, jb)
}

// UnitResult es el resultado que un cazador devuelve para una unidad.
type UnitResult struct {
	CoverageID            string   `json:"coverage_id"`
	Disposition           string   `json:"disposition"`
	ReviewedPaths         []string `json:"reviewed_paths"`
	Checks                []Check  `json:"checks"`
	CandidateFingerprints []string `json:"candidate_fingerprints"`
	Unresolved            []string `json:"unresolved"`
	Hardening             []string `json:"hardening"`
}

// Uncovered declara una superficie que merece su propia unidad y que el
// cazador encontró fuera de su asignación.
type Uncovered struct {
	Surface       string   `json:"surface"`
	Domain        string   `json:"domain"`
	Boundary      string   `json:"boundary"`
	Subsystem     string   `json:"subsystem"`
	AttackClass   string   `json:"attack_class"`
	StartingPaths []string `json:"starting_paths"`
	Reason        string   `json:"reason"`
}

// Verification es la respuesta de un verificador independiente.
type Verification struct {
	Fingerprint string  `json:"fingerprint"`
	Decision    string  `json:"decision"`
	Record      *Record `json:"record,omitempty"`
}

// Submission es lo que un agente entrega al motor.
type Submission struct {
	SchemaVersion string        `json:"schema_version"`
	AgentID       string        `json:"agent_id"`
	Units         []UnitResult  `json:"units,omitempty"`
	Candidates    []Record      `json:"candidates,omitempty"`
	Verification  *Verification `json:"verification,omitempty"`
	Hardening     []string      `json:"hardening,omitempty"`
	Uncovered     []Uncovered   `json:"uncovered,omitempty"`
}

// decodeStrict decodifica un único objeto JSON en v rechazando campos
// desconocidos y exigiendo que después del objeto solo quede espacio en
// blanco: un segundo objeto o basura residual invalida el documento.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("hay contenido adicional después del objeto JSON")
	}
	return nil
}

// DecodeSubmission lee y decodifica una entrega, rechazando campos
// desconocidos y contenido posterior al objeto.
func DecodeSubmission(data []byte) (*Submission, error) {
	if err := checkSize(data, MaxSubmissionBytes, "la entrega"); err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, errors.New("la entrega no es JSON válido")
	}
	if err := checkJSONDepth(data, MaxJSONDepth); err != nil {
		return nil, fmt.Errorf("entrega inválida: %w", err)
	}
	var s Submission
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("entrega inválida: %w", err)
	}
	if s.SchemaVersion != SubmissionSchemaVersion {
		return nil, fmt.Errorf("entrega con schema_version %q, se esperaba %q", s.SchemaVersion, SubmissionSchemaVersion)
	}
	for i := range s.Candidates {
		switch s.Candidates[i].Verdict {
		case VerdictConfirmed, VerdictNeedsValidation, VerdictRejected:
		default:
			return nil, fmt.Errorf("entrega inválida: el candidato %d declara el veredicto desconocido %q",
				i, s.Candidates[i].Verdict)
		}
	}
	if s.Verification != nil && s.Verification.Record != nil {
		switch s.Verification.Record.Verdict {
		case VerdictConfirmed, VerdictNeedsValidation, VerdictRejected:
		default:
			return nil, fmt.Errorf("entrega inválida: la verificación declara el veredicto desconocido %q",
				s.Verification.Record.Verdict)
		}
	}
	return &s, nil
}

// DecodeCandidates lee y decodifica el estado de verificación, rechazando
// campos desconocidos y contenido posterior al objeto. No valida la coherencia
// con el ledger: para eso está ValidateCandidates.
func DecodeCandidates(data []byte) (*Candidates, error) {
	if err := checkSize(data, MaxCandidatesBytes, "el estado de verificación"); err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, errors.New("el estado de verificación no es JSON válido")
	}
	if err := checkJSONDepth(data, MaxJSONDepth); err != nil {
		return nil, fmt.Errorf("estado de verificación inválido: %w", err)
	}
	var c Candidates
	if err := decodeStrict(data, &c); err != nil {
		return nil, fmt.Errorf("estado de verificación inválido: %w", err)
	}
	if c.SchemaVersion != CandidatesSchemaVersion {
		return nil, fmt.Errorf("estado de verificación con esquema %q, se esperaba %q", c.SchemaVersion, CandidatesSchemaVersion)
	}
	for i := range c.Items {
		cand := &c.Items[i]
		where := fmt.Sprintf("candidato %q", cand.Fingerprint)
		for _, r := range []*Record{&cand.Proposed, cand.Escalated, cand.Final} {
			if r == nil {
				continue
			}
			switch r.Verdict {
			case VerdictConfirmed, VerdictNeedsValidation, VerdictRejected:
			default:
				return nil, fmt.Errorf("estado de verificación inválido: %s con veredicto desconocido %q", where, r.Verdict)
			}
		}
		for j, a := range cand.Attempts {
			if a.Record == nil {
				continue
			}
			switch a.Record.Verdict {
			case VerdictConfirmed, VerdictNeedsValidation, VerdictRejected:
			default:
				return nil, fmt.Errorf("estado de verificación inválido: %s attempt[%d] con veredicto desconocido %q",
					where, j, a.Record.Verdict)
			}
		}
	}
	c.Normalize()
	return &c, nil
}

// AssignmentUnit describe una unidad asignada con su clase.
type AssignmentUnit struct {
	Unit  Unit  `json:"unit"`
	Class Class `json:"class"`
}

// AssignmentCandidate describe el candidato que un verificador debe revisar.
type AssignmentCandidate struct {
	Fingerprint string  `json:"fingerprint"`
	Unit        string  `json:"unit"`
	Proposed    Record  `json:"proposed"`
	Escalated   *Record `json:"escalated,omitempty"`
	// Final es el registro que una revisión final debe aprobar o reemplazar.
	Final *Record `json:"final,omitempty"`
}

// Task es la asignación que el motor entrega al agente.
type Task struct {
	SchemaVersion string               `json:"schema_version"`
	Kind          string               `json:"kind"`
	RunID         string               `json:"run_id"`
	AgentID       string               `json:"agent_id"`
	Budget        *Budget              `json:"budget"`
	Units         []AssignmentUnit     `json:"units,omitempty"`
	Candidate     *AssignmentCandidate `json:"candidate,omitempty"`
}

// JSON serializa la asignación.
func (t *Task) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// NextOptions configura el reparto.
type NextOptions struct {
	AgentID  string
	Catalog  *Catalog
	MaxUnits int
}

// Next entrega la siguiente asignación. La verificación pendiente tiene
// prioridad sobre la caza; una escalación tiene prioridad sobre una
// verificación normal.
func Next(l *Ledger, c *Candidates, opts NextOptions) (*Task, error) {
	if l == nil || c == nil {
		return nil, errors.New("auditoría: ledger y candidatos son obligatorios")
	}
	if !ValidAgentID(opts.AgentID) {
		return nil, fmt.Errorf("auditoría: agent_id inválido: %q", opts.AgentID)
	}
	if l.RunStatus != StatusInProgress {
		return nil, ErrNoTask
	}

	if cand, fresh := pickVerification(c, opts.AgentID, CandidateEscalation); cand != nil {
		return issueVerification(l, cand, opts.AgentID, fresh, ModeEscalationCheck)
	}
	if cand, fresh := pickVerification(c, opts.AgentID, CandidatePending); cand != nil {
		return issueVerification(l, cand, opts.AgentID, fresh, ModeVerify)
	}
	if cand, fresh := pickVerification(c, opts.AgentID, CandidateReviewPending); cand != nil {
		return issueReview(l, cand, opts.AgentID, fresh)
	}
	if hasVerificationWork(c) {
		return nil, ErrAgentIneligible
	}

	if task := existingAssignment(l, opts.AgentID, opts.Catalog); task != nil {
		return task, nil
	}

	planned := plannedUnits(l)
	if len(planned) == 0 {
		return nil, ErrNoTask
	}
	if l.Budget != nil && l.Budget.Used >= l.Budget.MaxAgentInvocations {
		deferRemaining(l, planned, "budget_exhausted")
		return nil, ErrBudgetExhausted
	}

	limit := opts.MaxUnits
	if limit <= 0 {
		limit = 1
		if opts.Catalog != nil {
			limit = opts.Catalog.Limits.MaxUnitsPerAssignment
		}
	}
	sortUnitsByPriority(planned, opts.Catalog)
	subsystem := planned[0].Subsystem
	selected := make([]*Unit, 0, limit)
	for _, u := range planned {
		if len(selected) >= limit {
			break
		}
		if u.Subsystem != subsystem {
			continue
		}
		u.Wave++
		u.State = StateInProgress
		u.Owner = opts.AgentID
		selected = append(selected, u)
	}
	if len(selected) == 0 {
		return nil, ErrNoTask
	}
	if l.Budget != nil {
		l.Budget.Used++
	}
	l.Recompute()

	task := &Task{
		SchemaVersion: TaskSchemaVersion,
		Kind:          "hunt",
		RunID:         l.Run.ID,
		AgentID:       opts.AgentID,
		Budget:        l.Budget,
		Units:         make([]AssignmentUnit, 0, len(selected)),
	}
	for _, u := range selected {
		class := Class{ID: u.AttackClass, Domain: u.Domain, Boundary: u.Boundary}
		if opts.Catalog != nil {
			if found := opts.Catalog.ClassByID(u.AttackClass); found != nil {
				class = *found
			}
		}
		task.Units = append(task.Units, AssignmentUnit{Unit: *u, Class: class})
	}
	return task, nil
}

// existingAssignment devuelve las unidades que el agente ya tiene en curso, de
// modo que repetir `audit next` no consume presupuesto ni reasigna trabajo.
func existingAssignment(l *Ledger, agent string, catalog *Catalog) *Task {
	units := make([]*Unit, 0)
	for i := range l.Units {
		if l.Units[i].State == StateInProgress && l.Units[i].Owner == agent {
			units = append(units, &l.Units[i])
		}
	}
	if len(units) == 0 {
		return nil
	}
	sortUnitsByPriority(units, catalog)
	task := &Task{
		SchemaVersion: TaskSchemaVersion, Kind: "hunt",
		RunID: l.Run.ID, AgentID: agent, Budget: l.Budget,
		Units: make([]AssignmentUnit, 0, len(units)),
	}
	for _, u := range units {
		class := Class{ID: u.AttackClass, Domain: u.Domain, Boundary: u.Boundary}
		if catalog != nil {
			if found := catalog.ClassByID(u.AttackClass); found != nil {
				class = *found
			}
		}
		task.Units = append(task.Units, AssignmentUnit{Unit: *u, Class: class})
	}
	return task
}

func pickVerification(c *Candidates, agent, state string) (*Candidate, bool) {
	candidates := make([]*Candidate, 0)
	for i := range c.Items {
		cand := &c.Items[i]
		if cand.State != state {
			continue
		}
		if cand.AssignedTo != "" && cand.AssignedTo != agent {
			continue
		}
		if !agentEligible(cand, agent) {
			continue
		}
		candidates = append(candidates, cand)
	}
	if len(candidates) == 0 {
		return nil, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Fingerprint < candidates[j].Fingerprint
	})
	chosen := candidates[0]
	fresh := chosen.AssignedTo == ""
	chosen.AssignedTo = agent
	return chosen, fresh
}

func agentEligible(cand *Candidate, agent string) bool {
	if cand.HunterAgent == agent {
		return false
	}
	for _, a := range cand.Attempts {
		if a.AgentID == agent {
			return false
		}
	}
	return true
}

func issueVerification(l *Ledger, cand *Candidate, agent string, fresh bool, mode string) (*Task, error) {
	if fresh && l.Budget != nil {
		if l.Budget.Used >= l.Budget.MaxAgentInvocations {
			return nil, ErrBudgetExhausted
		}
		l.Budget.Used++
	}
	l.Recompute()
	task := &Task{
		SchemaVersion: TaskSchemaVersion,
		Kind:          mode,
		RunID:         l.Run.ID,
		AgentID:       agent,
		Budget:        l.Budget,
		Candidate: &AssignmentCandidate{
			Fingerprint: cand.Fingerprint,
			Unit:        cand.Unit,
			Proposed:    cand.Proposed,
			Escalated:   cand.Escalated,
		},
	}
	if mode == ModeFinalReview {
		task.Candidate.Final = cand.Final
	}
	return task, nil
}

// issueReview entrega la revisión final de un registro decidido: la segunda
// pasada de los perfiles con dos verificaciones. El revisor no puede ser el
// cazador, un validador previo ni el autor de un reemplazo.
func issueReview(l *Ledger, cand *Candidate, agent string, fresh bool) (*Task, error) {
	return issueVerification(l, cand, agent, fresh, ModeFinalReview)
}

func hasVerificationWork(c *Candidates) bool {
	for _, cand := range c.Items {
		if cand.State == CandidatePending || cand.State == CandidateEscalation || cand.State == CandidateReviewPending {
			return true
		}
	}
	return false
}

func plannedUnits(l *Ledger) []*Unit {
	out := make([]*Unit, 0)
	for i := range l.Units {
		if l.Units[i].State == StatePlanned {
			out = append(out, &l.Units[i])
		}
	}
	return out
}

func sortUnitsByPriority(units []*Unit, catalog *Catalog) {
	priority := func(u *Unit) int {
		if catalog != nil {
			if class := catalog.ClassByID(u.AttackClass); class != nil {
				return class.Priority
			}
		}
		return 1 << 20
	}
	sort.SliceStable(units, func(i, j int) bool {
		pi, pj := priority(units[i]), priority(units[j])
		if pi != pj {
			return pi < pj
		}
		return units[i].CoverageID < units[j].CoverageID
	})
}

func deferRemaining(l *Ledger, units []*Unit, reason string) {
	for _, u := range units {
		u.State = StateDeferred
		u.Reason = reason
		u.Owner = ""
	}
	l.RunStatus = StatusIncomplete
	l.IncompleteReason = reason
	l.Recompute()
}

// ResetUnit devuelve una unidad abandonada a planned: cierra el intento
// vigente como blocked con la razón dada, archiva dueño, ola y checks
// realmente disponibles, y limpia la evidencia vigente. La ola aumenta en la
// siguiente asignación, no en el reinicio; el intento archivado registra la
// ola que le correspondió. Una entrega tardía del intento abandonado se
// rechaza por el estado y el dueño nuevos.
func ResetUnit(l *Ledger, coverageID, reason string) error {
	if l == nil {
		return errors.New("auditoría: ledger obligatorio")
	}
	if l.RunStatus != StatusInProgress {
		return fmt.Errorf("auditoría: la corrida está %s y no acepta reinicios de unidad", l.RunStatus)
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("auditoría: el reinicio exige una razón no vacía")
	}
	unit := l.UnitByID(coverageID)
	if unit == nil {
		return fmt.Errorf("auditoría: coverage_id desconocido: %s", coverageID)
	}
	if unit.State != StateInProgress {
		return fmt.Errorf("auditoría: la unidad %s está %s; solo in_progress puede reiniciarse", coverageID, unit.State)
	}
	unit.Attempts = append(unit.Attempts, Attempt{
		Wave:          unit.Wave,
		AgentID:       unit.Owner,
		State:         StateBlocked,
		ReviewedPaths: []string{},
		Checks:        []Check{},
		Candidates:    []string{},
		Unresolved:    []string{},
		Reason:        reason,
	})
	unit.State = StatePlanned
	unit.Owner = ""
	unit.ReviewedPaths = []string{}
	unit.Checks = []Check{}
	unit.Candidates = []string{}
	unit.Unresolved = []string{}
	unit.Hardening = nil
	unit.Reason = ""
	l.Recompute()
	return nil
}

// SubmitOutcome resume lo que aplicó una entrega.
type SubmitOutcome struct {
	SchemaVersion string   `json:"schema_version"`
	AppliedUnits  int      `json:"applied_units"`
	Decided       int      `json:"decided"`
	Pending       int      `json:"pending"`
	Escalations   int      `json:"escalations"`
	AddedUnits    []string `json:"added_units"`
	Notes         []string `json:"notes"`
}

// SubmitOptions configura una entrega.
type SubmitOptions struct {
	// Source, si no es nil, sella la fuente de cada registro presentable que
	// la entrega crea. Se invoca durante la fase de validación: un fallo
	// aborta la entrega sin mutar ledger ni candidatos. Los roles posibles
	// son escalated y final; el cazador no sella su propuesta.
	Source SourceStamper
	// Policy, si no es nil, define el número de pasadas de verificación; nil
	// resuelve la política del perfil desde el catálogo embebido.
	Policy *ProfilePolicy
}

// Submit aplica una entrega de forma atómica: si algo no cumple el contrato,
// no se modifica ni el ledger ni los candidatos.
func Submit(l *Ledger, c *Candidates, sub *Submission) (*SubmitOutcome, error) {
	return SubmitWithOptions(l, c, sub, SubmitOptions{})
}

// SubmitWithOptions aplica una entrega con sellado de fuente opcional.
func SubmitWithOptions(l *Ledger, c *Candidates, sub *Submission, opts SubmitOptions) (*SubmitOutcome, error) {
	if l == nil || c == nil || sub == nil {
		return nil, errors.New("auditoría: ledger, candidatos y entrega son obligatorios")
	}
	if l.RunStatus != StatusInProgress {
		return nil, fmt.Errorf("auditoría: la corrida está %s y no acepta entregas", l.RunStatus)
	}
	if !ValidAgentID(sub.AgentID) {
		return nil, fmt.Errorf("auditoría: agent_id inválido: %q", sub.AgentID)
	}
	pol := opts.Policy
	if pol == nil {
		var err error
		pol, err = profilePolicyFor(l.Profile)
		if err != nil {
			return nil, err
		}
	}
	if sub.Verification != nil {
		return submitVerification(l, c, sub, opts, pol)
	}
	return submitHunt(l, c, sub)
}

func submitHunt(l *Ledger, c *Candidates, sub *Submission) (*SubmitOutcome, error) {
	if len(sub.Units) == 0 && len(sub.Uncovered) == 0 {
		return nil, errors.New("auditoría: la entrega no trae unidades ni superficies no cubiertas")
	}
	records := map[string]Record{}
	for _, r := range sub.Candidates {
		if r.Verdict != VerdictConfirmed && r.Verdict != VerdictNeedsValidation {
			return nil, fmt.Errorf("auditoría: el cazador solo puede proponer confirmed o needs_validation, no %q", r.Verdict)
		}
		if _, dup := records[r.Fingerprint]; dup {
			return nil, fmt.Errorf("auditoría: fingerprint duplicado en la entrega: %s", r.Fingerprint)
		}
		if err := validateRecord(r); err != nil {
			return nil, err
		}
		records[r.Fingerprint] = r
	}

	used := map[string]bool{}
	submittedUnits := map[string]bool{}
	for _, res := range sub.Units {
		if submittedUnits[res.CoverageID] {
			return nil, fmt.Errorf("auditoría: la unidad %s aparece más de una vez en la entrega", res.CoverageID)
		}
		submittedUnits[res.CoverageID] = true
		unit := l.UnitByID(res.CoverageID)
		if unit == nil {
			return nil, fmt.Errorf("auditoría: coverage_id desconocido: %s", res.CoverageID)
		}
		if unit.State != StateInProgress {
			return nil, fmt.Errorf("auditoría: la unidad %s está %s, no in_progress", res.CoverageID, unit.State)
		}
		if unit.Owner != sub.AgentID {
			return nil, fmt.Errorf("auditoría: la unidad %s pertenece a %q, no a %q", res.CoverageID, unit.Owner, sub.AgentID)
		}
		switch res.Disposition {
		case DispositionCovered:
			if len(res.ReviewedPaths) == 0 || len(res.Checks) == 0 ||
				len(res.CandidateFingerprints) > 0 || len(res.Unresolved) > 0 {
				return nil, fmt.Errorf("auditoría: %s covered exige reviewed_paths y checks, sin candidatos ni pendientes", res.CoverageID)
			}
		case DispositionCandidate:
			if len(res.ReviewedPaths) == 0 || len(res.Checks) == 0 || len(res.CandidateFingerprints) == 0 {
				return nil, fmt.Errorf("auditoría: %s candidate exige reviewed_paths, checks y fingerprints", res.CoverageID)
			}
		case DispositionBlocked:
			if len(res.ReviewedPaths) == 0 || len(res.Checks) == 0 ||
				len(res.Unresolved) == 0 || len(res.CandidateFingerprints) > 0 {
				return nil, fmt.Errorf("auditoría: %s blocked exige reviewed_paths, checks y unresolved, sin fingerprints", res.CoverageID)
			}
		default:
			return nil, fmt.Errorf("auditoría: disposición desconocida %q", res.Disposition)
		}
		for _, fp := range res.CandidateFingerprints {
			if _, ok := records[fp]; !ok {
				return nil, fmt.Errorf("auditoría: la unidad %s declara %s sin registro de candidato", res.CoverageID, fp)
			}
			if used[fp] {
				return nil, fmt.Errorf("auditoría: el fingerprint %s está declarado en más de una unidad", fp)
			}
			used[fp] = true
			if existing := c.CandidateByFingerprint(fp); existing != nil {
				return nil, fmt.Errorf("auditoría: el fingerprint %s ya está en verificación", fp)
			}
		}
	}
	for fp := range records {
		if !used[fp] {
			return nil, fmt.Errorf("auditoría: el candidato %s no está vinculado a ninguna unidad", fp)
		}
	}
	for _, u := range l.Units {
		if u.State == StateInProgress && u.Owner == sub.AgentID && !submittedUnits[u.CoverageID] {
			return nil, fmt.Errorf("auditoría: falta la unidad asignada %s en la entrega", u.CoverageID)
		}
	}

	// Superficies no cubiertas: se convierten en unidades planificadas.
	added := make([]Unit, 0, len(sub.Uncovered))
	seenIDs := map[string]bool{}
	for _, u := range l.Units {
		seenIDs[u.CoverageID] = true
	}
	for _, u := range sub.Uncovered {
		if strings.TrimSpace(u.Subsystem) == "" || strings.TrimSpace(u.Domain) == "" ||
			strings.TrimSpace(u.Boundary) == "" || strings.TrimSpace(u.AttackClass) == "" ||
			strings.TrimSpace(u.Reason) == "" || len(u.StartingPaths) == 0 {
			return nil, errors.New("auditoría: una superficie no cubierta exige subsistema, dominio, frontera, clase, rutas y razón")
		}
		if !classIDPattern.MatchString(u.AttackClass) {
			return nil, fmt.Errorf("auditoría: clase inválida en superficie no cubierta: %q", u.AttackClass)
		}
		for _, p := range u.StartingPaths {
			if !ValidRepoPath(p) {
				return nil, fmt.Errorf("auditoría: ruta inválida en superficie no cubierta: %q", p)
			}
		}
		id := slugID(u.Subsystem) + "/" + slugID(u.Domain) + "/" + u.AttackClass
		if seenIDs[id] {
			continue
		}
		seenIDs[id] = true
		added = append(added, Unit{
			CoverageID:    id,
			Subsystem:     u.Subsystem,
			Domain:        u.Domain,
			Boundary:      u.Boundary,
			AttackClass:   u.AttackClass,
			StartingPaths: u.StartingPaths,
			State:         StatePlanned,
			ReviewedPaths: []string{},
			Checks:        []Check{},
			Candidates:    []string{},
			Unresolved:    []string{},
			Attempts:      []Attempt{},
		})
	}

	// Aplicación: a partir de aquí no hay validaciones que puedan fallar.
	out := &SubmitOutcome{
		SchemaVersion: OutcomeSchemaVersion,
		AddedUnits:    make([]string, 0, len(added)),
		Notes:         []string{},
	}
	for _, res := range sub.Units {
		unit := l.UnitByID(res.CoverageID)
		unit.State = res.Disposition
		unit.ReviewedPaths = nonNil(res.ReviewedPaths)
		unit.Checks = nonNil(res.Checks)
		unit.Candidates = nonNil(res.CandidateFingerprints)
		unit.Unresolved = nonNil(res.Unresolved)
		if len(sub.Hardening) > 0 || len(res.Hardening) > 0 {
			hardening := append([]string{}, sub.Hardening...)
			hardening = append(hardening, res.Hardening...)
			unit.Hardening = hardening
		}
		out.AppliedUnits++
	}
	for _, res := range sub.Units {
		for _, fp := range res.CandidateFingerprints {
			record := records[fp]
			c.Items = append(c.Items, Candidate{
				Fingerprint: fp,
				Unit:        res.CoverageID,
				HunterAgent: sub.AgentID,
				Proposed:    record,
				State:       CandidatePending,
				Attempts:    []VerificationAttempt{},
			})
			out.Pending++
		}
	}
	for _, u := range added {
		l.Units = append(l.Units, u)
		out.AddedUnits = append(out.AddedUnits, u.CoverageID)
	}
	if len(added) > 0 {
		out.Notes = append(out.Notes, "se agregaron superficies no cubiertas como unidades planificadas")
	}
	c.Normalize()
	l.Recompute()
	return out, nil
}

func submitVerification(l *Ledger, c *Candidates, sub *Submission, opts SubmitOptions, pol *ProfilePolicy) (*SubmitOutcome, error) {
	if len(sub.Units) > 0 || len(sub.Candidates) > 0 || len(sub.Uncovered) > 0 {
		return nil, errors.New("auditoría: una verificación no puede traer unidades, candidatos ni superficies nuevas")
	}
	v := sub.Verification
	cand := c.CandidateByFingerprint(v.Fingerprint)
	if cand == nil {
		return nil, fmt.Errorf("auditoría: el fingerprint %s no está en verificación", v.Fingerprint)
	}
	if cand.State != CandidatePending && cand.State != CandidateEscalation && cand.State != CandidateReviewPending {
		return nil, fmt.Errorf("auditoría: el candidato %s está %s", v.Fingerprint, cand.State)
	}
	if cand.AssignedTo != sub.AgentID {
		return nil, fmt.Errorf("auditoría: el candidato %s está asignado a %q, no a %q", v.Fingerprint, cand.AssignedTo, sub.AgentID)
	}
	if !agentEligible(cand, sub.AgentID) {
		return nil, fmt.Errorf("auditoría: el agente %q no es independiente para verificar %s", sub.AgentID, v.Fingerprint)
	}

	out := &SubmitOutcome{SchemaVersion: OutcomeSchemaVersion, AddedUnits: []string{}, Notes: []string{}}

	switch cand.State {
	case CandidatePending:
		switch v.Decision {
		case VerdictConfirmed, VerdictNeedsValidation, VerdictRejected:
		default:
			return nil, fmt.Errorf("auditoría: decisión desconocida %q en verificación pendiente", v.Decision)
		}
		if v.Record == nil {
			return nil, errors.New("auditoría: la verificación requiere record")
		}
		if v.Record.Verdict != v.Decision {
			return nil, fmt.Errorf("auditoría: la decisión %q no coincide con el veredicto %q", v.Decision, v.Record.Verdict)
		}
		if v.Record.Fingerprint != v.Fingerprint {
			return nil, fmt.Errorf("auditoría: el registro verifica %q pero la tarea es %q", v.Record.Fingerprint, v.Fingerprint)
		}
		if err := validateRecord(*v.Record); err != nil {
			return nil, err
		}
		record := *v.Record
		// El sello de fuente se resuelve antes de cualquier mutación: si la
		// cita no se puede validar o sellar, la entrega no aplica.
		role := SourceRoleFinal
		if VerdictRank(record.Verdict) > VerdictRank(cand.Proposed.Verdict) {
			role = SourceRoleEscalated
		}
		var stamps map[string]string
		if opts.Source != nil {
			var err error
			stamps, err = opts.Source(v.Fingerprint, role, &record)
			if err != nil {
				return nil, err
			}
		}
		cand.Attempts = append(cand.Attempts, VerificationAttempt{
			AgentID: sub.AgentID, Mode: ModeVerify, Decision: v.Decision, Record: &record,
		})
		if VerdictRank(record.Verdict) > VerdictRank(cand.Proposed.Verdict) {
			cand.State = CandidateEscalation
			cand.Escalated = &record
			cand.AssignedTo = ""
			mergeSourceStamps(cand, role, stamps)
			out.Escalations++
			out.Notes = append(out.Notes, "la promoción de veredicto exige un segundo verificador independiente")
			break
		}
		if pol.VerificationPasses > 1 {
			// Segunda pasada: el registro final espera revisión independiente.
			cand.State = CandidateReviewPending
			cand.AssignedTo = ""
			mergeSourceStamps(cand, role, stamps)
			out.Pending++
			out.Notes = append(out.Notes, "el registro final exige revisión independiente (segunda pasada)")
			break
		}
		cand.State = CandidateDecided
		cand.Final = &record
		cand.AssignedTo = ""
		mergeSourceStamps(cand, role, stamps)
		out.Decided++

	case CandidateEscalation:
		switch v.Decision {
		case EscalationVerified:
			if cand.Escalated == nil {
				return nil, errors.New("auditoría: escalación sin registro que verificar")
			}
			cand.Attempts = append(cand.Attempts, VerificationAttempt{
				AgentID: sub.AgentID, Mode: ModeEscalationCheck, Decision: v.Decision,
			})
			cand.Final = cand.Escalated
			cand.AssignedTo = ""
			// El final es exactamente el registro escalado: hereda sus
			// sellos de fuente; la fuente no se relee.
			inheritSourceStamps(cand, SourceRoleEscalated, SourceRoleFinal)
			if pol.VerificationPasses > 1 {
				cand.State = CandidateReviewPending
				out.Pending++
				out.Notes = append(out.Notes, "el registro final exige revisión independiente (segunda pasada)")
				break
			}
			cand.State = CandidateDecided
			out.Decided++
		case EscalationReplace:
			if v.Record == nil {
				return nil, errors.New("auditoría: replace requiere record")
			}
			if v.Record.Fingerprint != v.Fingerprint {
				return nil, fmt.Errorf("auditoría: el reemplazo verifica %q pero la tarea es %q", v.Record.Fingerprint, v.Fingerprint)
			}
			if err := validateRecord(*v.Record); err != nil {
				return nil, err
			}
			record := *v.Record
			role := SourceRoleFinal
			if cand.Escalated != nil && VerdictRank(record.Verdict) > VerdictRank(cand.Escalated.Verdict) {
				role = SourceRoleEscalated
			}
			var stamps map[string]string
			if opts.Source != nil {
				var err error
				stamps, err = opts.Source(v.Fingerprint, role, &record)
				if err != nil {
					return nil, err
				}
			}
			cand.Attempts = append(cand.Attempts, VerificationAttempt{
				AgentID: sub.AgentID, Mode: ModeEscalationCheck, Decision: v.Decision, Record: &record,
			})
			if cand.Escalated != nil && VerdictRank(record.Verdict) > VerdictRank(cand.Escalated.Verdict) {
				cand.Escalated = &record
				cand.AssignedTo = ""
				mergeSourceStamps(cand, role, stamps)
				out.Escalations++
				out.Notes = append(out.Notes, "el reemplazo vuelve a escalar el veredicto; se exige otro verificador")
				break
			}
			cand.Final = &record
			cand.AssignedTo = ""
			mergeSourceStamps(cand, role, stamps)
			if pol.VerificationPasses > 1 {
				cand.State = CandidateReviewPending
				out.Pending++
				out.Notes = append(out.Notes, "el registro final exige revisión independiente (segunda pasada)")
				break
			}
			cand.State = CandidateDecided
			out.Decided++
		default:
			return nil, fmt.Errorf("auditoría: decisión desconocida %q en escalación", v.Decision)
		}
	case CandidateReviewPending:
		// La revisión final: el revisor aprueba el registro o lo reemplaza.
		// Un reemplazo material queda pendiente hasta su revisión
		// independiente; uno editorial se aplica sin otra firma.
		switch v.Decision {
		case EscalationVerified:
			if cand.Final == nil {
				return nil, errors.New("auditoría: revisión sin registro final que aprobar")
			}
			cand.Attempts = append(cand.Attempts, VerificationAttempt{
				AgentID: sub.AgentID, Mode: ModeFinalReview, Decision: v.Decision,
			})
			cand.State = CandidateDecided
			cand.AssignedTo = ""
			out.Decided++
		case EscalationReplace:
			if v.Record == nil {
				return nil, errors.New("auditoría: replace requiere record")
			}
			if v.Record.Fingerprint != v.Fingerprint {
				return nil, fmt.Errorf("auditoría: el reemplazo verifica %q pero la tarea es %q", v.Record.Fingerprint, v.Fingerprint)
			}
			if err := validateRecord(*v.Record); err != nil {
				return nil, err
			}
			record := *v.Record
			var stamps map[string]string
			if MaterialChange(cand.Final, &record) {
				// El reemplazo es material: queda pendiente de un verificador
				// independiente que no cazó, no validó ni lo propuso.
				if opts.Source != nil {
					var err error
					stamps, err = opts.Source(v.Fingerprint, SourceRoleEscalated, &record)
					if err != nil {
						return nil, err
					}
				}
				cand.Attempts = append(cand.Attempts, VerificationAttempt{
					AgentID: sub.AgentID, Mode: ModeFinalReview, Decision: v.Decision, Record: &record,
				})
				cand.State = CandidateEscalation
				cand.Escalated = &record
				cand.AssignedTo = ""
				mergeSourceStamps(cand, SourceRoleEscalated, stamps)
				out.Escalations++
				out.Notes = append(out.Notes, "el reemplazo es material; exige un verificador independiente")
				break
			}
			if opts.Source != nil {
				var err error
				stamps, err = opts.Source(v.Fingerprint, SourceRoleFinal, &record)
				if err != nil {
					return nil, err
				}
			}
			cand.Attempts = append(cand.Attempts, VerificationAttempt{
				AgentID: sub.AgentID, Mode: ModeFinalReview, Decision: v.Decision, Record: &record,
			})
			cand.Final = &record
			cand.State = CandidateDecided
			cand.AssignedTo = ""
			mergeSourceStamps(cand, SourceRoleFinal, stamps)
			out.Decided++
		default:
			return nil, fmt.Errorf("auditoría: decisión desconocida %q en revisión final", v.Decision)
		}
	}

	c.Normalize()
	l.Recompute()
	return out, nil
}

func validateRecord(r Record) error {
	f := &Findings{
		SchemaVersion: FindingsSchemaVersion,
		Provenance:    CallerProvenance(),
		Findings:      []Record{r},
	}
	f.Recompute()
	if err := ValidateFindingsSemantics(f); err != nil {
		return fmt.Errorf("auditoría: registro %q inválido: %w", r.Fingerprint, err)
	}
	return nil
}
