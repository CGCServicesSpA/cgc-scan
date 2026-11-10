package audit

import (
	"encoding/json"
	"errors"
	"fmt"
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
)

// Modalidades de verificación.
const (
	ModeVerify          = "verify"
	ModeEscalationCheck = "escalation_check"
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

// DecodeSubmission lee y decodifica una entrega, rechazando campos
// desconocidos.
func DecodeSubmission(data []byte) (*Submission, error) {
	if !json.Valid(data) {
		return nil, errors.New("la entrega no es JSON válido")
	}
	var s Submission
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("entrega inválida: %w", err)
	}
	if s.SchemaVersion != SubmissionSchemaVersion {
		return nil, fmt.Errorf("entrega con schema_version %q, se esperaba %q", s.SchemaVersion, SubmissionSchemaVersion)
	}
	return &s, nil
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
	return &Task{
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
	}, nil
}

func hasVerificationWork(c *Candidates) bool {
	for _, cand := range c.Items {
		if cand.State == CandidatePending || cand.State == CandidateEscalation {
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

// Submit aplica una entrega de forma atómica: si algo no cumple el contrato,
// no se modifica ni el ledger ni los candidatos.
func Submit(l *Ledger, c *Candidates, sub *Submission) (*SubmitOutcome, error) {
	if l == nil || c == nil || sub == nil {
		return nil, errors.New("auditoría: ledger, candidatos y entrega son obligatorios")
	}
	if l.RunStatus != StatusInProgress {
		return nil, fmt.Errorf("auditoría: la corrida está %s y no acepta entregas", l.RunStatus)
	}
	if !ValidAgentID(sub.AgentID) {
		return nil, fmt.Errorf("auditoría: agent_id inválido: %q", sub.AgentID)
	}

	if sub.Verification != nil {
		return submitVerification(l, c, sub)
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

func submitVerification(l *Ledger, c *Candidates, sub *Submission) (*SubmitOutcome, error) {
	if len(sub.Units) > 0 || len(sub.Candidates) > 0 || len(sub.Uncovered) > 0 {
		return nil, errors.New("auditoría: una verificación no puede traer unidades, candidatos ni superficies nuevas")
	}
	v := sub.Verification
	cand := c.CandidateByFingerprint(v.Fingerprint)
	if cand == nil {
		return nil, fmt.Errorf("auditoría: el fingerprint %s no está en verificación", v.Fingerprint)
	}
	if cand.State != CandidatePending && cand.State != CandidateEscalation {
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
		cand.Attempts = append(cand.Attempts, VerificationAttempt{
			AgentID: sub.AgentID, Mode: ModeVerify, Decision: v.Decision, Record: &record,
		})
		if VerdictRank(record.Verdict) > VerdictRank(cand.Proposed.Verdict) {
			cand.State = CandidateEscalation
			cand.Escalated = &record
			cand.AssignedTo = ""
			out.Escalations++
			out.Notes = append(out.Notes, "la promoción de veredicto exige un segundo verificador independiente")
			break
		}
		cand.State = CandidateDecided
		cand.Final = &record
		cand.AssignedTo = ""
		out.Decided++

	case CandidateEscalation:
		switch v.Decision {
		case "verified":
			if cand.Escalated == nil {
				return nil, errors.New("auditoría: escalación sin registro que verificar")
			}
			cand.Attempts = append(cand.Attempts, VerificationAttempt{
				AgentID: sub.AgentID, Mode: ModeEscalationCheck, Decision: v.Decision,
			})
			cand.State = CandidateDecided
			cand.Final = cand.Escalated
			cand.AssignedTo = ""
			out.Decided++
		case "replace":
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
			cand.Attempts = append(cand.Attempts, VerificationAttempt{
				AgentID: sub.AgentID, Mode: ModeEscalationCheck, Decision: v.Decision, Record: &record,
			})
			if cand.Escalated != nil && VerdictRank(record.Verdict) > VerdictRank(cand.Escalated.Verdict) {
				cand.Escalated = &record
				cand.AssignedTo = ""
				out.Escalations++
				out.Notes = append(out.Notes, "el reemplazo vuelve a escalar el veredicto; se exige otro verificador")
				break
			}
			cand.State = CandidateDecided
			cand.Final = &record
			cand.AssignedTo = ""
			out.Decided++
		default:
			return nil, fmt.Errorf("auditoría: decisión desconocida %q en escalación", v.Decision)
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
