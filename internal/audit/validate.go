package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	agentIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	coverageIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)
	fingerprintPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)
)

// reservedAgentIDs son nombres de dispositivo de Windows: un identificador de
// agente no puede colisionar con ellos.
var reservedAgentIDs = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

var conditionKinds = map[string]bool{
	"authentication_level": true, "authorization_role": true,
	"user_interaction": true, "system_configuration": true,
	"network_routing": true, "environmental_dependency": true,
	"data_state": true, "timing_dependency": true, "third_party_dependency": true,
}

var severityRank = map[string]int{
	"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// Issues acumula los problemas de contrato de un documento.
type Issues struct{ list []string }

func (i *Issues) addf(format string, args ...any) {
	i.list = append(i.list, fmt.Sprintf(format, args...))
}

func (i *Issues) err() error {
	if len(i.list) == 0 {
		return nil
	}
	return fmt.Errorf("contrato inválido: %s", strings.Join(i.list, "; "))
}

// ValidAgentID informa si id cumple el patrón canónico y no es un nombre
// reservado de Windows.
func ValidAgentID(id string) bool {
	if !agentIDPattern.MatchString(id) {
		return false
	}
	return !reservedAgentIDs[id]
}

// ValidRepoPath informa si p es una ruta relativa al repositorio, sin
// componentes absolutos, vacíos, "." ni "..".
func ValidRepoPath(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return false
	}
	if len(p) >= 2 && p[1] == ':' {
		return false
	}
	normalized := strings.ReplaceAll(p, "\\", "/")
	for _, part := range strings.Split(normalized, "/") {
		switch part {
		case "", ".", "..":
			return false
		}
	}
	return true
}

// ValidateLedgerSemantics aplica las reglas que el esquema no puede expresar:
// estados coherentes, independencia de evidencia, presupuesto y honestidad de
// la cobertura.
func ValidateLedgerSemantics(l *Ledger) error {
	if l == nil {
		return fmt.Errorf("contrato inválido: ledger nulo")
	}
	var is Issues
	if l.SchemaVersion != LedgerSchemaVersion {
		is.addf("schema_version %q, se esperaba %q", l.SchemaVersion, LedgerSchemaVersion)
	}
	switch l.Profile {
	case ProfileQuick, ProfileStandard, ProfileDeep:
	default:
		is.addf("perfil desconocido: %q", l.Profile)
	}
	if l.Budget != nil {
		if l.Budget.MaxAgentInvocations < 1 {
			is.addf("presupuesto: max_agent_invocations debe ser positivo")
		}
		if l.Budget.Used < 0 || (l.Budget.MaxAgentInvocations > 0 && l.Budget.Used > l.Budget.MaxAgentInvocations) {
			is.addf("presupuesto excedido: used=%d max=%d", l.Budget.Used, l.Budget.MaxAgentInvocations)
		}
	}

	seen := map[string]bool{}
	for i := range l.Units {
		u := &l.Units[i]
		where := "unidad " + u.CoverageID
		if !coverageIDPattern.MatchString(u.CoverageID) {
			is.addf("%s: coverage_id no cumple el patrón canónico", where)
		}
		if seen[u.CoverageID] {
			is.addf("coverage_id duplicado: %s", u.CoverageID)
		}
		seen[u.CoverageID] = true
		for _, field := range []struct{ name, value string }{
			{"subsystem", u.Subsystem}, {"domain", u.Domain},
			{"boundary", u.Boundary}, {"attack_class", u.AttackClass},
		} {
			if strings.TrimSpace(field.value) == "" {
				is.addf("%s: %s vacío", where, field.name)
			}
		}
		if len(u.StartingPaths) == 0 {
			is.addf("%s: starting_paths vacío", where)
		}
		for _, p := range u.StartingPaths {
			if u.State == StateOutOfScope && p == "." {
				continue
			}
			if !ValidRepoPath(p) {
				is.addf("%s: starting_paths contiene una ruta no relativa al repositorio: %q", where, p)
			}
		}
		if !ValidAgentID(u.Owner) && u.Owner != "" {
			is.addf("%s: agent_id inválido: %q", where, u.Owner)
		}
		if err := validateChecks(where, u.Checks); err != nil {
			is.addf("%v", err)
		}
		for _, p := range u.ReviewedPaths {
			if !ValidRepoPath(p) {
				is.addf("%s: reviewed_paths contiene una ruta no relativa al repositorio: %q", where, p)
			}
		}
		if union := unionPaths(u.Checks); !sameSet(union, u.ReviewedPaths) {
			is.addf("%s: reviewed_paths debe ser exactamente la unión de los checks (unión=%v, declarado=%v)",
				where, union, u.ReviewedPaths)
		}
		for _, fp := range u.Candidates {
			if !fingerprintPattern.MatchString(fp) {
				is.addf("%s: fingerprint inválido: %q", where, fp)
			}
		}
		validateUnitState(where, u, &is)
		for _, a := range u.Attempts {
			validateAttempt(where, u.Wave, a, &is)
		}
	}

	if l.RunStatus == StatusComplete {
		if l.Summary.Planned > 0 || l.Summary.InProgress > 0 {
			is.addf("run_status complete con %d unidad(es) planned y %d in_progress", l.Summary.Planned, l.Summary.InProgress)
		}
	}
	if l.RunStatus == StatusIncomplete && strings.TrimSpace(l.IncompleteReason) == "" {
		is.addf("run_status incomplete requiere incomplete_reason")
	}
	if l.RunStatus != StatusInProgress && l.RunStatus != StatusComplete && l.RunStatus != StatusIncomplete {
		is.addf("run_status desconocido: %q", l.RunStatus)
	}
	if l.Prior != nil {
		if strings.TrimSpace(l.Prior.RunID) == "" || strings.TrimSpace(l.Prior.SourceRef) == "" {
			is.addf("prior requiere run_id y source_ref")
		}
		for _, fp := range append(append([]string{}, l.Prior.RejectedFingerprints...), l.Prior.NeedsValidationFingerprints...) {
			if !fingerprintPattern.MatchString(fp) {
				is.addf("prior: fingerprint inválido: %q", fp)
			}
		}
	}
	if l.Critique != nil {
		if l.Critique.Pending && !ValidAgentID(l.Critique.IssuedTo) {
			is.addf("critique: una crítica pendiente requiere issued_to válido")
		}
		if !l.Critique.Pending && l.Critique.IssuedTo != "" {
			is.addf("critique: issued_to solo es válido con una crítica pendiente")
		}
		for _, fp := range l.Critique.ResolvedLeads {
			if !fingerprintPattern.MatchString(fp) {
				is.addf("critique: fingerprint inválido en resolved_leads: %q", fp)
			}
		}
		if l.Critique.Stopped && strings.TrimSpace(l.Critique.Reason) == "" {
			is.addf("critique: un stop requiere reason")
		}
	}
	checkLedgerSummary(l, &is)
	return is.err()
}

func validateUnitState(where string, u *Unit, is *Issues) {
	switch u.State {
	case StatePlanned:
		if u.Owner != "" {
			is.addf("%s: planned no puede tener owner", where)
		}
	case StateInProgress:
		if u.Owner == "" {
			is.addf("%s: in_progress requiere owner", where)
		}
	case StateCovered:
		if u.Owner == "" {
			is.addf("%s: covered requiere owner", where)
		}
		if len(u.ReviewedPaths) == 0 || len(u.Checks) == 0 {
			is.addf("%s: covered requiere reviewed_paths y checks no vacíos", where)
		}
		if len(u.Candidates) > 0 {
			is.addf("%s: covered no puede tener candidate_fingerprints", where)
		}
		if len(u.Unresolved) > 0 {
			is.addf("%s: covered no puede tener unresolved", where)
		}
	case StateCandidate:
		if u.Owner == "" || len(u.ReviewedPaths) == 0 || len(u.Checks) == 0 {
			is.addf("%s: candidate requiere owner, reviewed_paths y checks", where)
		}
		if len(u.Candidates) == 0 {
			is.addf("%s: candidate requiere al menos un candidate_fingerprint", where)
		}
	case StateBlocked:
		if u.Owner == "" || len(u.ReviewedPaths) == 0 || len(u.Checks) == 0 {
			is.addf("%s: blocked requiere owner, reviewed_paths y checks", where)
		}
		if len(u.Unresolved) == 0 {
			is.addf("%s: blocked requiere unresolved", where)
		}
		if len(u.Candidates) > 0 {
			is.addf("%s: blocked no puede tener candidate_fingerprints", where)
		}
	case StateDeferred, StateOutOfScope:
		if strings.TrimSpace(u.Reason) == "" {
			is.addf("%s: %s requiere reason", where, u.State)
		}
		if u.Owner != "" || len(u.Checks) > 0 || len(u.Candidates) > 0 {
			is.addf("%s: %s no puede tener owner, checks ni candidate_fingerprints", where, u.State)
		}
	default:
		is.addf("%s: estado desconocido: %q", where, u.State)
	}
}

func validateChecks(where string, checks []Check) error {
	var is Issues
	for i, c := range checks {
		at := fmt.Sprintf("%s check[%d]", where, i)
		if !ValidAgentID(c.AgentID) {
			is.addf("%s: agent_id inválido: %q", at, c.AgentID)
		}
		if len(c.ReviewedPaths) == 0 {
			is.addf("%s: reviewed_paths vacío", at)
		}
		for _, p := range c.ReviewedPaths {
			if !ValidRepoPath(p) {
				is.addf("%s: ruta no relativa al repositorio: %q", at, p)
			}
		}
		if strings.TrimSpace(c.Invariant) == "" || strings.TrimSpace(c.Result) == "" {
			is.addf("%s: invariant y result son obligatorios", at)
		}
		switch c.Method {
		case "source":
			if c.Artifact != nil {
				is.addf("%s: un check source no puede tener artifact", at)
			}
		case "local":
			if c.Artifact == nil || strings.TrimSpace(*c.Artifact) == "" {
				is.addf("%s: un check local requiere artifact promovido", at)
			}
		default:
			is.addf("%s: method desconocido: %q", at, c.Method)
		}
	}
	return is.err()
}

func validateAttempt(where string, currentWave int, a Attempt, is *Issues) {
	at := fmt.Sprintf("%s attempt wave %d", where, a.Wave)
	if !ValidAgentID(a.AgentID) {
		is.addf("%s: agent_id inválido: %q", at, a.AgentID)
	}
	switch a.State {
	case StateCovered, StateCandidate, StateBlocked:
	default:
		is.addf("%s: estado archivado inválido: %q", at, a.State)
	}
	if a.Wave > currentWave {
		is.addf("%s: la ola archivada supera la ola vigente %d", at, currentWave)
	}
	if strings.TrimSpace(a.Reason) == "" {
		is.addf("%s: un intento archivado requiere reason", at)
	}
	if union := unionPaths(a.Checks); !sameSet(union, a.ReviewedPaths) {
		is.addf("%s: reviewed_paths no coincide con la unión de los checks", at)
	}
}

func checkLedgerSummary(l *Ledger, is *Issues) {
	expected := *l
	expected.Recompute()
	if expected.Summary != l.Summary {
		is.addf("summary no coincide con las unidades: declarado %+v, calculado %+v", l.Summary, expected.Summary)
	}
}

func unionPaths(checks []Check) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	for _, c := range checks {
		for _, p := range c.ReviewedPaths {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// ValidateFindingsSemantics aplica las reglas de veredicto que el esquema no
// puede expresar: trazas coherentes, severidad acotada al impacto y
// procedencia honesta.
func ValidateFindingsSemantics(f *Findings) error {
	if f == nil {
		return fmt.Errorf("contrato inválido: hallazgos nulos")
	}
	var is Issues
	if f.SchemaVersion != FindingsSchemaVersion {
		is.addf("schema_version %q, se esperaba %q", f.SchemaVersion, FindingsSchemaVersion)
	}
	if f.Provenance.AttestedBy != AttestedByCaller {
		is.addf("provenance.attested_by debe ser %q", AttestedByCaller)
	}
	if f.Provenance.EngineVerified {
		is.addf("provenance.engine_verified debe ser false: el motor valida estructura, no verdad")
	}
	if f.Provenance.EngineRole != EngineRoleStructure {
		is.addf("provenance.engine_role debe ser %q", EngineRoleStructure)
	}

	seen := map[string]bool{}
	for i := range f.Findings {
		r := &f.Findings[i]
		where := fmt.Sprintf("hallazgo %q", r.Fingerprint)
		if !fingerprintPattern.MatchString(r.Fingerprint) {
			is.addf("%s: fingerprint no cumple el patrón canónico", where)
		}
		if seen[r.Fingerprint] {
			is.addf("fingerprint duplicado: %s", r.Fingerprint)
		}
		seen[r.Fingerprint] = true
		if strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Description) == "" {
			is.addf("%s: title y description son obligatorios", where)
		}
		if err := validateTrace(where, r.Trace); err != nil {
			is.addf("%v", err)
		}
		for _, e := range r.Evidence {
			if !ValidRepoPath(e.File) {
				is.addf("%s: evidence.file no es relativa al repositorio: %q", where, e.File)
			}
		}
		switch r.Verdict {
		case VerdictConfirmed:
			validateConfirmed(where, r, &is)
		case VerdictNeedsValidation:
			validateNeedsValidation(where, r, &is)
		case VerdictRejected:
			validateRejected(where, r, &is)
		default:
			is.addf("%s: veredicto desconocido: %q", where, r.Verdict)
		}
	}
	expected := *f
	expected.Recompute()
	if expected.Summary != f.Summary {
		is.addf("summary no coincide con los hallazgos: declarado %+v, calculado %+v", f.Summary, expected.Summary)
	}
	return is.err()
}

func validateConfirmed(where string, r *Record, is *Issues) {
	if strings.TrimSpace(r.RootCause) == "" || strings.TrimSpace(r.IntendedBehavior) == "" {
		is.addf("%s: confirmed requiere root_cause e intended_behavior", where)
	}
	if r.Execution == nil {
		is.addf("%s: confirmed requiere execution", where)
	} else {
		if strings.TrimSpace(r.Execution.ObservedResult) == "" {
			is.addf("%s: confirmed requiere execution.observed_result no vacío", where)
		}
		if strings.TrimSpace(r.Execution.AttackerPerspective) == "" {
			is.addf("%s: confirmed requiere attacker_perspective", where)
		}
		if len(r.Execution.Payloads) == 0 || len(r.Execution.Instructions) == 0 {
			is.addf("%s: confirmed requiere payloads e instrucciones de reproducción", where)
		}
	}
	if r.Remediation == nil || strings.TrimSpace(r.Remediation.Strategy) == "" {
		is.addf("%s: confirmed requiere remediation.strategy", where)
	}
	if r.Severity == nil {
		is.addf("%s: confirmed requiere severity", where)
		return
	}
	for _, s := range []string{r.Severity.Likelihood.Score, r.Severity.Impact.Score, r.Severity.Overall} {
		if _, ok := severityRank[s]; !ok {
			is.addf("%s: severidad desconocida: %q", where, s)
		}
	}
	if severityRank[r.Severity.Overall] > severityRank[r.Severity.Impact.Score] {
		is.addf("%s: la severidad overall no puede superar al impacto demostrado", where)
	}
	if r.Severity.Likelihood.Reason == "" || r.Severity.Impact.Reason == "" {
		is.addf("%s: cada severidad requiere su razón", where)
	}
	if r.Confidence == nil || strings.TrimSpace(r.Confidence.Reason) == "" {
		is.addf("%s: confirmed requiere confidence con razón", where)
	} else {
		switch r.Confidence.Score {
		case "low", "medium", "high":
		default:
			is.addf("%s: confianza desconocida: %q", where, r.Confidence.Score)
		}
	}
	for _, c := range r.Conditions {
		if !conditionKinds[c.Kind] {
			is.addf("%s: condición desconocida: %q", where, c.Kind)
		}
		if strings.TrimSpace(c.Description) == "" {
			is.addf("%s: cada condición requiere descripción", where)
		}
	}
}

func validateNeedsValidation(where string, r *Record, is *Issues) {
	if strings.TrimSpace(r.ClaimedRootCause) == "" {
		is.addf("%s: needs_validation requiere claimed_root_cause", where)
	}
	if len(r.Blockers) == 0 {
		is.addf("%s: needs_validation requiere blockers", where)
	}
	if r.ValidationPlan == nil ||
		(strings.TrimSpace(r.ValidationPlan.Local) == "" && strings.TrimSpace(r.ValidationPlan.Deployment) == "") {
		is.addf("%s: needs_validation requiere un plan local o de despliegue", where)
	}
	if r.Severity != nil || r.Execution != nil || r.Remediation != nil || r.Reason != "" {
		is.addf("%s: needs_validation no puede llevar severidad, ejecución, remediación ni razón de rechazo", where)
	}
}

func validateRejected(where string, r *Record, is *Issues) {
	if strings.TrimSpace(r.Reason) == "" {
		is.addf("%s: rejected requiere reason", where)
	}
	if r.Severity != nil || r.Execution != nil || r.Remediation != nil || len(r.Blockers) > 0 || r.ValidationPlan != nil {
		is.addf("%s: rejected no puede llevar severidad, ejecución, remediación, blockers ni plan", where)
	}
}

func validateTrace(where string, trace []TraceStep) error {
	var is Issues
	if len(trace) == 0 {
		is.addf("%s: traza vacía", where)
		return is.err()
	}
	for i, step := range trace {
		at := fmt.Sprintf("%s trace[%d]", where, i)
		switch step.Kind {
		case "entrypoint", "propagation", "sink":
		default:
			is.addf("%s: kind desconocido: %q", at, step.Kind)
		}
		if !ValidRepoPath(step.File) {
			is.addf("%s: file no es relativa al repositorio: %q", at, step.File)
		}
		if step.Line < 1 {
			is.addf("%s: line debe ser positivo", at)
		}
		if strings.TrimSpace(step.Scope) == "" || strings.TrimSpace(step.Description) == "" {
			is.addf("%s: scope y description son obligatorios", at)
		}
	}
	if len(trace) == 1 {
		if trace[0].Kind != "entrypoint" && trace[0].Kind != "sink" {
			is.addf("%s: una traza de un paso debe ser entrypoint o sink", where)
		}
		return is.err()
	}
	if trace[0].Kind != "entrypoint" {
		is.addf("%s: la traza debe empezar en entrypoint", where)
	}
	if trace[len(trace)-1].Kind != "sink" {
		is.addf("%s: la traza debe terminar en sink", where)
	}
	for i := 1; i < len(trace)-1; i++ {
		if trace[i].Kind != "propagation" {
			is.addf("%s: los pasos intermedios deben ser propagation", where)
			break
		}
	}
	return is.err()
}

func sortRecords(records []Record) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Fingerprint != records[j].Fingerprint {
			return records[i].Fingerprint < records[j].Fingerprint
		}
		return records[i].Verdict < records[j].Verdict
	})
}
