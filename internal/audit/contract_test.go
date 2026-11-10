package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// validLedger es el fixture mínimo que debe pasar esquema y semántica.
func validLedger() *Ledger {
	max := 6
	l := &Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Run: Run{
			ID: "20261109T000000Z-aaaa", StartedAt: "2026-11-09T00:00:00Z",
			CLIVersion: "0.2.0", SourceRef: "worktree", Dirty: false,
		},
		Target:    Target{Root: "/tmp/proyecto", LocalID: "proyecto"},
		Profile:   ProfileStandard,
		Budget:    &Budget{MaxAgentInvocations: max, Used: 0},
		RunStatus: StatusInProgress,
		Units: []Unit{{
			CoverageID:    "project/code/injection/input-to-sink",
			Subsystem:     "project",
			Domain:        "code",
			Boundary:      "input-to-sink",
			AttackClass:   "injection",
			StartingPaths: []string{"main.go"},
			State:         StatePlanned,
			Wave:          0,
			ReviewedPaths: []string{},
			Checks:        []Check{},
			Candidates:    []string{},
			Unresolved:    []string{},
			Attempts:      []Attempt{},
		}},
	}
	l.Recompute()
	return l
}

func validFindings() *Findings {
	f := &Findings{
		SchemaVersion: FindingsSchemaVersion,
		Run:           Run{ID: "20261109T000000Z-aaaa", StartedAt: "2026-11-09T00:00:00Z", CLIVersion: "0.2.0", SourceRef: "worktree"},
		Target:        Target{Root: "/tmp/proyecto", LocalID: "proyecto"},
		Provenance:    CallerProvenance(),
		Findings: []Record{{
			Verdict:          VerdictConfirmed,
			Fingerprint:      "fp-0001",
			Title:            "Ejecución de comandos desde entrada no confiable",
			Description:      "La entrada del usuario se pasa a exec.Command sin validación.",
			RootCause:        "Falta validación de la entrada en el punto de decisión.",
			IntendedBehavior: "Solo se aceptan identificadores de una lista cerrada.",
			Trace: []TraceStep{
				{Kind: "entrypoint", File: "cmd/run.go", Line: 12, Scope: "handler", Description: "recibe el valor"},
				{Kind: "sink", File: "cmd/exec.go", Line: 40, Scope: "run", Description: "lo pasa al proceso"},
			},
			Evidence: []Evidence{{File: "cmd/exec.go", Line: 40, Description: "argumento interpolado"}},
			Conditions: []Condition{{
				Kind: "authentication_level", Description: "usuario autenticado",
			}},
			Execution: &Execution{
				AttackerPerspective: "usuario autenticado con permiso de ejecución",
				Payloads:            []string{"--target=../../etc/passwd"},
				Instructions:        []string{"llamar al comando con el payload en un entorno local"},
				ObservedResult:      "el proceso recibe el valor sin validar",
			},
			Remediation: &Remediation{Strategy: "validar contra lista cerrada antes de invocar"},
			Severity: &Severity{
				Likelihood: Score{Score: "medium", Reason: "requiere autenticación"},
				Impact:     Score{Score: "high", Reason: "ejecución de comandos"},
				Overall:    "high",
			},
			Confidence: &Confidence{Score: "high", Reason: "traza completa y resultado local"},
		}},
	}
	f.Recompute()
	return f
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(data, '\n')
}

func TestValidLedgerPassesSchemaAndSemantics(t *testing.T) {
	data := mustJSON(t, validLedger())
	if err := ValidateLedger(data); err != nil {
		t.Fatalf("esquema: %v", err)
	}
	l, err := DecodeLedger(data)
	if err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("semántica: %v", err)
	}
}

func TestLedgerRejectsUnknownField(t *testing.T) {
	l := validLedger()
	data := mustJSON(t, l)
	data = []byte(strings.Replace(string(data), `"profile"`, `"perfil_extra": true,
    "profile"`, 1))
	if err := ValidateLedger(data); err == nil {
		t.Fatal("se esperaba error de esquema por campo desconocido")
	}
}

func TestLedgerRejectsDuplicateCoverageID(t *testing.T) {
	l := validLedger()
	l.Units = append(l.Units, l.Units[0])
	l.Recompute()
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "coverage_id duplicado") {
		t.Fatalf("se esperaba error de coverage_id duplicado, got %v", err)
	}
}

func TestLedgerRejectsDeferredWithoutReason(t *testing.T) {
	l := validLedger()
	l.Units[0].State = StateDeferred
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("se esperaba error por deferred sin razón, got %v", err)
	}
}

func TestLedgerRejectsCoveredWithoutOwnerOrChecks(t *testing.T) {
	l := validLedger()
	l.Units[0].State = StateCovered
	l.Units[0].ReviewedPaths = []string{"main.go"}
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("se esperaba error por owner, got %v", err)
	}
}

func TestLedgerRejectsReviewedPathsNotEqualToCheckUnion(t *testing.T) {
	l := validLedger()
	u := &l.Units[0]
	u.State = StateCovered
	u.Owner = "hunter-a"
	u.ReviewedPaths = []string{"main.go", "otro.go"}
	u.Checks = []Check{{
		AgentID: "hunter-a", ReviewedPaths: []string{"main.go"},
		Invariant: "la entrada se valida antes del sink", Method: "source",
		Result: "no hay validación",
	}}
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "reviewed_paths") {
		t.Fatalf("se esperaba error de unión de reviewed_paths, got %v", err)
	}
}

func TestLedgerRejectsLocalCheckWithoutArtifact(t *testing.T) {
	l := validLedger()
	u := &l.Units[0]
	u.State = StateCandidate
	u.Owner = "hunter-a"
	u.ReviewedPaths = []string{"main.go"}
	u.Candidates = []string{"fp-0001"}
	u.Checks = []Check{{
		AgentID: "hunter-a", ReviewedPaths: []string{"main.go"},
		Invariant: "check", Method: "local", Result: "resultado",
	}}
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "artifact") {
		t.Fatalf("se esperaba error por artifact, got %v", err)
	}
}

func TestLedgerRejectsUnsafeAgentID(t *testing.T) {
	for _, id := range []string{"Hunter-A", "con", "com1", "-hunter"} {
		l := validLedger()
		l.Units[0].Owner = id
		if err := ValidateLedgerSemantics(l); err == nil {
			t.Fatalf("se esperaba rechazo del agent_id %q", id)
		}
	}
}

func TestLedgerRejectsBudgetOverrun(t *testing.T) {
	l := validLedger()
	l.Budget.Used = l.Budget.MaxAgentInvocations + 1
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "presupuesto") {
		t.Fatalf("se esperaba error de presupuesto, got %v", err)
	}
}

func TestLedgerCompleteRequiresNoPlannedUnits(t *testing.T) {
	l := validLedger()
	l.RunStatus = StatusComplete
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "planned") {
		t.Fatalf("se esperaba error por unidad planned, got %v", err)
	}
}

func TestLedgerIncompleteRequiresReason(t *testing.T) {
	l := validLedger()
	l.RunStatus = StatusIncomplete
	err := ValidateLedgerSemantics(l)
	if err == nil || !strings.Contains(err.Error(), "incomplete_reason") {
		t.Fatalf("se esperaba error por incomplete_reason, got %v", err)
	}
	l.IncompleteReason = "budget_exhausted"
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("semántica: %v", err)
	}
}

func TestLedgerRejectsUnsafePaths(t *testing.T) {
	for _, p := range []string{"/etc/passwd", "../fuera.go", "a/../../b.go", `C:\x.go`, ""} {
		l := validLedger()
		l.Units[0].StartingPaths = []string{p}
		if err := ValidateLedgerSemantics(l); err == nil {
			t.Fatalf("se esperaba rechazo de la ruta %q", p)
		}
	}
}

func TestFindingsRejectDuplicateFingerprint(t *testing.T) {
	f := validFindings()
	f.Findings = append(f.Findings, f.Findings[0])
	f.Recompute()
	err := ValidateFindingsSemantics(f)
	if err == nil || !strings.Contains(err.Error(), "fingerprint duplicado") {
		t.Fatalf("se esperaba fingerprint duplicado, got %v", err)
	}
}

func TestFindingsRejectNeedsValidationWithSeverity(t *testing.T) {
	// Entrada hostil: un needs_validation con severidad debe rechazarse al
	// validar el JSON recibido, aunque nuestro marshaller nunca la emita.
	raw := `{
  "schema_version": "findings-1.0.0",
  "run": {"id": "r", "started_at": "2026-11-09T00:00:00Z", "cli_version": "0.2.0", "source_ref": "worktree", "dirty": false},
  "target": {"root": "/tmp/p", "local_id": "p"},
  "provenance": {"attested_by": "caller", "engine_verified": false, "engine_role": "structure-and-consistency"},
  "summary": {
    "confirmed": 0, "needs_validation": 1, "rejected": 0,
    "confirmed_by_severity": {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
  },
  "findings": [{
    "verdict": "needs_validation",
    "fingerprint": "fp-0002",
    "title": "t",
    "description": "d",
    "claimed_root_cause": "c",
    "trace": [{"kind": "sink", "file": "a.go", "line": 1, "scope": "s", "description": "d"}],
    "evidence": [{"file": "a.go", "line": 1, "description": "d"}],
    "blockers": ["falta la configuración de despliegue"],
    "validation_plan": {"deployment": "observar la política del proxy"},
    "severity": {"likelihood": {"score": "low", "reason": "r"}, "impact": {"score": "high", "reason": "r"}, "overall_severity": "high"}
  }]
}`
	err := ValidateFindings([]byte(raw))
	if err == nil {
		t.Fatal("el esquema debe rechazar severidad en needs_validation")
	}
}

func TestFindingsRejectConfirmedWithoutObservedResult(t *testing.T) {
	f := validFindings()
	f.Findings[0].Execution.ObservedResult = "   "
	err := ValidateFindingsSemantics(f)
	if err == nil || !strings.Contains(err.Error(), "observed_result") {
		t.Fatalf("se esperaba error por observed_result, got %v", err)
	}
}

func TestFindingsRejectSeverityAboveImpact(t *testing.T) {
	f := validFindings()
	f.Findings[0].Severity.Impact.Score = "medium"
	f.Findings[0].Severity.Overall = "critical"
	err := ValidateFindingsSemantics(f)
	if err == nil || !strings.Contains(err.Error(), "severidad") {
		t.Fatalf("se esperaba error de severidad, got %v", err)
	}
}

func TestFindingsRejectBadTraceShape(t *testing.T) {
	cases := [][]TraceStep{
		{},
		{{Kind: "propagation", File: "a.go", Line: 1, Scope: "s", Description: "d"}},
		{{Kind: "sink", File: "a.go", Line: 1, Scope: "s", Description: "d"}, {Kind: "entrypoint", File: "b.go", Line: 1, Scope: "s", Description: "d"}},
		{{Kind: "entrypoint", File: "a.go", Line: 1, Scope: "s", Description: "d"}, {Kind: "propagation", File: "b.go", Line: 1, Scope: "s", Description: "d"}},
	}
	for i, trace := range cases {
		f := validFindings()
		f.Findings[0].Trace = trace
		if err := ValidateFindingsSemantics(f); err == nil {
			t.Fatalf("caso %d: se esperaba traza inválida", i)
		}
	}
}

func TestFindingsRejectFalseEngineAuthority(t *testing.T) {
	f := validFindings()
	f.Provenance.EngineVerified = true
	err := ValidateFindingsSemantics(f)
	if err == nil || !strings.Contains(err.Error(), "engine_verified") {
		t.Fatalf("se esperaba rechazo de engine_verified=true, got %v", err)
	}
}

func TestRecordMarshalKeepsBranchPurity(t *testing.T) {
	f := validFindings()
	f.Findings = []Record{{
		Verdict:     VerdictRejected,
		Fingerprint: "fp-0003",
		Title:       "t", Description: "d",
		ClaimedRootCause: "c",
		Trace:            []TraceStep{{Kind: "sink", File: "a.go", Line: 1, Scope: "s", Description: "d"}},
		Evidence:         []Evidence{{File: "a.go", Line: 1, Description: "d"}},
		Reason:           "la capa visible impide el efecto",
		Severity:         &Severity{Overall: "high"},
		Execution:        &Execution{ObservedResult: "x"},
	}}
	data := mustJSON(t, f)
	for _, banned := range []string{"severity", "execution", "blockers", "validation_plan"} {
		if strings.Contains(string(data), `"`+banned+`"`) {
			t.Fatalf("rejected no debe emitir %q:\n%s", banned, data)
		}
	}
}
