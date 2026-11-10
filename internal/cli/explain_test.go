package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
)

func TestAuditExplainUnitAndFingerprint(t *testing.T) {
	app, root, runDir, unitID := auditExplainFixture(t)

	// explain por unidad: estado, dueño, checks y próximos pasos.
	code, out, errOut := auditRun(t, app, "audit", "explain", "--out", runDir, "--coverage-id", unitID, "--format", "json")
	if code != 0 {
		t.Fatalf("explain unit = %d: %s %s", code, out, errOut)
	}
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Unit          struct {
			CoverageID string `json:"coverage_id"`
			State      string `json:"state"`
		} `json:"unit"`
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Unit.CoverageID != unitID || len(doc.NextSteps) == 0 {
		t.Fatalf("explicación inesperada: %+v", doc)
	}

	// explain por fingerprint con prefijo inequívoco.
	code, out, errOut = auditRun(t, app, "audit", "explain", "--out", runDir, "--fingerprint", "fp-", "--format", "json")
	if code != 0 {
		t.Fatalf("explain fp = %d: %s %s", code, out, errOut)
	}
	var candDoc struct {
		Candidate struct {
			Fingerprint string `json:"fingerprint"`
			State       string `json:"state"`
		} `json:"candidate"`
	}
	if err := json.Unmarshal([]byte(out), &candDoc); err != nil {
		t.Fatal(err)
	}
	if candDoc.Candidate.Fingerprint != "fp-1" {
		t.Fatalf("candidato inesperado: %+v", candDoc)
	}
	_ = root
}

func TestAuditExplainAmbiguousPrefixIsUseful(t *testing.T) {
	app, _, runDir, _ := auditExplainFixture(t)
	// Añadir un segundo candidato con prefijo fp-: el prefijo fp- se vuelve
	// ambiguo y el error lista los fingerprints.
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Ledger.Units[1].State = audit.StateCandidate
	st.Ledger.Units[1].Owner = "hunter-a"
	st.Ledger.Units[1].ReviewedPaths = []string{"main.go"}
	st.Ledger.Units[1].Checks = []audit.Check{checksFor("hunter-a", []string{"main.go"})[0]}
	st.Ledger.Units[1].Candidates = []string{"fp-2"}
	st.Candidates.Items = append(st.Candidates.Items, audit.Candidate{
		Fingerprint: "fp-2", Unit: st.Ledger.Units[1].CoverageID, HunterAgent: "hunter-a",
		Proposed: sampleNeedsValidation("fp-2"), State: audit.CandidatePending,
		Attempts: []audit.VerificationAttempt{},
	})
	st.Ledger.Recompute()
	if err := store.CommitState(st); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := auditRun(t, app, "audit", "explain", "--out", runDir, "--fingerprint", "fp-")
	if code != 2 || !strings.Contains(errOut, "ambiguo") {
		t.Fatalf("explain = %d: %s; se esperaba diagnóstico de ambigüedad", code, errOut)
	}
	if !strings.Contains(errOut, "fp-1") || !strings.Contains(errOut, "fp-2") {
		t.Fatalf("el error debe listar los fingerprints: %s", errOut)
	}
}

func TestAuditExplainUnknownIdentifier(t *testing.T) {
	app, _, runDir, _ := auditExplainFixture(t)
	code, _, errOut := auditRun(t, app, "audit", "explain", "--out", runDir, "--coverage-id", "root/nope/x")
	if code != 2 || !strings.Contains(errOut, "desconocido") {
		t.Fatalf("explain = %d: %s; se esperaba diagnóstico útil", code, errOut)
	}
	code, _, errOut = auditRun(t, app, "audit", "explain", "--out", runDir, "--fingerprint", "no-existe")
	if code != 2 || !strings.Contains(errOut, "desconocido") {
		t.Fatalf("explain = %d: %s; se esperaba diagnóstico útil", code, errOut)
	}
}

func TestAuditExplainDoesNotRewriteArtifacts(t *testing.T) {
	app, _, runDir, unitID := auditExplainFixture(t)
	statePath := runDir + "/state.json"
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := auditRun(t, app, "audit", "explain", "--out", runDir, "--coverage-id", unitID); code != 0 {
		t.Fatalf("explain = %d: %s", code, errOut)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("explain reescribió artefactos")
	}
}

func TestAuditStatusListsBlockedAndDeferred(t *testing.T) {
	app, _, runDir, _ := auditExplainFixture(t)
	// Una unidad bloqueada y una diferida en el estado persistido.
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Ledger.Units[1].State = audit.StateBlocked
	st.Ledger.Units[1].Owner = "hunter-a"
	st.Ledger.Units[1].ReviewedPaths = []string{"main.go"}
	st.Ledger.Units[1].Checks = []audit.Check{checksFor("hunter-a", []string{"main.go"})[0]}
	st.Ledger.Units[1].Unresolved = []string{"falta un despliegue local"}
	st.Ledger.Units[2].State = audit.StateDeferred
	st.Ledger.Units[2].Reason = "budget_exhausted"
	st.Ledger.Recompute()
	if err := store.CommitState(st); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json")
	if code != 0 {
		t.Fatalf("status = %d: %s %s", code, out, errOut)
	}
	var doc struct {
		BlockedUnits  []string `json:"blocked_units"`
		DeferredUnits []string `json:"deferred_units"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.BlockedUnits) != 1 || len(doc.DeferredUnits) != 1 {
		t.Fatalf("listas inesperadas: %+v", doc)
	}
	// El texto lista las unidades bloqueadas y diferidas.
	codeText, outText, _ := auditRun(t, app, "audit", "status", "--out", runDir, "--format", "text")
	if codeText != 0 || !strings.Contains(outText, "Bloqueadas:") || !strings.Contains(outText, "Diferidas:") {
		t.Fatalf("status text inesperado: %s", outText)
	}
}

// auditExplainFixture construye una corrida con un candidato pendiente.
func auditExplainFixture(t *testing.T) (*App, string, string, string) {
	t.Helper()
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json", "--profile", "quick"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	unitID := firstUnitID(t, runDir)
	file := candidateSubmissionFile(t, "hunter-a", unitID, "fp-1", sampleNeedsValidation("fp-1"))
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file); code != 0 {
		t.Fatalf("submit = %d: %s %s", code, out, errOut)
	}
	return app, root, runDir, unitID
}

func TestAuditFailOnMatrixWithRealRuns(t *testing.T) {
	app, _, runDir, _ := auditExplainFixture(t)
	// sellar la corrida completa con un hallazgo needs_validation decidido
	coverRemainingUnits(t, app, runDir)
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("report = %d: %s %s", code, out, errOut)
	}

	// Sin flag: comportamiento de compatibilidad (corrida completa → 0).
	code, _, _ := auditRun(t, app, "audit", "report", "--out", runDir)
	if code != 0 {
		t.Fatalf("sin flag = %d, want 0", code)
	}

	// confirmed con un hallazgo needs_validation decidido → 1.
	code, _, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--fail-on", "needs_validation")
	if code != 1 || !strings.Contains(errOut, "umbral") {
		t.Fatalf("needs_validation = %d: %s; want 1", code, errOut)
	}

	// critical: el hallazgo no es confirmado critical → 0.
	code, _, _ = auditRun(t, app, "audit", "report", "--out", runDir, "--fail-on", "critical")
	if code != 0 {
		t.Fatalf("critical = %d, want 0", code)
	}

	// Umbral desconocido → 2.
	code, _, errOut = auditRun(t, app, "audit", "report", "--out", runDir, "--fail-on", "no-existe")
	if code != 2 {
		t.Fatalf("umbral desconocido = %d: %s; want 2", code, errOut)
	}

	// La política de salida no altera hallazgos ni estado.
	code, out, _ := auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json")
	if code != 0 || !strings.Contains(out, "run_status") {
		t.Fatalf("status tras la política de salida = %d: %s", code, out)
	}
}
