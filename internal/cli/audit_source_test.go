package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
)

func gitCmd(t *testing.T, root string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root,
		"-c", "user.email=test@example.test", "-c", "user.name=Prueba",
		"-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// auditGitRepo crea un repositorio real con una revisión inicial limpia cuyo
// main.go tiene cuatro líneas.
func auditGitRepo(t *testing.T) (root, revA string) {
	t.Helper()
	root = t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.27.3\n",
		"main.go": "package main\n\nfunc main() {\n\trun()\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitCmd(t, root, "init", "-q")
	gitCmd(t, root, "add", "-A")
	gitCmd(t, root, "commit", "-q", "-m", "revisión a")
	return root, gitCmd(t, root, "rev-parse", "HEAD")
}

func candidateSubmissionFile(t *testing.T, agent, unitID, fp string, r audit.Record) string {
	t.Helper()
	sub := audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       agent,
		Units: []audit.UnitResult{{
			CoverageID:            unitID,
			Disposition:           audit.DispositionCandidate,
			ReviewedPaths:         []string{"main.go"},
			Checks:                checksFor(agent, []string{"main.go"}),
			CandidateFingerprints: []string{fp},
			Unresolved:            []string{},
		}},
		Candidates: []audit.Record{r},
	}
	return writeSubmissionFile(t, sub)
}

func TestAuditRejectsFabricatedTraceAgainstRevision(t *testing.T) {
	app, _, _ := newTestApp(t)
	root, revA := auditGitRepo(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	// Una cita fuera del snapshot se rechaza en submit y no muta la corrida.
	fabricated := sampleConfirmed("fp-1")
	fabricated.Trace[0].Line = 99
	file := candidateSubmissionFile(t, "hunter-a", firstUnitID(t, runDir), "fp-1", fabricated)
	code, _, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file)
	if code != 3 || !strings.Contains(errOut, "línea") {
		t.Fatalf("submit = %d: %s; se esperaba rechazo de la cita fabricada", code, errOut)
	}

	// La cita honesta se acepta.
	file = candidateSubmissionFile(t, "hunter-a", firstUnitID(t, runDir), "fp-1", sampleConfirmed("fp-1"))
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file); code != 0 {
		t.Fatalf("submit = %d: %s %s", code, out, errOut)
	}
	_ = revA
}

func firstUnitID(t *testing.T, runDir string) string {
	t.Helper()
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range st.Ledger.Units {
		if u.State == audit.StateInProgress {
			return u.CoverageID
		}
	}
	t.Fatal("no hay unidad en curso")
	return ""
}

func TestAuditHistoricalCitationSurvivesTreeChanges(t *testing.T) {
	app, _, _ := newTestApp(t)
	root, _ := auditGitRepo(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	unitID := ""
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	unitID = firstUnitID(t, runDir)
	file := candidateSubmissionFile(t, "hunter-a", unitID, "fp-1", sampleConfirmed("fp-1"))
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file); code != 0 {
		t.Fatalf("submit = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir, "--agent", "verifier-a", "--format", "json"); code != 0 {
		t.Fatalf("next verifier = %d: %s %s", code, out, errOut)
	}
	verification := audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       "verifier-a",
		Verification: &audit.Verification{
			Fingerprint: "fp-1", Decision: audit.VerdictConfirmed,
			Record: ptr(sampleConfirmed("fp-1")),
		},
	}
	file = writeSubmissionFile(t, verification)
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file); code != 0 {
		t.Fatalf("submit verify = %d: %s %s", code, out, errOut)
	}
	coverRemainingUnits(t, app, runDir)
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("report = %d: %s %s", code, out, errOut)
	}

	// El árbol de trabajo cambia (y se confirma otra revisión): la cita
	// histórica del snapshot declarado sigue siendo válida y el informe no
	// exige revalidación.
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", "-A")
	gitCmd(t, root, "commit", "-q", "-m", "revisión b")
	code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json")
	if code != 0 {
		t.Fatalf("report tras el cambio = %d: %s %s", code, out, errOut)
	}
	if strings.Contains(out, "revalidación") {
		t.Fatalf("la cita histórica no debe exigir revalidación: %s", out)
	}
}

func ptr(r audit.Record) *audit.Record { return &r }

// sampleNeedsValidation es una propuesta de cazador que cita main.go del
// árbol de prueba y exige verificación.
func sampleNeedsValidation(fp string) audit.Record {
	return audit.Record{
		Verdict:          audit.VerdictNeedsValidation,
		Fingerprint:      fp,
		Title:            "Posible ejecución de comandos",
		Description:      "La entrada podría alcanzar el proceso.",
		ClaimedRootCause: "Falta una lista cerrada en el punto de decisión.",
		Trace: []audit.TraceStep{
			{Kind: "entrypoint", File: "main.go", Line: 1, Scope: "main", Description: "recibe la entrada"},
			{Kind: "sink", File: "main.go", Line: 3, Scope: "main", Description: "ejecuta el proceso"},
		},
		Evidence:       []audit.Evidence{{File: "main.go", Line: 3, Description: "argumento interpolado"}},
		Blockers:       []string{"falta un despliegue local reproducible"},
		ValidationPlan: &audit.ValidationPlan{Local: "reproducir con un fixture mínimo"},
	}
}

// coverRemainingUnits asigna y cubre, con un agente fijo, todas las unidades
// que quedan planificadas o en curso.
func coverRemainingUnits(t *testing.T, app *App, runDir string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
			"--agent", "hunter-resto", "--max-units", "2", "--format", "json")
		if code != 0 {
			t.Fatalf("next resto = %d: %s %s", code, out, errOut)
		}
		if !strings.HasPrefix(strings.TrimSpace(out), "{") {
			return // no hay más tareas
		}
		var task audit.Task
		if err := json.Unmarshal([]byte(out), &task); err != nil {
			t.Fatalf("task resto: %v\n%s", err, out)
		}
		file := writeSubmissionFile(t, coveredSubmission("hunter-resto", task))
		if code, o, e := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file, "--format", "json"); code != 0 {
			t.Fatalf("submit resto = %d: %s %s", code, o, e)
		}
	}
	t.Fatal("el bucle de cobertura no terminó")
}

func TestAuditWorktreeDivergenceBlocksCompleteReport(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
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
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir, "--agent", "verifier-a", "--format", "json"); code != 0 {
		t.Fatalf("next verifier = %d: %s %s", code, out, errOut)
	}
	verification := audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       "verifier-a",
		Verification: &audit.Verification{
			Fingerprint: "fp-1", Decision: audit.VerdictConfirmed,
			Record: ptr(sampleConfirmed("fp-1")),
		},
	}
	// La promoción confirmed escala; exige un segundo verificador.
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", writeSubmissionFile(t, verification)); code != 0 {
		t.Fatalf("submit verify = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir, "--agent", "verifier-b", "--format", "json"); code != 0 {
		t.Fatalf("next escalation = %d: %s %s", code, out, errOut)
	}
	confirmed := audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       "verifier-b",
		Verification:  &audit.Verification{Fingerprint: "fp-1", Decision: audit.EscalationVerified},
	}
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", writeSubmissionFile(t, confirmed)); code != 0 {
		t.Fatalf("submit escalation = %d: %s %s", code, out, errOut)
	}
	coverRemainingUnits(t, app, runDir)
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("report = %d: %s %s", code, out, errOut)
	}

	// El archivo citado cambia: el informe ya no puede presentar el hallazgo
	// como vigente. La corrida queda incompleta con la razón explícita y el
	// informe declara la revalidación exigida.
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json")
	if code != 3 || !strings.Contains(errOut, "source_diverged") {
		t.Fatalf("report tras el cambio = %d: %s %s; se esperaba corrida incompleta", code, out, errOut)
	}
	reportMD, err := os.ReadFile(filepath.Join(runDir, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reportMD), "revalidación") {
		t.Fatalf("el informe debe exigir revalidación:\n%s", reportMD)
	}
	code, out, _ = auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json")
	if code != 0 {
		t.Fatalf("status = %d: %s", code, out)
	}
	var status struct {
		Status string `json:"run_status"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != audit.StatusIncomplete {
		t.Fatalf("status = %s, want incomplete", status.Status)
	}
}
