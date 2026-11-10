package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
)

func auditProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":                   "module example.test/app\n\ngo 1.27.3\n",
		"main.go":                  "package main\n\nfunc main() {}\n",
		"internal/db/query.go":     "package db\n\nfunc Query() {}\n",
		"Dockerfile":               "FROM scratch\n",
		".env":                     "TOKEN=placeholder\n",
		".github/workflows/ci.yml": "name: ci\n",
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func auditRun(t *testing.T, app *App, args ...string) (int, string, string) {
	t.Helper()
	var code int
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	app.Stdout, app.Stderr = stdout, stderr
	code = app.Execute(context.Background(), args)
	return code, stdout.String(), stderr.String()
}

func writeSubmissionFile(t *testing.T, sub audit.Submission) string {
	t.Helper()
	data, err := json.MarshalIndent(sub, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "submission.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func checksFor(agent string, paths []string) []audit.Check {
	checks := make([]audit.Check, 0, len(paths))
	for _, p := range paths {
		checks = append(checks, audit.Check{
			AgentID: agent, ReviewedPaths: []string{p},
			Invariant: "invariante comprobado", Method: "source", Result: "sin hallazgos",
		})
	}
	return checks
}

func coveredSubmission(agent string, task audit.Task) audit.Submission {
	units := make([]audit.UnitResult, 0, len(task.Units))
	for _, au := range task.Units {
		units = append(units, audit.UnitResult{
			CoverageID:            au.Unit.CoverageID,
			Disposition:           audit.DispositionCovered,
			ReviewedPaths:         au.Unit.StartingPaths,
			Checks:                checksFor(agent, au.Unit.StartingPaths),
			CandidateFingerprints: []string{},
			Unresolved:            []string{},
		})
	}
	return audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       agent,
		Units:         units,
	}
}

func sampleConfirmed(fp string) audit.Record {
	return audit.Record{
		Verdict:          audit.VerdictConfirmed,
		Fingerprint:      fp,
		Title:            "Ejecución de comandos desde entrada no confiable",
		Description:      "La entrada se interpola en la línea de comandos.",
		RootCause:        "Falta una lista cerrada en el punto de decisión.",
		IntendedBehavior: "Solo se aceptan identificadores conocidos.",
		Trace: []audit.TraceStep{
			{Kind: "entrypoint", File: "main.go", Line: 1, Scope: "main", Description: "recibe la entrada"},
			{Kind: "sink", File: "main.go", Line: 3, Scope: "main", Description: "ejecuta el proceso"},
		},
		Evidence:   []audit.Evidence{{File: "main.go", Line: 3, Description: "argumento interpolado"}},
		Conditions: []audit.Condition{},
		Execution: &audit.Execution{
			AttackerPerspective: "usuario autenticado",
			Payloads:            []string{"--target=../x"},
			Instructions:        []string{"invocar el comando con el payload en un entorno local"},
			ObservedResult:      "el proceso recibe el valor sin validar",
		},
		Remediation: &audit.Remediation{Strategy: "validar contra una lista cerrada"},
		Severity: &audit.Severity{
			Likelihood: audit.Score{Score: "medium", Reason: "requiere autenticación"},
			Impact:     audit.Score{Score: "high", Reason: "ejecución de comandos"},
			Overall:    "high",
		},
		Confidence: &audit.Confidence{Score: "high", Reason: "traza completa"},
	}
}

func TestAuditInitAndStatus(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	code, out, errOut := auditRun(t, app, "audit", "init", root,
		"--out", runDir, "--format", "json", "--profile", "quick", "--budget", "20")
	if code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	ledger, err := audit.DecodeLedger([]byte(out))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if ledger.RunStatus != audit.StatusInProgress || ledger.Profile != audit.ProfileQuick {
		t.Fatalf("ledger inesperado: %s/%s", ledger.RunStatus, ledger.Profile)
	}
	if ledger.Summary.UnitsTotal == 0 || ledger.Summary.Planned == 0 {
		t.Fatalf("sin unidades planificadas: %+v", ledger.Summary)
	}
	if ledger.Budget == nil || ledger.Budget.MaxAgentInvocations != 20 {
		t.Fatalf("presupuesto inesperado: %+v", ledger.Budget)
	}
	for _, u := range ledger.Units {
		if len(u.StartingPaths) == 0 {
			t.Fatalf("unidad sin puntos de partida: %s", u.CoverageID)
		}
	}

	code, out, errOut = auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json")
	if code != 0 {
		t.Fatalf("status = %d: %s %s", code, out, errOut)
	}
	var status struct {
		SchemaVersion string `json:"schema_version"`
		Status        string `json:"run_status"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("status json: %v", err)
	}
	if status.SchemaVersion != AuditStatusSchema || status.Status != audit.StatusInProgress {
		t.Fatalf("status inesperado: %+v", status)
	}
}

func TestAuditFullCoveredFlow(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json", "--profile", "quick"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}

	for i := 0; i < 200; i++ {
		code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
			"--agent", "hunter-a", "--max-units", "2", "--format", "json")
		if code != 0 {
			t.Fatalf("next = %d: %s %s", code, out, errOut)
		}
		if !strings.HasPrefix(strings.TrimSpace(out), "{") {
			break
		}
		var task audit.Task
		if err := json.Unmarshal([]byte(out), &task); err != nil {
			t.Fatalf("task: %v\n%s", err, out)
		}
		if task.Kind != "hunt" || len(task.Units) == 0 {
			t.Fatalf("tarea inesperada: %+v", task)
		}
		file := writeSubmissionFile(t, coveredSubmission("hunter-a", task))
		if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir,
			"--file", file, "--format", "json"); code != 0 {
			t.Fatalf("submit = %d: %s %s", code, out, errOut)
		}
	}

	code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json")
	if code != 0 {
		t.Fatalf("report = %d: %s %s", code, out, errOut)
	}
	var summary struct {
		SchemaVersion string                `json:"schema_version"`
		Status        string                `json:"status"`
		Findings      audit.FindingsSummary `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		t.Fatalf("report json: %v", err)
	}
	if summary.SchemaVersion != AuditReportSchema || summary.Status != audit.StatusComplete {
		t.Fatalf("informe inesperado: %+v", summary)
	}
	if summary.Findings.Confirmed != 0 {
		t.Fatalf("no debería haber confirmados: %+v", summary.Findings)
	}
	for _, name := range []string{"findings.json", "REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("falta %s: %v", name, err)
		}
	}
}

func TestAuditCandidateVerificationFlow(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json", "--profile", "quick"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}

	code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json")
	if code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	var task audit.Task
	if err := json.Unmarshal([]byte(out), &task); err != nil {
		t.Fatalf("task: %v", err)
	}
	if len(task.Units) != 1 {
		t.Fatalf("se esperaba una unidad: %+v", task)
	}
	unit := task.Units[0].Unit
	record := sampleConfirmed("fp-1")
	sub := audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       "hunter-a",
		Units: []audit.UnitResult{{
			CoverageID:            unit.CoverageID,
			Disposition:           audit.DispositionCandidate,
			ReviewedPaths:         unit.StartingPaths,
			Checks:                checksFor("hunter-a", unit.StartingPaths),
			CandidateFingerprints: []string{"fp-1"},
			Unresolved:            []string{},
		}},
		Candidates: []audit.Record{record},
	}
	file := writeSubmissionFile(t, sub)
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file); code != 0 {
		t.Fatalf("submit hunt = %d: %s %s", code, out, errOut)
	}

	// El cazador no puede verificarse a sí mismo.
	if code, _, _ := auditRun(t, app, "audit", "next", "--out", runDir, "--agent", "hunter-a"); code != 3 {
		t.Fatalf("el cazador debía ser rechazado, código %d", code)
	}

	code, out, errOut = auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "verifier-a", "--format", "json")
	if code != 0 {
		t.Fatalf("next verify = %d: %s %s", code, out, errOut)
	}
	var verifyTask audit.Task
	if err := json.Unmarshal([]byte(out), &verifyTask); err != nil {
		t.Fatalf("verify task: %v", err)
	}
	if verifyTask.Kind != audit.ModeVerify || verifyTask.Candidate == nil {
		t.Fatalf("tarea de verificación inesperada: %+v", verifyTask)
	}
	verifyFile := writeSubmissionFile(t, audit.Submission{
		SchemaVersion: audit.SubmissionSchemaVersion,
		AgentID:       "verifier-a",
		Verification: &audit.Verification{
			Fingerprint: "fp-1", Decision: audit.VerdictConfirmed, Record: &record,
		},
	})
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", verifyFile); code != 0 {
		t.Fatalf("submit verify = %d: %s %s", code, out, errOut)
	}

	code, out, errOut = auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json")
	if code != 3 {
		t.Fatalf("report = %d, se esperaba 3 por unidades planificadas: %s %s", code, out, errOut)
	}
	var summary struct {
		Status     string                `json:"status"`
		Incomplete string                `json:"incomplete_reason"`
		Findings   audit.FindingsSummary `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		t.Fatalf("report json: %v", err)
	}
	if summary.Findings.Confirmed != 1 {
		t.Fatalf("se esperaba un confirmado: %+v", summary.Findings)
	}
	if summary.Status != audit.StatusIncomplete || summary.Incomplete != audit.IncompleteUnassigned {
		t.Fatalf("estado inesperado: %+v", summary)
	}
	report, err := os.ReadFile(filepath.Join(runDir, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "Ejecución de comandos desde entrada no confiable") {
		t.Fatalf("el informe no contiene el hallazgo:\n%s", report)
	}
	if !strings.Contains(string(report), "Corrida incompleta") {
		t.Fatalf("el informe debe declarar la corrida incompleta:\n%s", report)
	}
}

func TestAuditReportWithoutWorkIsIncomplete(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json", "--profile", "quick"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json")
	if code != 3 {
		t.Fatalf("report = %d, want 3: %s %s", code, out, errOut)
	}
	var summary struct {
		Status     string `json:"status"`
		Incomplete string `json:"incomplete_reason"`
	}
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Status != audit.StatusIncomplete || summary.Incomplete != audit.IncompleteUnassigned {
		t.Fatalf("estado inesperado: %+v", summary)
	}
	findings, err := os.ReadFile(filepath.Join(runDir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(findings), `"findings": []`) {
		t.Fatalf("findings.json debe estar vacío:\n%s", findings)
	}
}

func TestAuditInitHonorsExclusions(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "tool.go"), []byte("package docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "go.mod"), []byte("module example.test/docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(t.TempDir(), "run")
	code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir,
		"--format", "json", "--exclude", "docs/**")
	if code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	ledger, err := audit.DecodeLedger([]byte(out))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	foundOOS := false
	for _, u := range ledger.Units {
		if u.Subsystem == "docs" && u.State == audit.StateOutOfScope {
			foundOOS = true
		}
		if u.Subsystem == "docs" && u.State == audit.StatePlanned {
			t.Fatalf("la unidad excluida no puede planificarse: %s", u.CoverageID)
		}
	}
	if !foundOOS {
		t.Fatalf("falta la unidad out_of_scope para docs: %+v", ledger.Summary)
	}
}

func TestAuditInitExposesPriorAsContext(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	first := filepath.Join(t.TempDir(), "run-1")
	second := filepath.Join(t.TempDir(), "run-2")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", first, "--format", "json"); code != 0 {
		t.Fatalf("init 1 = %d: %s %s", code, out, errOut)
	}
	code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", second,
		"--format", "json", "--prior", first)
	if code != 0 {
		t.Fatalf("init 2 = %d: %s %s", code, out, errOut)
	}
	ledger, err := audit.DecodeLedger([]byte(out))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if ledger.Prior == nil {
		t.Fatal("falta el contexto de la corrida anterior")
	}
	if ledger.Prior.SameRevisionClean {
		t.Fatal("sin revisión de Git no puede declararse misma fuente")
	}
	for _, u := range ledger.Units {
		if u.State != audit.StatePlanned {
			t.Fatalf("el contexto previo no puede suprimir %s (%s)", u.CoverageID, u.State)
		}
	}
}

func TestAuditSubmitRejectsMalformedSubmission(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json", "--profile", "quick"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"otra"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, _ := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", path)
	if code != 2 {
		t.Fatalf("submit = %d, want 2", code)
	}
}

func TestAuditBudgetExhaustionIsIncomplete(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir,
		"--format", "json", "--profile", "quick", "--budget", "2"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json")
	if code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	var task audit.Task
	if err := json.Unmarshal([]byte(out), &task); err != nil {
		t.Fatal(err)
	}
	file := writeSubmissionFile(t, coveredSubmission("hunter-a", task))
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir, "--file", file); code != 0 {
		t.Fatalf("submit = %d: %s %s", code, out, errOut)
	}
	code, _, _ = auditRun(t, app, "audit", "next", "--out", runDir, "--agent", "hunter-a", "--max-units", "1")
	if code != 3 {
		t.Fatalf("next = %d, want 3 por presupuesto", code)
	}
	code, out, errOut = auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json")
	if code != 0 {
		t.Fatalf("status = %d: %s %s", code, out, errOut)
	}
	var status struct {
		Status     string `json:"run_status"`
		Incomplete string `json:"incomplete_reason"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != audit.StatusIncomplete || status.Incomplete != "budget_exhausted" {
		t.Fatalf("estado inesperado: %+v", status)
	}
}
