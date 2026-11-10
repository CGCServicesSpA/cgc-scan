package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

func auditVerifyFlow(t *testing.T) (*App, string, string, string) {
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
	// coverRemainingUnits cubre el resto y responde la verificación pendiente
	// (en quick, needs_validation decide en la misma pasada).
	coverRemainingUnits(t, app, runDir)
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("report = %d: %s %s", code, out, errOut)
	}
	return app, root, runDir, unitID
}

func TestAuditReportVerifyPassesOnSealedReport(t *testing.T) {
	app, _, runDir, _ := auditVerifyFlow(t)
	code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--verify", "--format", "json")
	if code != 0 {
		t.Fatalf("verify = %d: %s %s", code, out, errOut)
	}
	if !strings.Contains(out, "valid") {
		t.Fatalf("verificación inesperada: %s", out)
	}
}

func TestAuditReportVerifyDetectsTampering(t *testing.T) {
	app, _, runDir, _ := auditVerifyFlow(t)
	statePath := filepath.Join(runDir, "state.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	// Alterar los registros en el estado persistido (cambio estructuralmente
	// válido): el título del hallazgo sellado.
	var st map[string]any
	if err := json.Unmarshal(before, &st); err != nil {
		t.Fatal(err)
	}
	findings := st["findings"].(map[string]any)["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("el informe sellado debe llevar registros")
	}
	record := findings[0].(map[string]any)
	record["title"] = "título alterado"
	st["findings"].(map[string]any)["findings"].([]any)[0] = record
	altered, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, append(altered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--verify", "--format", "json")
	if code != 3 || !strings.Contains(errOut, "no verifica") {
		t.Fatalf("verify = %d: %s; se esperaba rechazo por manipulación", code, errOut)
	}
	// La verificación no reescribe el estado alterado.
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "integrity-check-ok") {
		t.Fatal("la verificación no debe reescribir nada")
	}
	if !strings.Contains(string(after), "título alterado") {
		t.Fatal("la verificación debe conservar el contenido alterado intacto")
	}
}

func TestAuditReportVerifyMissingKeyIsExplicit(t *testing.T) {
	app, _, runDir, _ := auditVerifyFlow(t)
	// La clave vive en el directorio de configuración del app; al eliminarla,
	// la verificación produce un diagnóstico explícito y no improvisa otra.
	cfg := app.Paths.ConfigDir
	if err := os.Remove(filepath.Join(cfg, "audit-report.key")); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--verify", "--format", "json")
	if code != 3 || !strings.Contains(errOut, "no existe la clave") {
		t.Fatalf("verify = %d: %s; se esperaba diagnóstico de clave ausente", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(cfg, "audit-report.key")); !os.IsNotExist(err) {
		t.Fatal("verificar no debe crear una clave nueva")
	}
}

func TestAuditReportVerifyReadsUnderSharedLock(t *testing.T) {
	app, _, runDir, _ := auditVerifyFlow(t)
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	// Un lector externo con el bloqueo compartido no impide la verificación.
	held, err := platform.Acquire(context.Background(), store.LockPath(), true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", runDir, "--verify", "--format", "json"); code != 0 {
		t.Fatalf("verify = %d: %s %s", code, out, errOut)
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
}
