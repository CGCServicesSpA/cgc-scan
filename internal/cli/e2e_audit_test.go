package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
)

// gitRepoFixture crea un repositorio Git real con una revisión inicial limpia.
func gitRepoFixture(t *testing.T) string {
	t.Helper()
	root := auditProject(t)
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", root,
			"-c", "user.email=t@t", "-c", "user.name=t",
			"-c", "commit.gpgsign=false"}, args...)...)
		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "revisión inicial")
	return root
}

// TestAuditE2EGitFromInitToReport cubre el flujo completo con repositorio Git
// real: init, recuperación de unidad abandonada, verificación, informe con
// integridad, revalidación con continuidad y corrida incompleta. No necesita
// red ni proveedor de IA.
func TestAuditE2EGitFromInitToReport(t *testing.T) {
	root := gitRepoFixture(t)
	first := filepath.Join(t.TempDir(), "run-1")
	app, _, _ := newTestApp(t)

	// 1. init sobre el árbol limpio del repositorio.
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", first, "--format", "json", "--profile", "quick"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", first,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	unitID := firstUnitID(t, first)

	// 2. Recuperación: la unidad abandonada se archiva y otro agente la
	// recibe con la ola siguiente.
	if code, out, errOut := auditRun(t, app, "audit", "reset-unit", "--out", first,
		"--coverage-id", unitID, "--reason", "el agente abandonó la corrida"); code != 0 {
		t.Fatalf("reset-unit = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", first,
		"--agent", "hunter-b", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next hunter-b = %d: %s %s", code, out, errOut)
	}
	store, err := audit.OpenStore(first)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	u := st.Ledger.UnitByID(unitID)
	if u.Owner != "hunter-b" || u.Wave != 2 || len(u.Attempts) != 1 || u.Attempts[0].State != audit.StateBlocked {
		t.Fatalf("recuperación inesperada: %+v", u)
	}

	// 3. Verificación completa y informe sellado con integridad.
	file := candidateSubmissionFile(t, "hunter-b", unitID, "fp-1", sampleNeedsValidation("fp-1"))
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", first, "--file", file); code != 0 {
		t.Fatalf("submit = %d: %s %s", code, out, errOut)
	}
	coverRemainingUnits(t, app, first)
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", first, "--format", "json"); code != 0 {
		t.Fatalf("report = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "report", "--out", first, "--verify", "--format", "json"); code != 0 {
		t.Fatalf("verify = %d: %s %s", code, out, errOut)
	}

	// 4. Revalidación: una segunda corrida con --prior expone la continuidad
	// verificable (misma revisión, ambos árboles limpios).
	second := filepath.Join(t.TempDir(), "run-2")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", second,
		"--format", "json", "--profile", "quick", "--prior", first); code != 0 {
		t.Fatalf("init 2 = %d: %s %s", code, out, errOut)
	}
	st2, err := func() (*audit.RunState, error) {
		s, err := audit.OpenStore(second)
		if err != nil {
			return nil, err
		}
		return s.LoadState()
	}()
	if err != nil {
		t.Fatal(err)
	}
	if st2.Ledger.Prior == nil || st2.Ledger.Prior.RunID != st.Ledger.Run.ID {
		t.Fatalf("falta la continuidad con la corrida anterior: %+v", st2.Ledger.Prior)
	}
	// Misma revisión y ambos árboles limpios: la fuente es la misma y limpia.
	if !st2.Ledger.Prior.SameRevisionClean {
		t.Fatalf("con la misma revisión limpia la fuente debe orientar la prioridad: %+v", st2.Ledger.Prior)
	}
	// La cobertura no se suprime: todas las unidades siguen planificadas.
	for _, unit := range st2.Ledger.Units {
		if unit.State != audit.StatePlanned {
			t.Fatalf("el contexto previo no puede suprimir %s (%s)", unit.CoverageID, unit.State)
		}
	}

	// 5. Corrida incompleta: init sin caza y report devuelven código 3.
	third := filepath.Join(t.TempDir(), "run-3")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", third, "--format", "json"); code != 0 {
		t.Fatalf("init 3 = %d: %s %s", code, out, errOut)
	}
	code, _, errOut := auditRun(t, app, "audit", "report", "--out", third)
	if code != 3 || !strings.Contains(errOut, "incompleta") {
		t.Fatalf("report incompleto = %d: %s; want 3", code, errOut)
	}
	// Y la comparación entre corridas no las modifica.
	code, cmpOut, _ := auditRun(t, app, "audit", "compare", first, second, "--format", "json")
	if code != 0 {
		t.Fatalf("compare = %d", code)
	}
	var cmpDoc struct {
		Entries []struct{ Classification string } `json:"entries"`
	}
	if err := json.Unmarshal([]byte(cmpOut), &cmpDoc); err != nil {
		t.Fatal(err)
	}
	if len(cmpDoc.Entries) != 0 {
		t.Fatalf("corridas sin cobertura no producen entradas: %+v", cmpDoc.Entries)
	}
	_ = time.Now
	_ = os.Environ
}
