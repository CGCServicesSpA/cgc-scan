package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitRun(t *testing.T, root string, args ...string) string {
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

// gitRepoWithTwoRevisions crea un repositorio real con dos revisiones: en la
// segunda, main.go pierde la línea que la primera cita.
func gitRepoWithTwoRevisions(t *testing.T) (root, revA, revB string) {
	t.Helper()
	root = t.TempDir()
	main := "package main\n\nfunc main() {\n\tdanger()\n}\n"
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "revisión a")
	revA = gitRun(t, root, "rev-parse", "HEAD")

	changed := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "revisión b")
	revB = gitRun(t, root, "rev-parse", "HEAD")
	return root, revA, revB
}

func TestCountLinesDefinesEmptyAndUnterminated(t *testing.T) {
	cases := []struct {
		name string
		data string
		want int
	}{
		{"archivo vacío", "", 0},
		{"una línea con salto", "a\n", 1},
		{"una línea sin salto", "a", 1},
		{"dos líneas, la última sin salto", "a\nb", 2},
		{"dos líneas", "a\nb\n", 2},
		{"solo salto", "\n", 1},
	}
	for _, tc := range cases {
		if got := countLines([]byte(tc.data)); got != tc.want {
			t.Fatalf("%s: countLines = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestSourceRevisionRejectsFabricatedCitations(t *testing.T) {
	root, revA, _ := gitRepoWithTwoRevisions(t)
	src, err := ResolveSource(root, revA, false)
	if err != nil {
		t.Fatalf("resolver fuente: %v", err)
	}
	if src.Info.Mode != SourceModeRevision {
		t.Fatalf("modo = %s, want revision", src.Info.Mode)
	}
	// Línea dentro del snapshot: válida.
	if _, err := src.ResolveLine("main.go", 4); err != nil {
		t.Fatalf("línea válida: %v", err)
	}
	// Línea fuera de rango en el snapshot.
	if _, err := src.ResolveLine("main.go", 9); err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("err = %v, want línea fuera del snapshot", err)
	}
	// Archivo inexistente en la revisión.
	if _, err := src.ResolveLine("noexiste.go", 1); err == nil || !strings.Contains(err.Error(), "no existe en la revisión") {
		t.Fatalf("err = %v, want archivo ausente en la revisión", err)
	}
	// Rutas que escapan de la raíz.
	for _, bad := range []string{"../afuera.go", "/etc/passwd"} {
		if _, err := src.ResolveLine(bad, 1); err == nil {
			t.Fatalf("la cita %q debió rechazarse", bad)
		}
	}
}

func TestHistoricalCitationSurvivesTreeChanges(t *testing.T) {
	root, revA, _ := gitRepoWithTwoRevisions(t)
	src, err := ResolveSource(root, revA, false)
	if err != nil {
		t.Fatalf("resolver fuente: %v", err)
	}
	// El árbol actual ya no tiene la línea 4; la cita histórica sigue
	// resolviéndose contra el snapshot declarado.
	if _, err := src.ResolveLine("main.go", 4); err != nil {
		t.Fatalf("la cita histórica dejó de validar tras cambiar el árbol: %v", err)
	}
}

func TestSourceFromRejectsUnresolvableRevision(t *testing.T) {
	root, _, _ := gitRepoWithTwoRevisions(t)
	_, err := SourceFrom(root, SourceInfo{Mode: SourceModeRevision, Revision: "0123456789abcdef0123456789abcdef01234567"})
	if err == nil || !strings.Contains(err.Error(), "no es resoluble") {
		t.Fatalf("err = %v, want bloqueo explícito por revisión ausente", err)
	}
	_, err = SourceFrom(root, SourceInfo{Mode: "otro"})
	if err == nil || !strings.Contains(err.Error(), "modo de fuente desconocido") {
		t.Fatalf("err = %v, want modo desconocido", err)
	}
}

func TestSourceWorktreeValidatesCurrentTree(t *testing.T) {
	root, _, _ := gitRepoWithTwoRevisions(t)
	src, err := ResolveSource(root, "worktree", true)
	if err != nil {
		t.Fatalf("resolver fuente: %v", err)
	}
	if src.Info.Mode != SourceModeWorktree {
		t.Fatalf("modo = %s, want worktree", src.Info.Mode)
	}
	// El árbol actual perdió la línea 4.
	if _, err := src.ResolveLine("main.go", 4); err == nil || !strings.Contains(err.Error(), "línea") {
		t.Fatalf("err = %v, want línea fuera de rango", err)
	}
	if _, err := src.ResolveLine("main.go", 3); err != nil {
		t.Fatalf("línea vigente: %v", err)
	}
}

func TestWorktreeEscapeViaSymlinkIsRejected(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secreto.go"), []byte("s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secreto.go"), filepath.Join(root, "enlace.go")); err != nil {
		t.Fatal(err)
	}
	src, err := ResolveSource(root, "worktree", false)
	if err != nil {
		t.Fatalf("resolver fuente: %v", err)
	}
	if _, err := src.ResolveLine("enlace.go", 1); err == nil || !strings.Contains(err.Error(), "escapa") {
		t.Fatalf("err = %v, want rechazo por escape", err)
	}
}

// localRecord devuelve un registro válido cuyas citas apuntan a main.go del
// árbol de prueba.
func localRecord(fp, verdict string) Record {
	base := recordFor(fp, verdict)
	base.Trace = []TraceStep{
		{Kind: "entrypoint", File: "main.go", Line: 1, Scope: "main", Description: "recibe la entrada"},
		{Kind: "sink", File: "main.go", Line: 3, Scope: "main", Description: "ejecuta el proceso"},
	}
	base.Evidence = []Evidence{{File: "main.go", Line: 2, Description: "argumento sin validar"}}
	return base
}

func stampingSubmission(agent, unitID string, fps ...string) *Submission {
	sub := huntSubmission(agent, unitID, DispositionCandidate, fps...)
	for _, fp := range fps {
		sub.Candidates = append(sub.Candidates, localRecord(fp, VerdictNeedsValidation))
	}
	return sub
}

func TestSubmitStampsAndDetectsDivergence(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := ResolveSource(root, "worktree", false)
	if err != nil {
		t.Fatalf("resolver fuente: %v", err)
	}
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	stamper := func(fp, role string, record *Record) (map[string]string, error) {
		hashes := map[string]string{}
		for _, f := range CitedFiles(record) {
			hash, err := src.HashFile(f)
			if err != nil {
				return nil, err
			}
			hashes[f] = hash
		}
		return hashes, nil
	}
	// El cazador propone; sin sello, porque su propuesta no se presenta.
	if _, err := SubmitWithOptions(l, c, stampingSubmission("hunter-a", "root/code/sql-injection", "fp-1"), SubmitOptions{Source: stamper}); err != nil {
		t.Fatalf("submit hunt: %v", err)
	}
	if cand := c.CandidateByFingerprint("fp-1"); len(cand.SourceHashes) != 0 {
		t.Fatalf("la propuesta no debió sellarse: %+v", cand.SourceHashes)
	}
	// El verificador degrada el veredicto: el final se sella con la fuente
	// vigente.
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatalf("next verify: %v", err)
	}
	final := localRecord("fp-1", VerdictNeedsValidation)
	if _, err := SubmitWithOptions(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: VerdictNeedsValidation, Record: ptrRecord(final)},
	}, SubmitOptions{Source: stamper}); err != nil {
		t.Fatalf("submit verify: %v", err)
	}
	cand := c.CandidateByFingerprint("fp-1")
	if got := cand.SourceHashes["final:main.go"]; got == "" {
		t.Fatalf("falta el sello del final: %+v", cand.SourceHashes)
	}
	if diverged, err := src.CheckDivergence(c); err != nil || len(diverged) != 0 {
		t.Fatalf("sin cambios no debe haber divergencia: %v %v", diverged, err)
	}

	// El archivo cambia: el hallazgo ya no puede presentarse como vigente.
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("otro contenido\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	diverged, err := src.CheckDivergence(c)
	if err != nil || len(diverged) != 1 || diverged[0].File != "main.go" {
		t.Fatalf("divergencias = %+v err = %v", diverged, err)
	}
}

func TestSubmitStampsEscalatedAndFinalInherits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := ResolveSource(root, "worktree", false)
	if err != nil {
		t.Fatal(err)
	}
	stamper := func(fp, role string, record *Record) (map[string]string, error) {
		hashes := map[string]string{}
		for _, f := range CitedFiles(record) {
			hash, err := src.HashFile(f)
			if err != nil {
				return nil, err
			}
			hashes[f] = hash
		}
		return hashes, nil
	}
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitWithOptions(l, c, stampingSubmission("hunter-a", "root/code/sql-injection", "fp-1"), SubmitOptions{Source: stamper}); err != nil {
		t.Fatal(err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatal(err)
	}
	// El verificador promueve: el registro escalado se sella al crearse.
	if _, err := SubmitWithOptions(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: VerdictConfirmed, Record: ptrRecord(localRecord("fp-1", VerdictConfirmed))},
	}, SubmitOptions{Source: stamper}); err != nil {
		t.Fatal(err)
	}
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateEscalation || cand.SourceHashes["escalated:main.go"] == "" {
		t.Fatalf("el escalado debió sellarse: %+v", cand)
	}
	// El árbol cambia mientras la escalación espera.
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("cambio\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// El segundo verificador confirma el escalado: el final hereda el sello
	// de la fuente con la que ese registro se creó, no la actual.
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitWithOptions(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-b",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}, SubmitOptions{Source: stamper}); err != nil {
		t.Fatal(err)
	}
	if got := cand.SourceHashes["final:main.go"]; got != cand.SourceHashes["escalated:main.go"] {
		t.Fatalf("el final debió heredar el sello del escalado: %+v", cand.SourceHashes)
	}
	// Y la divergencia se declara frente al árbol cambiado.
	diverged, err := src.CheckDivergence(c)
	if err != nil || len(diverged) != 1 {
		t.Fatalf("divergencias = %+v err = %v", diverged, err)
	}
}

func TestCheckDivergenceSkipsUnstampedAndRevisionMode(t *testing.T) {
	// En modo revisión no se exige vigencia actual.
	root, revA, _ := gitRepoWithTwoRevisions(t)
	src, err := ResolveSource(root, revA, false)
	if err != nil {
		t.Fatal(err)
	}
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{{
		Fingerprint: "fp-1", Unit: "root/code/sql-injection", HunterAgent: "hunter-a",
		Proposed: localRecord("fp-1", VerdictConfirmed), State: CandidateDecided,
		Final: ptrRecord(localRecord("fp-1", VerdictConfirmed)), Attempts: []VerificationAttempt{},
	}}}
	l.Units[0].State = StateCandidate
	l.Units[0].Owner = "hunter-a"
	l.Units[0].ReviewedPaths = []string{"main.go"}
	l.Units[0].Checks = []Check{huntCheck("hunter-a")}
	l.Units[0].Candidates = []string{"fp-1"}
	l.Recompute()
	diverged, err := src.CheckDivergence(c)
	if err != nil || len(diverged) != 0 {
		t.Fatalf("el modo revisión no declara divergencias: %+v %v", diverged, err)
	}

	// En worktree, un registro sin sello (estado anterior) no afirma cambios.
	srcW, err := ResolveSource(root, "worktree", true)
	if err != nil {
		t.Fatal(err)
	}
	diverged, err = srcW.CheckDivergence(c)
	if err != nil || len(diverged) != 0 {
		t.Fatalf("un registro sin sello no debe declarar divergencia: %+v %v", diverged, err)
	}
}
