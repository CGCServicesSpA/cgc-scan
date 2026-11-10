package audit

import (
	"strings"
	"testing"
)

func TestReconcileMergesSameRootCause(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
		candDecidedWithKey("fp-a", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed, "rc-1"),
		candDecidedWithKey("fp-b", l.Units[1].CoverageID, "hunter-b", VerdictConfirmed, "rc-1"),
	}}

	out := Reconcile(c)
	if len(out) != 1 {
		t.Fatalf("una consolidación esperada: %+v", out)
	}
	con := out[0]
	if con.Key != "rc-1" || con.Representative != "fp-a" {
		t.Fatalf("el representante debe ser el menor fingerprint: %+v", con)
	}
	if len(con.Alternates) != 1 || con.Alternates[0] != "fp-b" {
		t.Fatalf("la variante absorbida debe archivarse: %+v", con)
	}
	if !strings.Contains(con.Reason, "mayor veredicto") || !strings.Contains(con.Reason, "fp-b") {
		t.Fatalf("el motivo debe registrar desempate y variantes: %q", con.Reason)
	}
	merged := c.CandidateByFingerprint("fp-b")
	if merged.MergedInto != "fp-a" {
		t.Fatalf("la relación de consolidación debe conservarse: %+v", merged)
	}
}

func TestReconcileKeepsDifferentRootCausesApart(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
		candDecidedWithKey("fp-a", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed, "rc-1"),
		candDecidedWithKey("fp-b", l.Units[1].CoverageID, "hunter-b", VerdictConfirmed, "rc-2"),
	}}
	// Títulos similares, claves distintas: no confluyen.
	c.Items[1].Final.Title = c.Items[0].Final.Title

	if out := Reconcile(c); len(out) != 0 {
		t.Fatalf("defectos distintos no se consolidan: %+v", out)
	}
	if c.CandidateByFingerprint("fp-b").MergedInto != "" {
		t.Fatal("ninguna variante debe marcarse absorbida")
	}
}

func TestReconcileIsOrderIndependent(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	build := func() *Candidates {
		return &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
			candDecidedWithKey("fp-b", l.Units[1].CoverageID, "hunter-b", VerdictConfirmed, "rc-1"),
			candDecidedWithKey("fp-a", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed, "rc-1"),
		}}
	}
	_ = build
	first := Reconcile(build())
	// El mismo estado con las filas invertidas produce el mismo resultado.
	inverted := build()
	inverted.Items[0], inverted.Items[1] = inverted.Items[1], inverted.Items[0]
	second := Reconcile(inverted)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("consolidaciones: %+v %+v", first, second)
	}
	if first[0].Representative != second[0].Representative ||
		first[0].Reason != second[0].Reason {
		t.Fatalf("el orden de entrada cambió el resultado: %+v vs %+v", first[0], second[0])
	}
}

func TestReconcilePrefersConfirmedAndFingerprint(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	// fp-c es rejected (menor rango); fp-a y fp-b confirmed: gana el menor.
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
		candDecidedWithKey("fp-c", l.Units[1].CoverageID, "hunter-c", VerdictRejected, "rc-1"),
		candDecidedWithKey("fp-b", l.Units[1].CoverageID, "hunter-b", VerdictConfirmed, "rc-1"),
		candDecidedWithKey("fp-a", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed, "rc-1"),
	}}
	out := Reconcile(c)
	if len(out) != 1 || out[0].Representative != "fp-a" {
		t.Fatalf("el representante debe ser confirmed con menor fingerprint: %+v", out)
	}
}

func TestBuildFindingsConsolidatesVariants(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	l.Profile = ProfileQuick
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
		candDecidedWithKey("fp-a", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed, "rc-1"),
		candDecidedWithKey("fp-b", l.Units[1].CoverageID, "hunter-b", VerdictConfirmed, "rc-1"),
	}}
	l.Units[0].State = StateCandidate
	l.Units[0].Owner = "hunter-a"
	l.Units[0].ReviewedPaths = []string{"main.go"}
	l.Units[0].Checks = []Check{huntCheck("hunter-a")}
	l.Units[0].Candidates = []string{"fp-a"}
	l.Units[1].State = StateCandidate
	l.Units[1].Owner = "hunter-b"
	l.Units[1].ReviewedPaths = []string{"main.go"}
	l.Units[1].Checks = []Check{huntCheck("hunter-b")}
	l.Units[1].Candidates = []string{"fp-b"}
	l.Recompute()

	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(f.Findings) != 1 || f.Findings[0].Fingerprint != "fp-a" {
		t.Fatalf("solo el registro representativo entra al documento: %+v", f.Findings)
	}
	merged := false
	for _, lim := range l.Limitations {
		if strings.Contains(lim, "consolidado") && strings.Contains(lim, "fp-b") {
			merged = true
		}
	}
	if !merged {
		t.Fatalf("la consolidación debe declararse: %v", l.Limitations)
	}
}

func TestReconciliationValidatesAgainstContract(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
		candDecidedWithKey("fp-a", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed, "rc-1"),
		candDecidedWithKey("fp-b", l.Units[1].CoverageID, "hunter-b", VerdictConfirmed, "rc-1"),
	}}
	l.Units[0].State = StateCandidate
	l.Units[0].Owner = "hunter-a"
	l.Units[0].ReviewedPaths = []string{"main.go"}
	l.Units[0].Checks = []Check{huntCheck("hunter-a")}
	l.Units[0].Candidates = []string{"fp-a"}
	l.Units[1].State = StateCandidate
	l.Units[1].Owner = "hunter-b"
	l.Units[1].ReviewedPaths = []string{"main.go"}
	l.Units[1].Checks = []Check{huntCheck("hunter-b")}
	l.Units[1].Candidates = []string{"fp-b"}
	l.Recompute()
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("estado con clave de consolidación debe validar: %v", err)
	}
	Reconcile(c)
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("el estado consolidado debe seguir validando: %v", err)
	}
}

// candDecidedWithKey crea un candidato decidido con clave de consolidación.
func candDecidedWithKey(fp, unit, hunter, verdict, key string) Candidate {
	cand := candDecided(fp, unit, hunter, verdict)
	cand.ConsolidationKey = key
	return cand
}
