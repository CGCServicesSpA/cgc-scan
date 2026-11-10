package audit

import (
	"strings"
	"testing"
)

// buildForProfile construye el ledger de un proyecto para un perfil dado.
func buildForProfile(t *testing.T, root, profile string) *Ledger {
	t.Helper()
	return buildForTestProfile(t, root, nil, profile)
}

func TestProfilesProduceJustifiedDifferences(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.27.3\n",
		"go.sum":  "",
		"main.go": "package main\n\nfunc main() {}\n",
	})

	quick := buildForProfile(t, root, ProfileQuick)
	standard := buildForProfile(t, root, ProfileStandard)
	deep := buildForProfile(t, root, ProfileDeep)

	// quick colapsa por subsistema × dominio: una unidad por dominio.
	quickIDs := coverageIDs(quick)
	for _, u := range quick.Units {
		if u.Boundary != "domain-wide" {
			t.Fatalf("quick debe agrupar por dominio: %+v", u)
		}
		segments := strings.Split(u.CoverageID, "/")
		if len(segments) != 2 {
			t.Fatalf("quick: coverage_id debe ser subsistema/dominio: %s", u.CoverageID)
		}
	}
	if !contains(quickIDs, "root/code") {
		t.Fatalf("quick: falta la unidad del dominio code: %v", quickIDs)
	}

	// standard reparte por clase: los ids existentes no cambian.
	if !contains(coverageIDs(standard), "root/code/sql-injection") {
		t.Fatalf("standard: falta la unidad por clase: %v", coverageIDs(standard))
	}

	// deep colapsa por ciclo de vida.
	for _, u := range deep.Units {
		if u.Domain != "lifecycle" {
			t.Fatalf("deep debe agrupar por ciclo de vida: %+v", u)
		}
		if !strings.Contains(u.CoverageID, "/lifecycle/") {
			t.Fatalf("deep: coverage_id debe ser subsistema/lifecycle/etapa: %s", u.CoverageID)
		}
	}
	if !containsSuffix(deep.Units, "/lifecycle/runtime") {
		t.Fatalf("deep: falta la etapa runtime: %v", coverageIDs(deep))
	}

	// Las granularidades difieren entre sí con el mismo fixture.
	if len(quick.Units) == len(standard.Units) && len(standard.Units) == len(deep.Units) {
		t.Fatalf("los tres perfiles producen la misma cantidad de unidades: %d", len(standard.Units))
	}
	if len(standard.Units) <= len(quick.Units) {
		t.Fatalf("standard debe producir más unidades que quick: %d vs %d",
			len(standard.Units), len(quick.Units))
	}

	for name, ledger := range map[string]*Ledger{"quick": quick, "standard": standard, "deep": deep} {
		if err := ValidateLedgerSemantics(ledger); err != nil {
			t.Fatalf("%s: ledger inválido: %v", name, err)
		}
	}
}

func TestProfileLedgersAreDeterministic(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.27.3\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	for _, profile := range []string{ProfileQuick, ProfileStandard, ProfileDeep} {
		first := buildForProfile(t, root, profile)
		second := buildForProfile(t, root, profile)
		a, err := first.JSON()
		if err != nil {
			t.Fatal(err)
		}
		b, err := second.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("%s: el reparto no es determinista:\n%s\n---\n%s", profile, a, b)
		}
	}
}

func TestProfilePolicyPhases(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	quick, err := ProfilePolicyFor(ProfileQuick, cat)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(quick.MandatoryPhases(), ","); got != "hunt,verification" {
		t.Fatalf("quick: fases = %s", got)
	}
	if len(quick.UnimplementedPhases()) != 0 {
		t.Fatalf("quick no debe exigir fases pendientes: %v", quick.UnimplementedPhases())
	}
	standard, _ := ProfilePolicyFor(ProfileStandard, cat)
	if got := strings.Join(standard.MandatoryPhases(), ","); got != "hunt,verification,final-critique" {
		t.Fatalf("standard: fases = %s", got)
	}
	deep, _ := ProfilePolicyFor(ProfileDeep, cat)
	if got := strings.Join(deep.MandatoryPhases(), ","); got != "hunt,verification,final-critique,prior-rework" {
		t.Fatalf("deep: fases = %s", got)
	}
	var pending []string
	for _, phase := range deep.UnimplementedPhases() {
		pending = append(pending, phase)
	}
	if len(pending) != 0 {
		t.Fatalf("las fases del protocolo están entregadas; quedan pendientes: %v", pending)
	}
}

func TestBuildFindingsHonorsProfilePhases(t *testing.T) {
	// quick sella completa con una pasada de verificación.
	l, c := sealedFixture(t)
	if _, err := BuildFindings(l, c); err != nil {
		t.Fatalf("build quick: %v", err)
	}
	if l.RunStatus != StatusComplete {
		t.Fatalf("quick = %s/%s, want complete", l.RunStatus, l.IncompleteReason)
	}

	// standard exige la crítica final limpia: una corrida sin crítica
	// completada queda pendiente.
	l2, c2 := sealedFixture(t)
	l2.Profile = ProfileStandard
	l2.Recompute()
	if _, err := BuildFindings(l2, c2); err != nil {
		t.Fatalf("build standard: %v", err)
	}
	if l2.RunStatus != StatusIncomplete || l2.IncompleteReason != IncompleteCritiquePending {
		t.Fatalf("standard = %s/%s, want incomplete/critique_pending", l2.RunStatus, l2.IncompleteReason)
	}

	// deep exige prior-rework: una corrida con confirmados previos con la
	// fuente cambiada queda pendiente de revalidación (probada con la
	// continuidad); sin corrida previa, cierra con crítica limpia.
	l3, c3 := sealedFixture(t)
	l3.Profile = ProfileDeep
	l3.Critique = &CritiqueState{FinalClean: true}
	l3.Recompute()
	if _, err := BuildFindings(l3, c3); err != nil {
		t.Fatalf("build deep: %v", err)
	}
	if l3.RunStatus != StatusComplete {
		t.Fatalf("deep sin corrida previa debe completar con crítica limpia: %s/%s",
			l3.RunStatus, l3.IncompleteReason)
	}
}

func TestCatalogProfilesAreVersioned(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	if cat.SchemaVersion != "audit-catalog-1.1.0" {
		t.Fatalf("esquema = %q, want audit-catalog-1.1.0", cat.SchemaVersion)
	}
	if !strings.HasPrefix(cat.SourceVersion, "cloudflare/security-audit-skill@") {
		t.Fatalf("la referencia externa no está fijada: %q", cat.SourceVersion)
	}
	// Cada clase declara su ciclo de vida con vocabulario conocido.
	for _, class := range cat.Classes {
		if !knownLifecycles[class.Lifecycle] {
			t.Fatalf("clase %s con ciclo de vida desconocido %q", class.ID, class.Lifecycle)
		}
	}
}

func coverageIDs(l *Ledger) []string {
	out := make([]string, 0, len(l.Units))
	for _, u := range l.Units {
		out = append(out, u.CoverageID)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func containsSuffix(units []Unit, want string) bool {
	for _, u := range units {
		if strings.HasSuffix(u.CoverageID, want) {
			return true
		}
	}
	return false
}
