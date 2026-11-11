package audit

import (
	"strings"
	"testing"
)

// Fixture positivo de http-framing-desync / host-header-trust: un árbol con
// capa de servidor HTTP reconocible (middleware, handlers, rutas).
func webServerProject() map[string]string {
	return map[string]string{
		"go.mod":                        "module example.test/web\n\ngo 1.27.3\n",
		"cmd/server/main.go":            "package main\n\nfunc main() {}\n",
		"internal/http/middleware.go":   "package httpmw\n\nfunc Auth() {}\n",
		"internal/http/handler_user.go": "package handlers\n\nfunc User() {}\n",
		"internal/http/routes.go":       "package handlers\n\nfunc Routes() {}\n",
	}
}

// Fixture negativo: un árbol sin capa HTTP reconocible (CLI puro).
func cliOnlyProject() map[string]string {
	return map[string]string{
		"go.mod":            "module example.test/cli\n\ngo 1.27.3\n",
		"main.go":           "package main\n\nfunc main() {}\n",
		"internal/fs/fs.go": "package fs\n\nfunc Read() {}\n",
	}
}

func classByIDIn(ledger *Ledger, id string) bool {
	for _, u := range ledger.Units {
		if u.AttackClass == id {
			return true
		}
	}
	return false
}

func TestWebClassesActivateOnHTTPServerSignal(t *testing.T) {
	positive := buildForTestProfile(t, writeProject(t, webServerProject()), nil, ProfileStandard)
	// Con capa HTTP reconocible, las clases del dominio web activan unidades.
	for _, class := range []string{"http-framing-desync", "host-header-trust"} {
		if !classByIDIn(positive, class) {
			t.Fatalf("la clase %s debió activarse con la señal http_server", class)
		}
	}
	if err := ValidateLedgerSemantics(positive); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestWebClassesDoNotActivateWithoutSignal(t *testing.T) {
	negative := buildForTestProfile(t, writeProject(t, cliOnlyProject()), nil, ProfileStandard)
	// Sin capa HTTP reconocible, las clases del dominio web no aparecen: la
	// ausencia de señales no se presenta como cobertura.
	for _, class := range []string{"http-framing-desync", "web-cache-unkeyed-input", "host-header-trust"} {
		if classByIDIn(negative, class) {
			t.Fatalf("la clase %s no debió activarse sin señal", class)
		}
	}
}

func TestCacheClassRequiresCacheSignal(t *testing.T) {
	// Proyecto con servidor HTTP pero sin capa de caché: la clase de caché no
	// aparece aunque otras del dominio web sí.
	files := webServerProject()
	files["internal/http/handler_user.go"] = "package handlers\n\nfunc User() {}\n"
	ledger := buildForTestProfile(t, writeProject(t, files), nil, ProfileStandard)
	if classByIDIn(ledger, "web-cache-unkeyed-input") {
		t.Fatal("la clase de caché no debió activarse sin señal de caché")
	}
	if !classByIDIn(ledger, "http-framing-desync") {
		t.Fatal("las clases de framing sí debieron activarse")
	}
}

func TestResourceClassesActivateOnAnySource(t *testing.T) {
	// Las clases de recursos requieren la señal source, presente en todo
	// proyecto con código fuente.
	ledger := buildForTestProfile(t, writeProject(t, cliOnlyProject()), nil, ProfileStandard)
	for _, class := range []string{"superlinear-parsing", "unbounded-accumulation"} {
		if !classByIDIn(ledger, class) {
			t.Fatalf("la clase %s debió activarse en un proyecto con fuente", class)
		}
	}
}

func TestNewClassesDeterministicOrderAcrossProfiles(t *testing.T) {
	root := writeProject(t, webServerProject())
	for _, profile := range []string{ProfileQuick, ProfileStandard, ProfileDeep} {
		first := buildForTestProfile(t, root, nil, profile)
		second := buildForTestProfile(t, root, nil, profile)
		a, err := first.JSON()
		if err != nil {
			t.Fatal(err)
		}
		b, err := second.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("%s: reparto no determinista", profile)
		}
		// El orden de unidades es determinista: coverage_ids ordenados.
		for i := 1; i < len(first.Units); i++ {
			if first.Units[i-1].CoverageID >= first.Units[i].CoverageID {
				t.Fatalf("%s: unidades desordenadas en %d", profile, i)
			}
		}
	}
}

func TestNewClassCatalogEntriesAreWellFormed(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"http-framing-desync", "web-cache-unkeyed-input", "host-header-trust", "superlinear-parsing", "unbounded-accumulation"} {
		class := cat.ClassByID(id)
		if class == nil {
			t.Fatalf("falta la clase %s en el catálogo", id)
		}
		if !strings.HasPrefix(class.Source, "companions/") {
			t.Fatalf("la clase %s debe trazarse a su companion: %q", id, class.Source)
		}
		if !knownLifecycles[class.Lifecycle] {
			t.Fatalf("clase %s con ciclo de vida inválido", id)
		}
	}
}
