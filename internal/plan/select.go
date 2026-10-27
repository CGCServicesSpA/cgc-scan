package plan

import (
	"github.com/bmatcuk/doublestar/v4"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

// ApplySelection recorta el plan según --include y las exclusiones elegidas.
// Las exclusiones prevalecen sobre las inclusiones; las intrínsecas no
// participan aquí porque no hay unidades dentro de ellas. Las unidades que no
// sobreviven quedan en coverage.not_analyzed (design §9.4).
func ApplySelection(p *Plan) {
	if len(p.Include) == 0 && !hasElected(p.Exclusions) {
		return
	}
	// Un --include marca el escaneo como parcial aunque todas las unidades
	// sobrevivan: el universo se restringió.
	if len(p.Include) > 0 {
		p.Partial = true
	}
	kept := make([]UnitPlan, 0, len(p.Units))
	for _, u := range p.Units {
		if reason, patterns := excludedUnit(u.Unit.Path, p.Exclusions); reason != "" {
			p.NotAnalyzed = append(p.NotAnalyzed, NotAnalyzed{
				Unit: u.Unit.ID, Path: u.Unit.Path, Reason: reason, Patterns: patterns,
			})
			continue
		}
		if len(p.Include) > 0 && !includedUnit(u.Unit.Path, p.Include) {
			p.NotAnalyzed = append(p.NotAnalyzed, NotAnalyzed{
				Unit: u.Unit.ID, Path: u.Unit.Path, Reason: "fuera de --include", Patterns: p.Include,
			})
			continue
		}
		kept = append(kept, u)
	}
	p.Units = kept
}

func hasElected(ex []discovery.Exclusion) bool {
	for _, e := range ex {
		if e.Origin.Elected() {
			return true
		}
	}
	return false
}

func excludedUnit(unitPath string, ex []discovery.Exclusion) (string, []string) {
	var patterns []string
	for _, e := range ex {
		if !e.Origin.Elected() {
			continue
		}
		if matches(e.Pattern, unitPath) {
			patterns = append(patterns, e.Pattern)
		}
	}
	if len(patterns) > 0 {
		return "excluida por la selección de rutas", patterns
	}
	return "", nil
}

func includedUnit(unitPath string, patterns []string) bool {
	for _, p := range patterns {
		if matches(p, unitPath) || matches(p, unitPath+"/**") {
			return true
		}
		// Un patrón que apunta a un archivo dentro de la unidad también la
		// incluye, porque los motores reciben la unidad completa.
		if matches(p, unitPath+"/x") {
			return true
		}
	}
	return false
}

func matches(pattern, path string) bool {
	ok, err := doublestar.Match(pattern, path)
	if err != nil {
		return false
	}
	if ok {
		return true
	}
	// Los patrones de directorio (`docs/**`) también excluyen la unidad
	// `docs` sin barra final.
	if len(pattern) > 3 && pattern[len(pattern)-3:] == "/**" {
		base := pattern[:len(pattern)-3]
		ok, _ = doublestar.Match(base, path)
		return ok
	}
	return false
}
