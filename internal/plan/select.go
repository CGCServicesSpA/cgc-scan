package plan

import (
	"strings"

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
	// Los patrones de la CLI se interpretan respecto del objetivo del escaneo,
	// mientras que las rutas del reporte son relativas a la raíz detectada.
	prefix := ""
	for _, u := range p.Units {
		if u.Unit.ID == "project" && u.Unit.Path != "." {
			prefix = u.Unit.Path
		}
	}
	candidates := func(unitPath string) []string {
		out := []string{unitPath}
		if prefix != "" {
			if trimmed := strings.TrimPrefix(unitPath, prefix+"/"); trimmed != unitPath {
				out = append(out, trimmed)
			}
		}
		return out
	}
	kept := make([]UnitPlan, 0, len(p.Units))
	for _, u := range p.Units {
		paths := candidates(u.Unit.Path)
		if reason, patterns := excludedUnit(paths, p.Exclusions); reason != "" {
			p.NotAnalyzed = append(p.NotAnalyzed, NotAnalyzed{
				Unit: u.Unit.ID, Path: u.Unit.Path, Reason: reason, Patterns: patterns,
			})
			continue
		}
		if len(p.Include) > 0 && !includedUnit(paths, p.Include) {
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

func excludedUnit(paths []string, ex []discovery.Exclusion) (string, []string) {
	var patterns []string
	for _, e := range ex {
		if !e.Origin.Elected() {
			continue
		}
		for _, u := range paths {
			if matches(e.Pattern, u) {
				patterns = append(patterns, e.Pattern)
				break
			}
		}
	}
	if len(patterns) > 0 {
		return "excluida por la selección de rutas", patterns
	}
	return "", nil
}

func includedUnit(paths []string, patterns []string) bool {
	for _, p := range patterns {
		for _, u := range paths {
			if matches(p, u) || matches(p, u+"/**") || matches(p, u+"/x") {
				return true
			}
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
