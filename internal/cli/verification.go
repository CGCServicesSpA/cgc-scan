package cli

import (
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// attachVerification adjunta a cada hallazgo la receta de validación de la
// unidad a la que pertenece, el comando de reescaneo y el estado de la
// validación. Una unidad sin receta confirmada queda bloqueada; nunca se
// inventa un comando.
func attachVerification(doc *report.Document, suggested map[string][]normalize.VerificationRecipe) {
	if doc == nil {
		return
	}
	units := append([]report.UnitInfo(nil), doc.Target.Units...)
	// La unidad de proyecto ("." o el objetivo) es el último recurso.
	sort.SliceStable(units, func(i, j int) bool { return len(units[i].Path) > len(units[j].Path) })

	recipesByUnit := map[string][]report.Recipe{}
	for _, r := range doc.Validation.Recipes {
		recipesByUnit[r.Unit] = append(recipesByUnit[r.Unit], r)
	}
	missingByUnit := map[string][]string{}
	for _, u := range doc.Validation.Unresolved {
		missingByUnit[u.Unit] = append(missingByUnit[u.Unit], u.Missing...)
	}

	for i := range doc.Findings {
		f := &doc.Findings[i]
		unit := unitForFinding(f, units)
		v := normalize.Verification{
			Unit:    unit.ID,
			Recipes: []normalize.VerificationRecipe{},
			Missing: []string{},
			Rescan:  rescanCommand(doc, unit.Path),
		}
		has := map[string]bool{}
		for _, r := range recipesByUnit[unit.ID] {
			has[r.Kind] = true
			v.Recipes = append(v.Recipes, normalize.VerificationRecipe{
				Unit: r.Unit, Kind: r.Kind, Command: r.Command,
				Workdir: r.Workdir, Origin: r.Origin,
			})
		}
		for _, kind := range []string{"test", "build"} {
			if !has[kind] {
				v.Missing = append(v.Missing, kind)
			}
		}
		switch {
		case f.Kind == normalize.KindSecret:
			// Un secreto no se valida con tests ni build: exige revocación y
			// rotación confirmadas por el usuario; el reescaneo solo comprueba
			// que ya no aparece en el código.
			v.Recipes = []normalize.VerificationRecipe{}
			v.Missing = []string{}
			v.Status = "blocked"
			v.Note = "Un secreto requiere revocar y rotar la credencial; el reescaneo no valida la rotación."
		case len(v.Missing) == 0:
			v.Status = "ready"
		default:
			v.Status = "blocked"
			for _, kind := range v.Missing {
				for _, candidate := range suggested[unit.ID] {
					if candidate.Kind == kind {
						v.Suggested = append(v.Suggested, candidate)
						break
					}
				}
			}
			if len(v.Suggested) > 0 {
				v.Note = "Faltan recetas confirmadas: " + strings.Join(v.Missing, ", ") +
					". Hay sugerencias detectadas, pero no son de confianza hasta confirmarlas con `cgc-scan recipes --set`."
			} else {
				v.Note = "Faltan recetas confirmadas: " + strings.Join(v.Missing, ", ") +
					". Confírmalas con `cgc-scan recipes --set`; la validación de este hallazgo queda bloqueada."
			}
		}
		if unit.ID == "" && f.Kind != normalize.KindSecret {
			v.Status = "blocked"
			v.Note = "No se pudo asociar el hallazgo a una unidad de proyecto; la validación queda bloqueada."
		}
		f.Verification = &v
	}
}

// unitForFinding elige la unidad más específica que contiene alguna ubicación
// del hallazgo. Si no hay coincidencia, cae en la unidad de proyecto.
func unitForFinding(f *normalize.Finding, units []report.UnitInfo) report.UnitInfo {
	var moduleFallback, projectFallback report.UnitInfo
	for _, u := range units {
		if u.Path != "" && u.Path != "." {
			continue
		}
		if u.ID == "project" {
			projectFallback = u
			continue
		}
		if moduleFallback.ID == "" {
			moduleFallback = u
		}
	}
	for _, loc := range f.Locations {
		for _, u := range units {
			if u.ID == "project" || u.Path == "" || u.Path == "." {
				continue
			}
			if loc.Path == u.Path || strings.HasPrefix(loc.Path, u.Path+"/") {
				return u
			}
		}
	}
	if moduleFallback.ID != "" {
		return moduleFallback
	}
	if projectFallback.ID != "" {
		return projectFallback
	}
	if len(units) > 0 {
		return units[len(units)-1]
	}
	return report.UnitInfo{}
}

// rescanCommand construye el comando para volver a analizar el ámbito de la
// unidad con la modalidad y el modo offline de la ejecución original.
func rescanCommand(doc *report.Document, unitPath string) string {
	target := unitPath
	if target == "" {
		target = "."
	}
	parts := []string{"cgc-scan", "scan", shellQuote(target)}
	if mode, ok := doc.Run.Arguments["trivy_mode"].(string); ok && mode != "" {
		parts = append(parts, "--trivy-mode", shellQuote(mode))
	}
	if offline, ok := doc.Run.Arguments["offline"].(bool); ok && offline {
		parts = append(parts, "--offline")
	}
	parts = append(parts, "--format", "json")
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"$&|;<>()*?[]{}!#~`\\") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
