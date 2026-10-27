package report

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Emit escribe el resultado en el formato pedido. Es el único punto que
// escribe en stdout (design §10.2).
func Emit(w io.Writer, doc *Document, format string) error {
	switch format {
	case "json":
		data, err := RenderJSON(doc)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	case "text":
		_, err := io.WriteString(w, RenderText(doc))
		return err
	case "prompt":
		return fmt.Errorf("el formato prompt se habilita en H5")
	default:
		return fmt.Errorf("formato desconocido: %q", format)
	}
}

// RenderText produce una salida legible, sin color ni Unicode decorativo.
func RenderText(doc *Document) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "CGC Scan %s - %s\n", doc.Run.CLIVersion, doc.Target.Root)
	fmt.Fprintf(&b, "Ejecucion: %s (%s)\n", doc.Run.ID, doc.Run.StartedAt)

	if doc.Coverage.Partial {
		fmt.Fprintln(&b, "Cobertura: PARCIAL")
	} else {
		fmt.Fprintln(&b, "Cobertura: COMPLETA")
	}
	counts := map[string]int{}
	for _, u := range doc.Coverage.Units {
		counts[u.Status]++
	}
	fmt.Fprintf(&b, "Unidades: %d (completadas %d, omitidas %d, fallidas %d)\n",
		len(doc.Coverage.Units), counts["completed"], counts["skipped"], counts["failed"])
	if doc.Coverage.Partial {
		fmt.Fprintf(&b, "No analizado: %d unidades\n", len(doc.Coverage.NotAnalyzed))
		for _, n := range doc.Coverage.NotAnalyzed {
			fmt.Fprintf(&b, "  - %s: %s\n", n.Path, n.Reason)
		}
	}
	elected := 0
	for _, e := range doc.Coverage.Exclusions {
		if e.Origin != "intrinsic" {
			elected++
		}
	}
	fmt.Fprintf(&b, "Exclusiones: %d (intrinsecas %d, elegidas %d)\n",
		len(doc.Coverage.Exclusions), len(doc.Coverage.Exclusions)-elected, elected)

	fmt.Fprintln(&b, "Motores:")
	for _, e := range doc.Tools.Engines {
		line := fmt.Sprintf("  %s %s %s %s - %d hallazgos", e.ID, e.Version, e.Mode, e.Status, totalEngineFindings(e))
		if e.DB != nil {
			line += ", base " + e.DB.Status
			if e.DB.UpdatedAt != nil && *e.DB.UpdatedAt != "" {
				line += " (" + *e.DB.UpdatedAt + ")"
			}
		}
		if len(e.Limitations) > 0 {
			line += ", limitaciones: " + strings.Join(e.Limitations, "; ")
		}
		fmt.Fprintln(&b, line)
	}
	fmt.Fprintf(&b, "Aislamiento: %s", doc.Isolation.Level)
	if doc.Isolation.VerifiedBy == "" {
		fmt.Fprint(&b, " (no verificado en esta ejecucion)")
	} else {
		fmt.Fprint(&b, " (verificado por "+doc.Isolation.VerifiedBy+")")
	}
	fmt.Fprintln(&b)

	if len(doc.Findings) == 0 {
		fmt.Fprintln(&b, "Hallazgos: ninguno dentro del alcance analizado")
	} else {
		fmt.Fprintf(&b, "Hallazgos (%d):\n", len(doc.Findings))
		for i, f := range doc.Findings {
			loc := ""
			if len(f.Locations) > 0 {
				loc = f.Locations[0].Path
				if f.Locations[0].StartLine != nil {
					loc += fmt.Sprintf(":%d", *f.Locations[0].StartLine)
				}
			}
			pkg := ""
			if f.Package != nil {
				pkg = fmt.Sprintf(" [%s %s]", f.Package.Name, f.Package.Version)
			}
			status := ""
			if f.Policy.Status == "suppressed" {
				status = " (suprimido)"
			}
			fmt.Fprintf(&b, "  %d. [%s] %s - %s%s%s\n",
				i+1, strings.ToUpper(string(f.Severity.Normalized)), f.Title, loc, pkg, status)
		}
	}

	fmt.Fprintf(&b, "Politica: fail-on %s - ", doc.Policy.FailOn)
	if doc.Policy.Violated {
		fmt.Fprintln(&b, "INCUMPLIDA")
	} else {
		fmt.Fprintln(&b, "cumplida")
	}
	if len(doc.Errors) > 0 {
		fmt.Fprintf(&b, "Errores (%d):\n", len(doc.Errors))
		errs := append([]Error(nil), doc.Errors...)
		sort.SliceStable(errs, func(i, j int) bool { return errs[i].Code < errs[j].Code })
		for _, e := range errs {
			fmt.Fprintf(&b, "  - [%s] %s: %s\n", e.Code, e.Scope, e.Message)
		}
	}
	return b.String()
}

func totalEngineFindings(e EngineReport) int {
	total := 0
	for _, u := range e.Units {
		total += u.Findings
	}
	return total
}
