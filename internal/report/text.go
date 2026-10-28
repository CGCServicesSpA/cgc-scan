package report

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
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
		return fmt.Errorf("el formato prompt se emite con EmitPrompt")
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
		writeFindingSummary(&b, doc.Findings)
		for i, f := range doc.Findings {
			writeFinding(&b, i+1, f)
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

// writeFindingSummary agrega el conteo por severidad y cuántos hallazgos tienen
// una versión corregida conocida.
func writeFindingSummary(b *bytes.Buffer, findings []normalize.Finding) {
	bySeverity := map[normalize.Severity]int{}
	withFix := 0
	for _, f := range findings {
		bySeverity[f.Severity.Normalized]++
		if f.Package != nil && f.Package.FixedVersion != nil && *f.Package.FixedVersion != "" {
			withFix++
		}
	}
	fmt.Fprintf(b, "Hallazgos (%d) — correcciones disponibles: %d\n", len(findings), withFix)
	fmt.Fprintf(b, "  severidad: critical %d, high %d, medium %d, low %d, info %d, unknown %d\n",
		bySeverity[normalize.SeverityCritical], bySeverity[normalize.SeverityHigh],
		bySeverity[normalize.SeverityMedium], bySeverity[normalize.SeverityLow],
		bySeverity[normalize.SeverityInformational], bySeverity[normalize.SeverityUnknown])
}

func writeFinding(b *bytes.Buffer, index int, f normalize.Finding) {
	fmt.Fprintf(b, "\n  %d. [%s] %s\n", index, strings.ToUpper(string(f.Severity.Normalized)), f.Title)
	if f.Package != nil {
		line := f.Package.Name + " " + f.Package.Version + " (" + f.Package.Ecosystem + ")"
		if f.Package.FixedVersion != nil && *f.Package.FixedVersion != "" {
			line += " -> version corregida " + *f.Package.FixedVersion
		} else {
			line += " (sin version corregida conocida)"
		}
		writeField(b, "paquete", line)
	}
	if ids := joinIDs(f.IDs); ids != "" {
		writeField(b, "ids", ids)
	}
	if len(f.Locations) > 0 {
		writeField(b, "ubicacion", locationString(f.Locations[0]))
		for _, loc := range f.Locations[1:] {
			writeField(b, "ubicacion", locationString(loc))
		}
	}
	if sources := sourceString(f.Sources); sources != "" {
		writeField(b, "motores", sources)
	}
	if sev := severityDetail(f); sev != "" {
		writeField(b, "severidad", sev)
	}
	if prio := priorityString(f.Priority); prio != "" {
		writeField(b, "prioridad", prio)
	}
	if desc := descriptionsString(f.Descriptions); desc != "" {
		writeField(b, "descripcion", clipText(desc, 1200))
	}
	if f.Evidence.Snippet != "" {
		writeField(b, "evidencia", clipText(strings.TrimSpace(f.Evidence.Snippet), 600))
	}
	if rem := remediationString(f.Remediation); rem != "" {
		writeField(b, "remediacion", clipText(rem, 600))
	}
	if refs := referencesString(f.References); refs != "" {
		writeField(b, "referencias", clipText(refs, 500))
	}
	if f.Policy.Status == "suppressed" {
		reason := f.Policy.SuppressedReason
		if reason == "" {
			reason = "excepción de política"
		}
		writeField(b, "estado", "suprimido: "+reason)
	}
}

func writeField(b *bytes.Buffer, label, value string) {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return
	}
	prefix := "     " + label + ": "
	const width = 100
	if len(prefix)+len(value) <= width {
		fmt.Fprintf(b, "%s%s\n", prefix, value)
		return
	}
	cont := strings.Repeat(" ", len(prefix))
	fmt.Fprintf(b, "%s%s\n", prefix, wrapWords(value, width-len(prefix))[0])
	for _, line := range wrapWords(value, width-len(prefix))[1:] {
		fmt.Fprintf(b, "%s%s\n", cont, line)
	}
}

func wrapWords(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	line := ""
	for _, w := range words {
		if line == "" {
			line = w
			continue
		}
		if len(line)+1+len(w) <= width {
			line += " " + w
			continue
		}
		lines = append(lines, line)
		line = w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func clipText(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= limit {
		return s
	}
	omitted := len(s) - limit
	return s[:limit] + fmt.Sprintf(" [texto truncado; %d caracteres omitidos; consulta el reporte JSON]", omitted)
}

func joinIDs(ids []normalize.Identifier) string {
	parts := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if id.Value == "" || seen[id.Value] {
			continue
		}
		seen[id.Value] = true
		if id.Type == "RULE" {
			parts = append(parts, "regla="+id.Value)
			continue
		}
		parts = append(parts, id.Value)
	}
	return strings.Join(parts, ", ")
}

func locationString(l normalize.Location) string {
	out := l.Path
	if l.StartLine != nil {
		out += fmt.Sprintf(":%d", *l.StartLine)
		if l.StartColumn != nil {
			out += fmt.Sprintf(":%d", *l.StartColumn)
		}
	}
	return out
}

func sourceString(sources []normalize.SourceRef) string {
	parts := make([]string, 0, len(sources))
	seen := map[string]bool{}
	for _, s := range sources {
		label := s.Engine
		if s.Version != "" {
			label += " " + s.Version
		}
		if s.Rule != "" {
			label += " (" + s.Rule + ")"
		}
		if seen[label] {
			continue
		}
		seen[label] = true
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

func severityDetail(f normalize.Finding) string {
	out := fmt.Sprintf("original %s (%s)", f.Severity.Original, f.Severity.Source)
	if len(f.SeverityOthers) == 0 {
		return out
	}
	parts := make([]string, 0, len(f.SeverityOthers))
	for _, other := range f.SeverityOthers {
		parts = append(parts, fmt.Sprintf("%s (%s)", other.Normalized, other.Source))
	}
	return out + "; otras fuentes: " + strings.Join(parts, ", ")
}

func priorityString(p *normalize.Priority) string {
	if p == nil {
		return ""
	}
	var parts []string
	if p.CVSSScore != nil {
		line := fmt.Sprintf("CVSS %.1f", *p.CVSSScore)
		if p.CVSSVector != nil {
			line += " (" + *p.CVSSVector + ")"
		}
		parts = append(parts, line)
	}
	if p.KEV != nil && *p.KEV {
		parts = append(parts, "KEV")
	}
	if p.EPSS != nil {
		parts = append(parts, fmt.Sprintf("EPSS %.3f", *p.EPSS))
	}
	if p.Reachable != nil {
		if *p.Reachable {
			parts = append(parts, "funcion alcanzable")
		} else {
			parts = append(parts, "no alcanzable")
		}
	}
	return strings.Join(parts, ", ")
}

func descriptionsString(descriptions []normalize.Description) string {
	seen := map[string]bool{}
	var parts []string
	for _, d := range descriptions {
		text := strings.Join(strings.Fields(d.Text), " ")
		if text == "" || seen[text] {
			continue
		}
		seen[text] = true
		parts = append(parts, text)
	}
	return strings.Join(parts, " | ")
}

func referencesString(references []string) string {
	seen := map[string]bool{}
	var parts []string
	for _, ref := range references {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		parts = append(parts, ref)
	}
	return strings.Join(parts, ", ")
}

func remediationString(remediations []normalize.Remediation) string {
	seen := map[string]bool{}
	updateShown := false
	var parts []string
	for _, r := range remediations {
		text := strings.Join(strings.Fields(r.Description), " ")
		if text == "" || seen[text] {
			continue
		}
		seen[text] = true
		// Varias fuentes describen la misma actualización con distinto fraseo;
		// en texto se muestra la primera para no repetir la misma acción.
		if strings.HasPrefix(strings.ToLower(text), "actualizar ") {
			if updateShown {
				continue
			}
			updateShown = true
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, " | ")
}
