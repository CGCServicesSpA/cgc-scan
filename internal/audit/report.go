package audit

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
)

// Motivos de una corrida incompleta.
const (
	IncompleteUnassigned           = "unassigned_units"
	IncompleteUnverifiedCandidates = "unverified_candidates"
	IncompleteMissingCandidate     = "missing_candidate_state"
)

// BuildFindings sella el estado de la corrida y deriva el documento de
// hallazgos. Solo los candidatos con veredicto final entran al documento; los
// pendientes quedan fuera y fuerzan una corrida incompleta.
func BuildFindings(l *Ledger, c *Candidates) (*Findings, error) {
	if l == nil || c == nil {
		return nil, errors.New("auditoría: ledger y candidatos son obligatorios")
	}
	if err := reconcileCandidates(l, c); err != nil {
		return nil, err
	}

	reason := ""
	switch {
	case l.RunStatus == StatusIncomplete && l.IncompleteReason != "":
		// La corrida ya fue sellada como incompleta (por ejemplo, presupuesto
		// agotado). Un informe posterior no puede degradar ese hecho a complete.
		reason = l.IncompleteReason
	case l.Summary.Planned > 0 || l.Summary.InProgress > 0:
		reason = IncompleteUnassigned
	case countUndecided(c) > 0:
		reason = IncompleteUnverifiedCandidates
	default:
		if err := checkCandidateStateComplete(l, c); err != nil {
			return nil, err
		}
	}

	if reason == "" {
		l.RunStatus = StatusComplete
		l.IncompleteReason = ""
	} else {
		l.RunStatus = StatusIncomplete
		l.IncompleteReason = reason
	}
	l.Recompute()

	f := &Findings{
		SchemaVersion: FindingsSchemaVersion,
		Run:           l.Run,
		Target:        l.Target,
		Provenance:    CallerProvenance(),
		Findings:      []Record{},
	}
	for _, cand := range c.Items {
		if cand.State != CandidateDecided || cand.Final == nil {
			continue
		}
		f.Findings = append(f.Findings, *cand.Final)
	}
	f.Recompute()
	if err := ValidateFindingsSemantics(f); err != nil {
		return nil, fmt.Errorf("auditoría: hallazgos derivados inválidos: %w", err)
	}
	return f, nil
}

func countUndecided(c *Candidates) int {
	n := 0
	for _, cand := range c.Items {
		if cand.State == CandidatePending || cand.State == CandidateEscalation {
			n++
		}
	}
	return n
}

// reconcileCandidates comprueba que el estado de verificación y el ledger no
// se contradigan.
func reconcileCandidates(l *Ledger, c *Candidates) error {
	known := map[string]bool{}
	for _, cand := range c.Items {
		known[cand.Fingerprint] = true
		if l.UnitByID(cand.Unit) == nil {
			return fmt.Errorf("auditoría: el candidato %s apunta a una unidad inexistente: %s", cand.Fingerprint, cand.Unit)
		}
	}
	for _, u := range l.Units {
		for _, fp := range u.Candidates {
			if !known[fp] {
				return fmt.Errorf("auditoría: la unidad %s declara %s sin estado de verificación", u.CoverageID, fp)
			}
		}
	}
	return nil
}

func checkCandidateStateComplete(l *Ledger, c *Candidates) error {
	decided := map[string]bool{}
	for _, cand := range c.Items {
		if cand.State == CandidateDecided {
			decided[cand.Fingerprint] = true
		}
	}
	for _, u := range l.Units {
		for _, fp := range u.Candidates {
			if !decided[fp] {
				return fmt.Errorf("auditoría: %s no tiene disposición final; la corrida no puede declararse completa", fp)
			}
		}
	}
	return nil
}

// RenderReport produce REPORT.md a partir de los registros verificados y del
// ledger. No cambia ningún veredicto.
func RenderReport(l *Ledger, f *Findings) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Informe de auditoría — %s\n\n", clean(targetName(l)))
	fmt.Fprintf(&b, "- Perfil: `%s`\n", l.Profile)
	fmt.Fprintf(&b, "- Fuente revisada: `%s`", clean(l.Run.SourceRef))
	if l.Run.Dirty {
		b.WriteString(" (árbol con cambios sin commit)")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- Cobertura: %d unidad(es), %d cubierta(s), %d con candidato, %d bloqueada(s), %d diferida(s), %d fuera de alcance\n",
		l.Summary.UnitsTotal, l.Summary.Covered, l.Summary.Candidate,
		l.Summary.Blocked, l.Summary.Deferred, l.Summary.OutOfScope)
	if l.Budget != nil {
		fmt.Fprintf(&b, "- Presupuesto: %d de %d invocaciones de agente\n", l.Budget.Used, l.Budget.MaxAgentInvocations)
	} else {
		b.WriteString("- Presupuesto: sin límite declarado\n")
	}
	if partial := l.Summary.Blocked + l.Summary.Deferred + l.Summary.OutOfScope; partial > 0 {
		fmt.Fprintf(&b, "- Cobertura parcial: %d unidad(es) bloqueadas, diferidas o fuera de alcance\n", partial)
	}
	b.WriteString("- Ejecución: el motor no ejecutó código del proyecto ni contactó servicios externos; la evidencia la aporta el agente llamador y el motor validó estructura y consistencia, no verdad.\n\n")

	if l.RunStatus != StatusComplete {
		fmt.Fprintf(&b, "> **Corrida incompleta** (`%s`). Este informe es parcial: no hay cobertura completa ni se puede declarar el proyecto limpio.\n", clean(l.IncompleteReason))
		b.WriteString(">\n")
		b.WriteString("> Los candidatos sin disposición final no se presentan como hallazgos.\n\n")
	}

	fmt.Fprintf(&b, "## Postura\n\n")
	fmt.Fprintf(&b, "%d confirmado(s), %d pendiente(s) de validación y %d rechazado(s).",
		f.Summary.Confirmed, f.Summary.NeedsValidation, f.Summary.Rejected)
	if f.Summary.Confirmed == 0 {
		b.WriteString(" No hay hallazgos confirmados; eso no convierte la cobertura en completa.")
	}
	b.WriteString("\n\n")

	confirmed := recordsByVerdict(f.Findings, VerdictConfirmed)
	fmt.Fprintf(&b, "## Hallazgos confirmados\n\n")
	if len(confirmed) == 0 {
		b.WriteString("Ninguno.\n\n")
	} else {
		b.WriteString("| Severidad | Hallazgo | Frontera | Resultado observado |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		sortBySeverity(confirmed)
		for _, r := range confirmed {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				r.Severity.Overall, cell(r.Title), cell(boundaryOf(l, r)), cell(observedOf(r)))
		}
		b.WriteString("\n")
		for i, r := range confirmed {
			fmt.Fprintf(&b, "### %d. %s\n\n", i+1, clean(r.Title))
			fmt.Fprintf(&b, "- Severidad: **%s** (probabilidad %s, impacto %s)\n",
				r.Severity.Overall, r.Severity.Likelihood.Score, r.Severity.Impact.Score)
			fmt.Fprintf(&b, "- Traza: `%s`\n", traceLine(r.Trace))
			fmt.Fprintf(&b, "- Actor de menor confianza: %s\n", clean(r.Execution.AttackerPerspective))
			fmt.Fprintf(&b, "- Causa raíz: %s\n", clean(r.RootCause))
			fmt.Fprintf(&b, "- Comportamiento previsto: %s\n", clean(r.IntendedBehavior))
			if len(r.Execution.Payloads) > 0 {
				fmt.Fprintf(&b, "- Entrada mínima: `%s`\n", strings.Join(r.Execution.Payloads, "`, `"))
			}
			fmt.Fprintf(&b, "- Reproducción: %s\n", clean(strings.Join(r.Execution.Instructions, " ")))
			fmt.Fprintf(&b, "- Resultado observado: %s\n", clean(r.Execution.ObservedResult))
			if len(r.Conditions) > 0 {
				var conds []string
				for _, c := range r.Conditions {
					conds = append(conds, clean(c.Description))
				}
				fmt.Fprintf(&b, "- Condiciones: %s\n", strings.Join(conds, "; "))
			}
			fmt.Fprintf(&b, "- Corrección mínima: %s\n", clean(r.Remediation.Strategy))
			if r.Confidence != nil {
				fmt.Fprintf(&b, "- Confianza: %s (%s)\n", r.Confidence.Score, clean(r.Confidence.Reason))
			}
			b.WriteString("\n")
		}
	}

	nv := recordsByVerdict(f.Findings, VerdictNeedsValidation)
	fmt.Fprintf(&b, "## Necesita validación\n\n")
	if len(nv) == 0 {
		b.WriteString("Ninguna.\n\n")
	} else {
		b.WriteString("| Hallazgo | Traza | Bloqueo |\n")
		b.WriteString("| --- | --- | --- |\n")
		for _, r := range nv {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", cell(r.Title), traceLine(r.Trace), cell(strings.Join(r.Blockers, "; ")))
		}
		b.WriteString("\nEstos registros no tienen severidad: un bloqueo no es una vulnerabilidad confirmada.\n\n")
	}

	hardening := hardeningNotes(l)
	fmt.Fprintf(&b, "## Notas de endurecimiento\n\n")
	if len(hardening) == 0 {
		b.WriteString("Sin notas.\n\n")
	} else {
		for _, n := range hardening {
			fmt.Fprintf(&b, "- %s\n", clean(n))
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Cobertura\n\n")
	fmt.Fprintf(&b, "- Planificadas: %d\n- En curso: %d\n- Cubiertas: %d\n- Con candidato: %d\n- Bloqueadas: %d\n- Diferidas: %d\n- Fuera de alcance: %d\n",
		l.Summary.Planned, l.Summary.InProgress, l.Summary.Covered,
		l.Summary.Candidate, l.Summary.Blocked, l.Summary.Deferred, l.Summary.OutOfScope)
	if len(l.Limitations) > 0 {
		b.WriteString("\nLimitaciones del reconocimiento:\n")
		for _, lim := range l.Limitations {
			fmt.Fprintf(&b, "- %s\n", clean(lim))
		}
	}
	deferred := unitsByState(l, StateDeferred)
	if len(deferred) > 0 {
		b.WriteString("\nDiferidas:\n")
		for _, u := range deferred {
			fmt.Fprintf(&b, "- `%s` (%s)\n", u.CoverageID, clean(u.Reason))
		}
	}
	oos := unitsByState(l, StateOutOfScope)
	if len(oos) > 0 {
		b.WriteString("\nFuera de alcance:\n")
		for _, u := range oos {
			fmt.Fprintf(&b, "- `%s` (%s)\n", u.CoverageID, clean(u.Reason))
		}
	}
	if len(deferred) == 0 && len(oos) == 0 {
		b.WriteString("\nSin unidades diferidas ni fuera de alcance.\n")
	}
	return []byte(b.String())
}

// RenderFindingsDetail produce FINDINGS-DETAIL.md para los confirmados de
// severidad media o superior.
func RenderFindingsDetail(l *Ledger, f *Findings) []byte {
	var b strings.Builder
	b.WriteString("# Detalle de hallazgos confirmados\n\n")
	confirmed := recordsByVerdict(f.Findings, VerdictConfirmed)
	sortBySeverity(confirmed)
	written := 0
	for _, r := range confirmed {
		if severityRank[r.Severity.Overall] < severityRank["medium"] {
			continue
		}
		written++
		fmt.Fprintf(&b, "## %s\n\n", clean(r.Title))
		fmt.Fprintf(&b, "**Severidad:** %s · **Confianza:** %s\n\n", r.Severity.Overall, r.Confidence.Score)
		fmt.Fprintf(&b, "**Frontera:** %s\n\n", clean(boundaryOf(l, r)))
		b.WriteString("### Traza\n\n")
		for _, step := range r.Trace {
			fmt.Fprintf(&b, "1. `%s` (%s:%d) — %s\n", step.Kind, clean(step.File), step.Line, clean(step.Description))
		}
		fmt.Fprintf(&b, "\n**Actor:** %s\n\n", clean(r.Execution.AttackerPerspective))
		b.WriteString("**Entrada mínima:**\n\n")
		for _, p := range r.Execution.Payloads {
			fmt.Fprintf(&b, "```\n%s\n```\n", p)
		}
		b.WriteString("**Pasos:**\n\n")
		for i, step := range r.Execution.Instructions {
			fmt.Fprintf(&b, "%d. %s\n", i+1, clean(step))
		}
		fmt.Fprintf(&b, "\n**Resultado observado:** %s\n\n", clean(r.Execution.ObservedResult))
		b.WriteString("**Evidencia:**\n\n")
		for _, e := range r.Evidence {
			fmt.Fprintf(&b, "- `%s:%d` — %s\n", clean(e.File), e.Line, clean(e.Description))
		}
		b.WriteString("\n**Corrección mínima:** ")
		b.WriteString(clean(r.Remediation.Strategy))
		b.WriteString("\n\n")
		if len(r.Remediation.CodeChanges) > 0 {
			for _, cc := range r.Remediation.CodeChanges {
				fmt.Fprintf(&b, "`%s`:\n\n```\n%s\n```\n\n", clean(cc.FileName), cc.FixedCode)
			}
		}
	}
	if written == 0 {
		b.WriteString("No hay hallazgos confirmados de severidad media o superior.\n")
	}
	return []byte(b.String())
}

// RenderNeedsValidation produce NEEDS-VALIDATION.md sin severidad ni
// instrucciones de prueba contra entornos desplegados.
func RenderNeedsValidation(f *Findings) []byte {
	var b strings.Builder
	b.WriteString("# Pendientes de validación\n\n")
	b.WriteString("Estos registros tienen una hipótesis de frontera con un hecho decisivo fuera de la fuente. No son vulnerabilidades confirmadas y no llevan severidad.\n\n")
	nv := recordsByVerdict(f.Findings, VerdictNeedsValidation)
	if len(nv) == 0 {
		b.WriteString("Ninguno.\n")
		return []byte(b.String())
	}
	for _, r := range nv {
		fmt.Fprintf(&b, "## %s\n\n", clean(r.Title))
		fmt.Fprintf(&b, "%s\n\n", clean(r.Description))
		fmt.Fprintf(&b, "**Causa raíz propuesta:** %s\n\n", clean(r.ClaimedRootCause))
		b.WriteString("**Traza:**\n\n")
		for _, step := range r.Trace {
			fmt.Fprintf(&b, "1. `%s` (%s:%d) — %s\n", step.Kind, clean(step.File), step.Line, clean(step.Description))
		}
		b.WriteString("\n**Bloqueos:**\n\n")
		for _, blocker := range r.Blockers {
			fmt.Fprintf(&b, "- %s\n", clean(blocker))
		}
		if r.ValidationPlan.Local != "" {
			fmt.Fprintf(&b, "\n**Plan local acotado:** %s\n", clean(r.ValidationPlan.Local))
		}
		if r.ValidationPlan.Deployment != "" {
			fmt.Fprintf(&b, "\n**Observación del responsable:** %s\n", clean(r.ValidationPlan.Deployment))
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func targetName(l *Ledger) string {
	if base := filepath.Base(filepath.Clean(l.Target.Root)); base != "" && base != "." && base != string(filepath.Separator) {
		return base
	}
	return l.Target.LocalID
}

func recordsByVerdict(records []Record, verdict string) []Record {
	out := make([]Record, 0)
	for _, r := range records {
		if r.Verdict == verdict {
			out = append(out, r)
		}
	}
	return out
}

func sortBySeverity(records []Record) {
	sort.SliceStable(records, func(i, j int) bool {
		ri, rj := 0, 0
		if records[i].Severity != nil {
			ri = severityRank[records[i].Severity.Overall]
		}
		if records[j].Severity != nil {
			rj = severityRank[records[j].Severity.Overall]
		}
		if ri != rj {
			return ri > rj
		}
		return records[i].Fingerprint < records[j].Fingerprint
	})
}

func boundaryOf(l *Ledger, r Record) string {
	for _, u := range l.Units {
		for _, fp := range u.Candidates {
			if fp == r.Fingerprint {
				return u.Domain + "/" + u.Boundary
			}
		}
	}
	for _, step := range r.Trace {
		if step.Kind == "sink" {
			return step.Scope
		}
	}
	return "sin clasificar"
}

func observedOf(r Record) string {
	if r.Execution == nil {
		return ""
	}
	return r.Execution.ObservedResult
}

func traceLine(trace []TraceStep) string {
	if len(trace) == 0 {
		return ""
	}
	first := trace[0]
	last := trace[len(trace)-1]
	if len(trace) == 1 {
		return fmt.Sprintf("%s:%d", first.File, first.Line)
	}
	return fmt.Sprintf("%s:%d -> %s:%d", first.File, first.Line, last.File, last.Line)
}

func unitsByState(l *Ledger, state string) []Unit {
	out := make([]Unit, 0)
	for _, u := range l.Units {
		if u.State == state {
			out = append(out, u)
		}
	}
	return out
}

func hardeningNotes(l *Ledger) []string {
	out := make([]string, 0)
	for _, u := range l.Units {
		out = append(out, u.Hardening...)
	}
	sort.Strings(out)
	return out
}

// cell prepara texto para una celda de tabla Markdown.
func cell(s string) string {
	s = clean(s)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// clean quita caracteres de control y direccionales del texto libre.
func clean(s string) string {
	return masking.Sanitize(s)
}
