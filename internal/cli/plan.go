package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/remediation"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// PlanSchema identifica el documento de `plan`.
const PlanSchema = "plan-1.0.0"

// PlanDocument es el plan de remediación derivado del último reporte.
type PlanDocument struct {
	SchemaVersion string                    `json:"schema_version"`
	Project       string                    `json:"project"`
	RunID         string                    `json:"run_id"`
	Coverage      PlanCoverage              `json:"coverage"`
	Groups        []report.RemediationGroup `json:"remediation_groups"`
	NextActions   []report.NextAction       `json:"next_actions"`
	Blocked       []BlockedItem             `json:"blocked"`
	Delta         *report.Delta             `json:"delta,omitempty"`
	ReportPath    string                    `json:"report_path"`
}

// PlanCoverage resume la cobertura del reporte de origen.
type PlanCoverage struct {
	Partial bool `json:"partial"`
	Errors  int  `json:"errors"`
}

// BlockedItem explica por qué una validación o un motor quedó bloqueado.
type BlockedItem struct {
	Kind   string `json:"kind"`
	Unit   string `json:"unit,omitempty"`
	Engine string `json:"engine,omitempty"`
	Reason string `json:"reason"`
}

func (a *App) runPlan(_ context.Context, target, format string) error {
	store, err := a.projectStore(target)
	if err != nil {
		return err
	}
	doc, err := store.LoadLatest()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	plan := buildPlanDocument(doc, store)
	if format == "json" {
		data, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, append(data, '\n'))
	}
	_, err = fmt.Fprint(a.Stdout, renderPlan(plan))
	return err
}

func buildPlanDocument(doc *report.Document, store *projectstate.Store) PlanDocument {
	groups := remediation.Build(doc)
	actions := remediation.Actions(doc, groups)
	p := PlanDocument{
		SchemaVersion: PlanSchema, Project: doc.Target.Root, RunID: doc.Run.ID,
		Coverage: PlanCoverage{Partial: doc.Coverage.Partial, Errors: len(doc.Errors)},
		Groups:   groups, NextActions: actions, Blocked: collectBlocked(doc),
		ReportPath: store.LatestPath(),
	}
	if baseline, err := store.LoadBaseline(); err == nil {
		p.Delta = compare.ReportDelta(compare.Compare(baseline, doc))
	}
	return p
}

func collectBlocked(doc *report.Document) []BlockedItem {
	out := make([]BlockedItem, 0)
	for _, u := range doc.Validation.Unresolved {
		out = append(out, BlockedItem{
			Kind: "missing_recipes", Unit: u.Unit,
			Reason: "faltan recetas: " + strings.Join(u.Missing, ", "),
		})
	}
	for _, e := range doc.Errors {
		kind := e.Code
		if kind == "requirement_missing" {
			kind = "missing_toolchain"
		}
		out = append(out, BlockedItem{Kind: kind, Reason: e.Message})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Unit != out[j].Unit {
			return out[i].Unit < out[j].Unit
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

func renderPlan(p PlanDocument) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan de remediación: %s\n", p.Project)
	fmt.Fprintf(&b, "Reporte: %s (%d grupos, %d acciones)\n", p.RunID, len(p.Groups), len(p.NextActions))
	if p.Delta != nil {
		fmt.Fprintf(&b, "Delta: nuevo %d, persistente %d, resuelto %d, no evaluado %d\n",
			len(p.Delta.New), len(p.Delta.Persistent), len(p.Delta.Resolved), len(p.Delta.NotEvaluated))
	}
	if len(p.Blocked) > 0 {
		fmt.Fprintln(&b, "Bloqueado:")
		for _, x := range p.Blocked {
			fmt.Fprintf(&b, "  [%s] %s\n", x.Kind, x.Reason)
		}
	}
	if len(p.Groups) > 0 {
		fmt.Fprintln(&b, "Grupos:")
		for _, g := range p.Groups {
			line := fmt.Sprintf("  %s [%s] prioridad %d, %d hallazgo(s)", g.ID, g.MaxSeverity, g.PriorityScore, len(g.Fixes))
			if g.Package != nil {
				line += fmt.Sprintf(" · %s %s -> %s (%s)", g.Package.Name, g.Package.From, g.Package.To, g.BreakingRisk)
			}
			fmt.Fprintln(&b, line)
			if g.Commands.Apply != "" {
				fmt.Fprintf(&b, "    aplicar: %s\n", g.Commands.Apply)
			}
		}
	}
	if len(p.NextActions) > 0 {
		fmt.Fprintln(&b, "Próximas acciones:")
		for i, a := range p.NextActions {
			fmt.Fprintf(&b, "  %d. %s", i+1, a.Action)
			if a.Group != "" {
				fmt.Fprintf(&b, " %s", a.Group)
			}
			if a.Unit != "" {
				fmt.Fprintf(&b, " (%s)", a.Unit)
			}
			if a.Command != "" {
				fmt.Fprintf(&b, " · %s", a.Command)
			}
			if a.Reason != "" {
				fmt.Fprintf(&b, " · %s", a.Reason)
			}
			fmt.Fprintln(&b)
		}
	}
	return b.String()
}
