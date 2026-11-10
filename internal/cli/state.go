package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// StatusSchema identifica el documento de `status`.
const StatusSchema = "status-1.0.0"

// ExplainSchema identifica el documento de `explain`.
const ExplainSchema = "explain-1.0.0"

// StatusDocument es el resumen del último resultado guardado.
type StatusDocument struct {
	SchemaVersion string         `json:"schema_version"`
	Project       string         `json:"project"`
	LocalID       string         `json:"local_id"`
	Available     bool           `json:"available"`
	RunID         string         `json:"run_id,omitempty"`
	FinishedAt    string         `json:"finished_at,omitempty"`
	CLIVersion    string         `json:"cli_version,omitempty"`
	Coverage      StatusCoverage `json:"coverage"`
	Counts        StatusCounts   `json:"counts"`
	Baseline      BaselineStatus `json:"baseline"`
	Groups        int            `json:"groups"`
	NextActions   int            `json:"next_actions"`
	ReportPath    string         `json:"report_path,omitempty"`
}

// StatusCoverage resume la cobertura del último reporte.
type StatusCoverage struct {
	Partial bool `json:"partial"`
	Units   int  `json:"units"`
	Errors  int  `json:"errors"`
}

// StatusCounts resume hallazgos y delta.
type StatusCounts struct {
	Total        int            `json:"total"`
	Suppressed   int            `json:"suppressed"`
	BySeverity   map[string]int `json:"by_severity"`
	ByKind       map[string]int `json:"by_kind"`
	New          int            `json:"new"`
	Persistent   int            `json:"persistent"`
	Resolved     int            `json:"resolved"`
	NotEvaluated int            `json:"not_evaluated"`
}

// BaselineStatus describe la línea base y su delta con el último reporte.
type BaselineStatus struct {
	Available bool   `json:"available"`
	RunID     string `json:"run_id,omitempty"`
}

// ExplainDocument es el detalle completo de una huella o un grupo.
type ExplainDocument struct {
	SchemaVersion string                   `json:"schema_version"`
	Fingerprint   string                   `json:"fingerprint,omitempty"`
	Group         *report.RemediationGroup `json:"group,omitempty"`
	Unit          string                   `json:"unit,omitempty"`
	Engines       []string                 `json:"engines"`
	Finding       *normalize.Finding       `json:"finding,omitempty"`
	Findings      []normalize.Finding      `json:"findings"`
	ReportPath    string                   `json:"report_path,omitempty"`
}

func (a *App) newStatusCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "status [ruta]",
		Short: "Resume el último resultado guardado sin escanear",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runStatus(cmd.Context(), target, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: text|json")
	return cmd
}

func (a *App) newExplainCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "explain <fingerprint|grupo> [ruta]",
		Short: "Muestra el detalle de un hallazgo o grupo desde el último reporte",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			target := ""
			if len(args) == 2 {
				target = args[1]
			}
			return a.runExplain(cmd.Context(), args[0], target, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: text|json")
	return cmd
}

func (a *App) newPlanCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "plan [ruta]",
		Short: "Genera el plan de remediación desde el último reporte, sin escanear",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runPlan(cmd.Context(), target, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: text|json")
	return cmd
}

func (a *App) newBaselineCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "baseline <set|show|clear> [ruta]",
		Short: "Fija, muestra o elimina la línea base del proyecto",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("action", args[0], "set", "show", "clear"); err != nil {
				return err
			}
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			target := ""
			if len(args) == 2 {
				target = args[1]
			}
			return a.runBaseline(args[0], target, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: text|json")
	return cmd
}

func (a *App) projectStore(target string) (*projectstate.Store, error) {
	if target == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, IncompleteErrorf("obtener el directorio actual: %v", err)
		}
		target = wd
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, UsageErrorf("ruta objetivo inválida: %v", err)
	}
	root := discovery.DetectRoot(abs)
	store, err := projectstate.Open(a.Paths, root)
	if err != nil {
		return nil, IncompleteErrorf("%v", err)
	}
	return store, nil
}

func (a *App) runStatus(_ context.Context, target, format string) error {
	store, err := a.projectStore(target)
	if err != nil {
		return err
	}
	doc, err := store.LoadLatest()
	if err != nil {
		if errors.Is(err, projectstate.ErrNoReport) {
			return IncompleteErrorf("%v", err)
		}
		return IncompleteErrorf("%v", err)
	}
	status := buildStatus(store, doc)
	baseline, err := store.LoadBaseline()
	if err == nil {
		status.Baseline = BaselineStatus{Available: true, RunID: baseline.Run.ID}
		delta := compare.Compare(baseline, doc)
		status.Counts.New = len(delta.New)
		status.Counts.Persistent = len(delta.Persistent)
		status.Counts.Resolved = len(delta.Resolved)
		status.Counts.NotEvaluated = len(delta.NotEvaluated)
	}
	if format == "json" {
		data, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, append(data, '\n'))
	}
	_, err = fmt.Fprint(a.Stdout, renderStatus(status))
	return err
}

func buildStatus(store *projectstate.Store, doc *report.Document) StatusDocument {
	st := StatusDocument{
		SchemaVersion: StatusSchema, Project: doc.Target.Root, LocalID: doc.Target.LocalID,
		Available: true, RunID: doc.Run.ID, FinishedAt: doc.Run.FinishedAt,
		CLIVersion: doc.Run.CLIVersion, ReportPath: store.LatestPath(),
		Counts: StatusCounts{BySeverity: map[string]int{}, ByKind: map[string]int{}},
		Coverage: StatusCoverage{
			Partial: doc.Coverage.Partial, Units: len(doc.Coverage.Units), Errors: len(doc.Errors),
		},
		Groups: len(doc.RemediationGroups), NextActions: len(doc.NextActions),
	}
	for _, f := range doc.Findings {
		if f.Policy.Status == "suppressed" {
			st.Counts.Suppressed++
			continue
		}
		st.Counts.Total++
		st.Counts.BySeverity[string(f.Severity.Normalized)]++
		st.Counts.ByKind[string(f.Kind)]++
	}
	return st
}

func renderStatus(st StatusDocument) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Proyecto: %s\n", st.Project)
	if !st.Available {
		fmt.Fprintln(&b, "Estado: sin reporte guardado")
		return b.String()
	}
	fmt.Fprintf(&b, "Último reporte: %s (%s)\n", st.RunID, st.FinishedAt)
	coverage := "COMPLETA"
	if st.Coverage.Partial {
		coverage = "PARCIAL"
	}
	fmt.Fprintf(&b, "Cobertura: %s (%d unidades, %d errores)\n", coverage, st.Coverage.Units, st.Coverage.Errors)
	fmt.Fprintf(&b, "Hallazgos: %d", st.Counts.Total)
	if st.Counts.Suppressed > 0 {
		fmt.Fprintf(&b, " (%d suprimidos)", st.Counts.Suppressed)
	}
	fmt.Fprintln(&b)
	sev := make([]string, 0, len(st.Counts.BySeverity))
	for k := range st.Counts.BySeverity {
		sev = append(sev, k)
	}
	sort.Slice(sev, func(i, j int) bool { return severityRank(sev[i]) > severityRank(sev[j]) })
	for _, k := range sev {
		fmt.Fprintf(&b, "  %s: %d\n", k, st.Counts.BySeverity[k])
	}
	fmt.Fprintf(&b, "Grupos: %d · Próximas acciones: %d\n", st.Groups, st.NextActions)
	if st.Baseline.Available {
		fmt.Fprintf(&b, "Línea base: %s · nuevo %d, persistente %d, resuelto %d, no evaluado %d\n",
			st.Baseline.RunID, st.Counts.New, st.Counts.Persistent, st.Counts.Resolved, st.Counts.NotEvaluated)
	} else {
		fmt.Fprintln(&b, "Línea base: no definida")
	}
	fmt.Fprintf(&b, "Reporte: %s\n", st.ReportPath)
	return b.String()
}

func severityRank(s string) int {
	return normalize.Severity(s).Rank()
}

func (a *App) runExplain(_ context.Context, selector, target, format string) error {
	store, err := a.projectStore(target)
	if err != nil {
		return err
	}
	doc, err := store.LoadLatest()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	out, err := buildExplain(store, doc, selector)
	if err != nil {
		return err
	}
	if format == "json" {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, append(data, '\n'))
	}
	_, err = fmt.Fprint(a.Stdout, renderExplain(out))
	return err
}

func buildExplain(store *projectstate.Store, doc *report.Document, selector string) (ExplainDocument, error) {
	idx, _ := store.LoadIndex()
	out := ExplainDocument{
		SchemaVersion: ExplainSchema, Findings: []normalize.Finding{},
		Engines: []string{}, ReportPath: store.LatestPath(),
	}
	byFP := make(map[string]normalize.Finding, len(doc.Findings))
	for _, f := range doc.Findings {
		byFP[f.Fingerprint] = f
	}
	for i := range doc.RemediationGroups {
		g := doc.RemediationGroups[i]
		if g.ID != selector {
			continue
		}
		out.Group = &g
		out.Fingerprint = selector
		for _, fp := range g.Fixes {
			if f, ok := byFP[fp]; ok {
				out.Findings = append(out.Findings, f)
			}
		}
		out.Unit = g.Unit
		out.Engines = groupEngines(doc, g.Fixes)
		return out, nil
	}
	f, ok := byFP[selector]
	if !ok {
		return ExplainDocument{}, UsageErrorf("no existe la huella ni el grupo %q en el último reporte", selector)
	}
	out.Fingerprint = selector
	out.Finding = &f
	out.Findings = []normalize.Finding{f}
	if entry, ok := idx.Findings[selector]; ok {
		out.Unit = entry.Unit
		out.Engines = entry.Engines
	}
	for i := range doc.RemediationGroups {
		for _, fp := range doc.RemediationGroups[i].Fixes {
			if fp == selector {
				g := doc.RemediationGroups[i]
				out.Group = &g
				if out.Unit == "" {
					out.Unit = g.Unit
				}
			}
		}
	}
	return out, nil
}

func groupEngines(doc *report.Document, fixes []string) []string {
	set := map[string]bool{}
	for _, fp := range fixes {
		for _, f := range doc.Findings {
			if f.Fingerprint != fp {
				continue
			}
			for _, s := range f.Sources {
				if s.Engine != "" {
					set[s.Engine] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func renderExplain(d ExplainDocument) string {
	var b strings.Builder
	if d.Group != nil {
		g := d.Group
		fmt.Fprintf(&b, "Grupo: %s\n", g.ID)
		fmt.Fprintf(&b, "Tipo: %s · Unidad: %s · Severidad máxima: %s\n", g.Kind, g.Unit, g.MaxSeverity)
		if g.Package != nil {
			fmt.Fprintf(&b, "Paquete: %s %s %s -> %s\n", g.Package.Ecosystem, g.Package.Name, g.Package.From, g.Package.To)
			fmt.Fprintf(&b, "Riesgo de ruptura: %s\n", g.BreakingRisk)
		}
		if g.File != "" {
			fmt.Fprintf(&b, "Archivo: %s · Regla: %s · Ubicaciones: %d\n", g.File, g.Rule, g.Locations)
		}
		fmt.Fprintf(&b, "Corrige %d hallazgo(s): %s\n", len(g.Fixes), strings.Join(g.Fixes, ", "))
		if g.Commands.Apply != "" {
			fmt.Fprintf(&b, "Aplicar (sugerencia, no se ejecuta): %s\n", g.Commands.Apply)
		}
		if g.Commands.Override != "" {
			fmt.Fprintf(&b, "Alternativa/override: %s\n", g.Commands.Override)
		}
		fmt.Fprintf(&b, "Verificar: %s\n", g.Verification.Verify)
	}
	for _, f := range d.Findings {
		fmt.Fprintf(&b, "\n[%s] %s\n", f.Severity.Normalized, f.Title)
		fmt.Fprintf(&b, "Huella: %s · Tipo: %s\n", f.Fingerprint, f.Kind)
		if f.Package != nil {
			fmt.Fprintf(&b, "Paquete: %s %s %s", f.Package.Ecosystem, f.Package.Name, f.Package.Version)
			if f.Package.FixedVersion != nil {
				fmt.Fprintf(&b, " (corregido en %s)", *f.Package.FixedVersion)
			}
			fmt.Fprintln(&b)
		}
		if len(f.Locations) > 0 {
			fmt.Fprint(&b, "Ubicaciones:")
			for _, l := range f.Locations {
				fmt.Fprintf(&b, " %s", l.Path)
				if l.StartLine != nil {
					fmt.Fprintf(&b, ":%d", *l.StartLine)
				}
			}
			fmt.Fprintln(&b)
		}
		for _, desc := range f.Descriptions {
			fmt.Fprintf(&b, "Descripción (%s): %s\n", desc.Source, desc.Text)
		}
		if f.Evidence.Snippet != "" {
			fmt.Fprintf(&b, "Evidencia: %s\n", f.Evidence.Snippet)
		}
		for _, r := range f.Remediation {
			fmt.Fprintf(&b, "Remediación (%s): %s\n", r.Source, r.Description)
		}
		for _, ref := range f.References {
			fmt.Fprintf(&b, "Referencia: %s\n", ref)
		}
		if f.Priority != nil && f.Priority.Score != nil {
			fmt.Fprintf(&b, "Prioridad: %d", *f.Priority.Score)
			if f.Priority.Rank != nil {
				fmt.Fprintf(&b, " (rank %d)", *f.Priority.Rank)
			}
			if len(f.Priority.Factors) > 0 {
				fmt.Fprintf(&b, " · %s", strings.Join(f.Priority.Factors, ", "))
			}
			fmt.Fprintln(&b)
		}
		if f.Verification != nil {
			fmt.Fprintf(&b, "Verificación: %s · %s\n", f.Verification.Status, f.Verification.Rescan)
			for _, r := range f.Verification.Recipes {
				fmt.Fprintf(&b, "  %s: %s (%s)\n", r.Kind, r.Command, r.Workdir)
			}
		}
	}
	return b.String()
}

func (a *App) runBaseline(action, target, format string) error {
	store, err := a.projectStore(target)
	if err != nil {
		return err
	}
	switch action {
	case "set":
		doc, err := store.LoadLatest()
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		if err := store.SaveBaseline(doc); err != nil {
			return IncompleteErrorf("%v", err)
		}
	case "clear":
		if err := store.ClearBaseline(); err != nil {
			return IncompleteErrorf("%v", err)
		}
	case "show":
		doc, err := store.LoadBaseline()
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		if format == "json" {
			data, err := json.MarshalIndent(map[string]any{
				"schema_version": StatusSchema, "project": doc.Target.Root,
				"available": true, "run_id": doc.Run.ID, "finished_at": doc.Run.FinishedAt,
				"findings": len(doc.Findings), "path": store.BaselinePath(),
			}, "", "  ")
			if err != nil {
				return IncompleteErrorf("%v", err)
			}
			return report.EmitRaw(a.Stdout, append(data, '\n'))
		}
		fmt.Fprintf(a.Stdout, "Línea base: %s (%s)\nHallazgos: %d\nRuta: %s\n",
			doc.Run.ID, doc.Run.FinishedAt, len(doc.Findings), store.BaselinePath())
		return nil
	}
	if format == "json" {
		data, _ := json.MarshalIndent(map[string]any{
			"schema_version": StatusSchema, "action": action, "path": store.BaselinePath(),
		}, "", "  ")
		return report.EmitRaw(a.Stdout, append(data, '\n'))
	}
	fmt.Fprintf(a.Stdout, "Línea base %s: %s\n", baselinePastTense(action), store.BaselinePath())
	return nil
}

func baselinePastTense(action string) string {
	switch action {
	case "set":
		return "fijada"
	case "clear":
		return "eliminada"
	default:
		return action
	}
}
