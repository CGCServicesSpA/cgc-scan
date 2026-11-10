package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/remediation"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// VerifySchema identifica el documento de `verify`.
const VerifySchema = "verify-1.0.0"

// VerifyDocument es el resultado de un reescaneo focalizado.
type VerifyDocument struct {
	SchemaVersion string         `json:"schema_version"`
	Selector      string         `json:"selector"`
	Kind          string         `json:"kind"` // fingerprint | group
	Group         string         `json:"group,omitempty"`
	Fingerprint   string         `json:"fingerprint,omitempty"`
	Unit          string         `json:"unit,omitempty"`
	Units         []string       `json:"units"`
	Engines       []string       `json:"engines"`
	Status        string         `json:"status"` // resolved | persistent | partial
	Fixes         []VerifyFix    `json:"fixes"`
	Delta         *report.Delta  `json:"delta,omitempty"`
	ReportPath    string         `json:"report_path"`
	Errors        []report.Error `json:"errors"`
}

// VerifyFix es el estado de una huella del selector.
type VerifyFix struct {
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"` // resolved | persistent | not_evaluated
}

func (a *App) newVerifyCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "verify <fingerprint|grupo> [ruta]",
		Short: "Reescanea solo la unidad y los motores afectados y compara",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			target := ""
			if len(args) == 2 {
				target = args[1]
			}
			return a.runVerify(cmd, args[0], target, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "formato: json|text")
	return cmd
}

func (a *App) runVerify(cmd *cobra.Command, selector, target, format string) error {
	store, err := a.projectStore(target)
	if err != nil {
		return err
	}
	previous, err := store.LoadLatest()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	idx, _ := store.LoadIndex()
	baseline, _ := store.LoadBaseline()
	sel, err := resolveSelector(previous, baseline, idx, selector)
	if err != nil {
		return err
	}

	opts := verifyScanOptions(previous, sel)
	res, err := a.executeScan(cmd, opts)
	if err != nil {
		return err
	}
	merged := mergeVerification(previous, res.Doc, sel)
	merged.Delta = nil
	if baseline, err := store.LoadBaseline(); err == nil {
		merged.Delta = compare.ReportDelta(compare.Compare(baseline, merged))
	}
	merged.Normalize()
	if err := store.SaveLatest(merged); err != nil {
		return IncompleteErrorf("guardar el resultado de verify: %v", err)
	}
	if err := store.SaveIndex(projectstate.BuildIndex(merged)); err != nil {
		return IncompleteErrorf("guardar el índice de verify: %v", err)
	}
	a.persistUnits(merged, store)

	out := buildVerifyDocument(store, merged, sel, res.Doc)
	if format == "json" {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		if err := report.EmitRaw(a.Stdout, append(data, '\n')); err != nil {
			return IncompleteErrorf("%v", err)
		}
	} else {
		fmt.Fprint(a.Stdout, renderVerify(out))
	}
	if out.Status == "persistent" || out.Status == "partial" {
		return &ExitError{Code: codeForVerify(out, res.ExitCode)}
	}
	if res.ExitCode != 0 {
		return &ExitError{Code: res.ExitCode}
	}
	return nil
}

type selectorInfo struct {
	ID          string
	Kind        string // fingerprint | group
	Group       *report.RemediationGroup
	Fingerprint string
	Unit        string
	Engines     []string
	Fixes       []string
}

func resolveSelector(doc, fallback *report.Document, idx projectstate.Index, selector string) (selectorInfo, error) {
	if sel, ok := selectorIn(doc, selector); ok {
		return sel, nil
	}
	if fallback != nil {
		if sel, ok := selectorIn(fallback, selector); ok {
			return sel, nil
		}
	}
	entry, ok := idx.Findings[selector]
	if !ok {
		return selectorInfo{}, UsageErrorf("no existe la huella ni el grupo %q en el último reporte", selector)
	}
	sort.Strings(entry.Engines)
	entry.Engines = dedupeList(entry.Engines)
	return selectorInfo{
		ID: selector, Kind: "fingerprint", Fingerprint: selector,
		Unit: entry.Unit, Engines: entry.Engines, Fixes: []string{selector},
	}, nil
}

func selectorIn(doc *report.Document, selector string) (selectorInfo, bool) {
	if doc == nil {
		return selectorInfo{}, false
	}
	for i := range doc.RemediationGroups {
		g := doc.RemediationGroups[i]
		if g.ID != selector {
			continue
		}
		fixes := append([]string{}, g.Fixes...)
		return selectorInfo{
			ID: g.ID, Kind: "group", Group: &g, Unit: g.Unit,
			Engines: groupEngines(doc, fixes), Fixes: fixes,
		}, true
	}
	for _, f := range doc.Findings {
		if f.Fingerprint != selector {
			continue
		}
		engines := make([]string, 0, len(f.Sources))
		for _, s := range f.Sources {
			engines = append(engines, s.Engine)
		}
		sort.Strings(engines)
		engines = dedupeList(engines)
		return selectorInfo{
			ID: selector, Kind: "fingerprint", Fingerprint: selector,
			Unit: projectstate.UnitForFinding(doc, &f), Engines: engines, Fixes: []string{selector},
		}, true
	}
	return selectorInfo{}, false
}

func verifyScanOptions(previous *report.Document, sel selectorInfo) scanOptions {
	opts := scanOptions{
		Target: previous.Target.Root, Format: "json",
		FailOn: "high", RequireIsolation: "configured",
		NoPersist: true, Engines: sel.Engines,
	}
	if v, ok := previous.Run.Arguments["trivy_mode"].(string); ok && v != "" {
		opts.TrivyMode = v
	}
	if v, ok := previous.Run.Arguments["offline"].(bool); ok {
		opts.Offline = v
	}
	if v, ok := previous.Run.Arguments["no_auto_install"].(bool); ok {
		opts.NoAutoInstall = v
	}
	if previous.Policy.FailOn != "" {
		opts.FailOn = previous.Policy.FailOn
	}
	opts.Limitations = []string{"verify focalizado: " + sel.ID}
	units := map[string]bool{}
	engines := map[string]bool{}
	for _, e := range sel.Engines {
		engines[e] = true
	}
	for _, u := range previous.Target.Units {
		if u.ID == sel.Unit {
			units[u.ID] = true
		}
	}
	// Trivy y Semgrep recorren el repositorio completo: se ejecutan en la
	// unidad repository.
	for _, u := range previous.Target.Units {
		if u.Kind == "repository" && (engines["trivy"] || engines["semgrep"] || len(sel.Engines) == 0) {
			units[u.ID] = true
		}
	}
	if len(units) == 0 && sel.Unit != "" {
		units[sel.Unit] = true
	}
	for id := range units {
		opts.Units = append(opts.Units, id)
	}
	sort.Strings(opts.Units)
	return opts
}

// mergeVerification integra el resultado focalizado en el reporte anterior sin
// perder los hallazgos de unidades o motores que no se volvieron a evaluar.
func mergeVerification(previous, current *report.Document, sel selectorInfo) *report.Document {
	verified := map[string]bool{}
	for _, e := range sel.Engines {
		verified[e] = true
	}
	// Si no se declararon motores, se usan los que realmente corrieron.
	for _, e := range current.Tools.Engines {
		if len(sel.Engines) == 0 {
			verified[e.ID] = true
		}
	}
	full := map[string]bool{}
	for _, e := range current.Tools.Engines {
		for _, st := range e.Units {
			for _, u := range previous.Target.Units {
				if u.ID == st.ID && u.Kind == "repository" {
					full[e.ID] = true
				}
			}
		}
	}
	scanUnits := map[string]bool{}
	for _, e := range current.Tools.Engines {
		for _, st := range e.Units {
			scanUnits[st.ID] = true
		}
	}

	kept := make([]normalize.Finding, 0, len(previous.Findings)+len(current.Findings))
	seen := map[string]bool{}
	for _, f := range previous.Findings {
		if affectedFinding(previous, f, verified, full, scanUnits) {
			continue
		}
		kept = append(kept, f)
		seen[f.Fingerprint] = true
	}
	for _, f := range current.Findings {
		if seen[f.Fingerprint] {
			continue
		}
		kept = append(kept, f)
		seen[f.Fingerprint] = true
	}

	merged := *current
	merged.Findings = normalize.Correlate(kept)
	merged.Coverage = previous.Coverage
	merged.Coverage.Partial = partialAfterMerge(previous, current)
	merged.Coverage.Limitations = append(append([]string{}, previous.Coverage.Limitations...),
		"verify focalizado: solo se reevaluaron "+strings.Join(sel.Engines, ", ")+" en "+sel.Unit)
	merged.Tools = previous.Tools
	mergeEngines(&merged, current)
	merged.Errors = mergeErrors(previous.Errors, current.Errors, verified, scanUnits)
	merged.Validation = current.Validation
	merged.Policy = previous.Policy
	merged.Run.Arguments = copyArgs(current.Run.Arguments)
	merged.Run.Arguments["verify"] = sel.ID
	merged.Target.VCS = current.Target.VCS

	remediation.ApplyPriority(merged.Findings)
	merged.RemediationGroups = remediation.Build(&merged)
	merged.NextActions = remediation.Actions(&merged, merged.RemediationGroups)
	// Recalcular contadores de hallazgos por motor y unidad.
	recountReportFindings(&merged)
	merged.Normalize()
	return &merged
}

func affectedFinding(doc *report.Document, f normalize.Finding, verified, full, scanUnits map[string]bool) bool {
	engines := map[string]bool{}
	for _, s := range f.Sources {
		if verified[s.Engine] {
			engines[s.Engine] = true
		}
	}
	if len(engines) == 0 {
		return false
	}
	for e := range engines {
		if full[e] {
			return true
		}
	}
	return scanUnits[projectstate.UnitForFinding(doc, &f)]
}

func mergeEngines(merged *report.Document, current *report.Document) {
	byID := map[string]int{}
	for i, e := range merged.Tools.Engines {
		byID[e.ID] = i
	}
	for _, cur := range current.Tools.Engines {
		i, ok := byID[cur.ID]
		if !ok {
			merged.Tools.Engines = append(merged.Tools.Engines, cur)
			continue
		}
		prev := merged.Tools.Engines[i]
		states := map[string]report.EngineState{}
		for _, st := range prev.Units {
			states[st.ID] = st
		}
		for _, st := range cur.Units {
			states[st.ID] = st
		}
		prev.Units = make([]report.EngineState, 0, len(states))
		ids := make([]string, 0, len(states))
		for id := range states {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			prev.Units = append(prev.Units, states[id])
		}
		prev.Status = cur.Status
		prev.DurationMS = cur.DurationMS
		prev.DB = cur.DB
		prev.Rules = cur.Rules
		prev.Preparation = cur.Preparation
		merged.Tools.Engines[i] = prev
	}
}

// partialAfterMerge decide si la cobertura sigue siendo parcial tras el
// reescaneo. Un error del motor verificado deja de contar si ya no ocurre; un
// alcance restringido de la ejecución original se conserva.
func partialAfterMerge(previous, current *report.Document) bool {
	if len(current.Errors) > 0 {
		return true
	}
	if len(previous.Coverage.NotAnalyzed) > 0 {
		return true
	}
	for _, e := range previous.Coverage.Exclusions {
		if e.Origin != "intrinsic" {
			return true
		}
	}
	for _, l := range previous.Coverage.Limitations {
		if strings.HasPrefix(l, "alcance ") || strings.HasPrefix(l, "sin revisión") {
			return true
		}
	}
	if inc, ok := previous.Run.Arguments["include"].([]any); ok && len(inc) > 0 {
		return true
	}
	for _, u := range previous.Coverage.Units {
		if u.Status == "failed" || u.Status == "requested" {
			return true
		}
	}
	return false
}

func mergeErrors(previous, current []report.Error, verified, scanUnits map[string]bool) []report.Error {
	out := make([]report.Error, 0, len(previous)+len(current))
	for _, e := range previous {
		engine, unit := splitScope(e.Scope)
		if verified[engine] && scanUnits[unit] {
			continue
		}
		out = append(out, e)
	}
	out = append(out, current...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

func recountReportFindings(doc *report.Document) {
	counts := map[string]int{}
	for _, f := range doc.Findings {
		unit := projectstate.UnitForFinding(doc, &f)
		for _, s := range f.Sources {
			counts[s.Engine+"|"+unit]++
		}
	}
	unitStatus := map[string][]report.EngineState{}
	for i := range doc.Tools.Engines {
		e := &doc.Tools.Engines[i]
		for j := range e.Units {
			st := &e.Units[j]
			st.Findings = counts[e.ID+"|"+st.ID]
			unitStatus[st.ID] = append(unitStatus[st.ID], *st)
		}
	}
	for i := range doc.Coverage.Units {
		u := &doc.Coverage.Units[i]
		if states, ok := unitStatus[u.ID]; ok {
			u.Engines = states
		}
	}
}

func buildVerifyDocument(store *projectstate.Store, merged *report.Document, sel selectorInfo, current *report.Document) VerifyDocument {
	out := VerifyDocument{
		SchemaVersion: VerifySchema, Selector: sel.ID, Kind: sel.Kind,
		Group: groupOrEmpty(sel), Fingerprint: sel.Fingerprint,
		Unit: sel.Unit, Units: append([]string{}, sel.UnitsForDocument(merged)...),
		Engines: append([]string{}, sel.Engines...), Fixes: []VerifyFix{},
		Delta: merged.Delta, ReportPath: store.LatestPath(), Errors: current.Errors,
	}
	if out.Units == nil {
		out.Units = []string{}
	}
	if out.Engines == nil {
		out.Engines = []string{}
	}
	present := map[string]bool{}
	for _, f := range merged.Findings {
		present[f.Fingerprint] = true
	}
	resolved, persistent := 0, 0
	for _, fp := range sel.Fixes {
		status := "resolved"
		if present[fp] {
			status = "persistent"
			persistent++
		} else {
			resolved++
		}
		out.Fixes = append(out.Fixes, VerifyFix{Fingerprint: fp, Status: status})
	}
	switch {
	case len(current.Errors) > 0 || current.Coverage.Partial && len(sel.Fixes) == 0:
		out.Status = "partial"
	case persistent > 0:
		out.Status = "persistent"
	default:
		out.Status = "resolved"
	}
	return out
}

func groupOrEmpty(sel selectorInfo) string {
	if sel.Kind == "group" {
		return sel.ID
	}
	return ""
}

func (sel selectorInfo) UnitsForDocument(doc *report.Document) []string {
	var out []string
	if sel.Unit != "" {
		out = append(out, sel.Unit)
	}
	return out
}

func renderVerify(v VerifyDocument) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Verificación: %s (%s)\n", v.Selector, v.Status)
	fmt.Fprintf(&b, "Unidades: %s · Motores: %s\n", strings.Join(v.Units, ", "), strings.Join(v.Engines, ", "))
	for _, f := range v.Fixes {
		fmt.Fprintf(&b, "  %s: %s\n", f.Fingerprint, f.Status)
	}
	if v.Delta != nil {
		fmt.Fprintf(&b, "Delta: nuevo %d, persistente %d, resuelto %d, no evaluado %d\n",
			len(v.Delta.New), len(v.Delta.Persistent), len(v.Delta.Resolved), len(v.Delta.NotEvaluated))
	}
	return b.String()
}

func codeForVerify(out VerifyDocument, scanCode int) int {
	if out.Status == "partial" && scanCode == 0 {
		return 3
	}
	if out.Status == "persistent" && scanCode == 0 {
		return 1
	}
	return scanCode
}

func dedupeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func (a *App) persistUnits(doc *report.Document, store *projectstate.Store) {
	for _, eng := range doc.Tools.Engines {
		for _, st := range eng.Units {
			_ = store.SaveUnit(projectstate.UnitResult{
				Engine: eng.ID, Unit: st.ID, Status: st.Status, Reason: st.Reason,
				Findings: findingsForUnitEngine(doc, st.ID, eng.ID),
			})
		}
	}
}

func copyArgs(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func splitScope(scope string) (engine, unit string) {
	if i := strings.Index(scope, ":"); i >= 0 {
		return scope[:i], scope[i+1:]
	}
	return scope, ""
}
