package cli

import (
	"errors"
	"log/slog"

	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// attachDelta compara el documento con la línea base guardada, si existe.
func (a *App) attachDelta(doc *report.Document) {
	store, err := projectstate.Open(a.Paths, doc.Target.Root)
	if err != nil {
		return
	}
	baseline, err := store.LoadBaseline()
	if err != nil {
		return
	}
	doc.Delta = compare.ReportDelta(compare.Compare(baseline, doc))
}

// persistProjectState guarda latest.json, el índice y los resultados por
// unidad. Un fallo se registra y no cambia el contrato del escaneo.
func (a *App) persistProjectState(doc *report.Document) {
	store, err := projectstate.Open(a.Paths, doc.Target.Root)
	if err != nil {
		slog.Warn("no se pudo abrir el estado del proyecto", "error", err)
		return
	}
	if err := store.SaveLatest(doc); err != nil {
		slog.Warn("no se pudo guardar el último reporte", "error", err)
		return
	}
	idx := projectstate.BuildIndex(doc)
	if err := store.SaveIndex(idx); err != nil {
		slog.Warn("no se pudo guardar el índice del proyecto", "error", err)
	}
	for _, eng := range doc.Tools.Engines {
		for _, st := range eng.Units {
			findings := findingsForUnitEngine(doc, st.ID, eng.ID)
			if err := store.SaveUnit(projectstate.UnitResult{
				Engine: eng.ID, Unit: st.ID, Status: st.Status, Reason: st.Reason,
				Findings: findings,
			}); err != nil {
				slog.Warn("no se pudo guardar el resultado de unidad", "engine", eng.ID, "unit", st.ID, "error", err)
			}
		}
	}
}

func (a *App) loadBaselineFor(root string) (*report.Document, error) {
	store, err := projectstate.Open(a.Paths, root)
	if err != nil {
		return nil, err
	}
	doc, err := store.LoadBaseline()
	if errors.Is(err, projectstate.ErrNoBaseline) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func findingsForUnitEngine(doc *report.Document, unit, engine string) []normalize.Finding {
	out := make([]normalize.Finding, 0)
	for _, f := range doc.Findings {
		has := false
		for _, s := range f.Sources {
			if s.Engine == engine {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		if projectstate.UnitForFinding(doc, &f) != unit {
			continue
		}
		out = append(out, f)
	}
	return out
}
