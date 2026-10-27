package plan

import (
	"sort"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

// Build convierte el descubrimiento en un plan explícito de cobertura. Todo
// motor aplicable queda en estado requested hasta que el orquestador lo
// complete, omita o marque como fallido.
func Build(d discovery.Result, engineIDs []string) Plan {
	ids := append([]string(nil), engineIDs...)
	sort.Strings(ids)

	p := Plan{
		Root:       d.Root,
		Exclusions: append([]discovery.Exclusion(nil), d.Exclusions...),
		Partial:    d.Partial,
		Units:      make([]UnitPlan, 0, len(d.Units)),
	}
	discovery.SortExclusions(p.Exclusions)

	for _, u := range d.Units {
		up := UnitPlan{Unit: u, Engines: make([]EnginePlan, 0, len(ids))}
		for _, id := range ids {
			up.Engines = append(up.Engines, EnginePlan{ID: id, Status: StatusRequested})
		}
		p.Units = append(p.Units, up)
	}
	return p
}

// SetEngineStatus actualiza el estado de un motor en una unidad.
func (p *Plan) SetEngineStatus(unitID, engineID, status, reason string) bool {
	for i := range p.Units {
		if p.Units[i].Unit.ID != unitID {
			continue
		}
		for j := range p.Units[i].Engines {
			if p.Units[i].Engines[j].ID == engineID {
				p.Units[i].Engines[j].Status = status
				if reason != "" {
					p.Units[i].Engines[j].Reason = reason
				}
				return true
			}
		}
	}
	return false
}

// UnitStatus resume el estado de una unidad a partir de sus motores: failed si
// alguno falló, completed si todos completaron, skipped si todos se omitieron.
func (p Plan) UnitStatus(unitID string) string {
	for _, u := range p.Units {
		if u.Unit.ID != unitID {
			continue
		}
		failed, completed, skipped := 0, 0, 0
		for _, e := range u.Engines {
			switch e.Status {
			case StatusFailed:
				failed++
			case StatusCompleted:
				completed++
			case StatusSkipped:
				skipped++
			}
		}
		switch {
		case failed > 0:
			return StatusFailed
		case completed > 0:
			return StatusCompleted
		case skipped > 0 && skipped == len(u.Engines):
			return StatusSkipped
		default:
			return StatusRequested
		}
	}
	return StatusRequested
}
