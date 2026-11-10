package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Continuidad verificable entre corridas.
//
// La identidad de una unidad son sus rutas de partida —archivos o directorios
// reconocidos— con el hash de su fuente, junto con la versión de catálogo y
// el perfil que las produjeron. El store archiva esa identidad al sellar el
// informe; la corrida siguiente la compara con su árbol o revisión y declara
// qué cambió. Las listas orientan prioridad y honestidad: nunca suprimen
// cobertura ni copian un veredicto anterior como actual.

// UnitChanges resume la comparación entre la identidad archivada de una
// unidad y la fuente actual.
type UnitChanges struct {
	Modified []string
	Added    []string
	Deleted  []string
}

// Changed informa si la unidad cambió.
func (c *UnitChanges) Changed() bool {
	return len(c.Modified) > 0 || len(c.Added) > 0 || len(c.Deleted) > 0
}

// ArchiveUnitIdentity recorre las rutas de partida de cada unidad y archiva
// el hash de su fuente: es la identidad que las corridas siguientes
// comparan. Los recorridos son acotados por los límites del catálogo.
func ArchiveUnitIdentity(l *Ledger, root string, cat *Catalog) (map[string]map[string]string, error) {
	if cat == nil {
		return nil, errors.New("auditoría: falta el catálogo para archivar la identidad")
	}
	identity := make(map[string]map[string]string, len(l.Units))
	for i := range l.Units {
		u := &l.Units[i]
		files, err := unitFiles(u, root, cat)
		if err != nil {
			return nil, err
		}
		set := make(map[string]string, len(files))
		for _, f := range files {
			sum, err := hashLocalFile(f)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return nil, fmt.Errorf("unidad %s: %w", u.CoverageID, err)
			}
			rel, relErr := filepath.Rel(root, f)
			if relErr != nil {
				continue
			}
			set[filepath.ToSlash(rel)] = sum
		}
		if len(set) > 0 {
			identity[u.CoverageID] = set
		}
	}
	return identity, nil
}

// EvaluateUnitChanges compara la identidad archivada de una unidad con la
// fuente actual: archivos modificados, añadidos y eliminados.
func EvaluateUnitChanges(id string, identity map[string]string, l *Ledger, root string, cat *Catalog) (*UnitChanges, error) {
	unit := l.UnitByID(id)
	if unit == nil {
		return nil, fmt.Errorf("auditoría: coverage_id desconocido: %s", id)
	}
	files, err := unitFiles(unit, root, cat)
	if err != nil {
		return nil, err
	}
	current := make(map[string]bool, len(files))
	changes := &UnitChanges{Modified: []string{}, Added: []string{}, Deleted: []string{}}
	for _, f := range files {
		rel, relErr := filepath.Rel(root, f)
		if relErr != nil {
			continue
		}
		key := filepath.ToSlash(rel)
		current[key] = true
		sum, err := hashLocalFile(f)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				changes.Deleted = append(changes.Deleted, key)
				continue
			}
			return nil, fmt.Errorf("unidad %s: %w", id, err)
		}
		if prev, ok := identity[key]; ok && prev != sum {
			changes.Modified = append(changes.Modified, key)
		} else if !ok && len(identity) > 0 {
			changes.Added = append(changes.Added, key)
		}
	}
	for key := range identity {
		if !current[key] {
			changes.Deleted = append(changes.Deleted, key)
		}
	}
	sort.Strings(changes.Modified)
	sort.Strings(changes.Added)
	sort.Strings(changes.Deleted)
	return changes, nil
}

// ContinuityFrom resume una corrida anterior con continuidad verificable:
// además del contexto, evalúa qué unidades cambiaron respecto de su
// identidad archivada y exporta los veredictos que exigen revalidación. Los
// cambios de catálogo o de perfil invalidan la reutilización.
func ContinuityFrom(priorState *RunState, currentProfile string, src *Source, cat *Catalog) (*PriorRun, error) {
	if priorState == nil {
		return nil, errors.New("auditoría: la corrida anterior es obligatoria")
	}
	prior := PriorFrom(priorState.Ledger, priorState.Findings, src.sourceRef(), src.dirtiness())
	if priorState.CatalogVersion != cat.SchemaVersion || priorState.Ledger.Profile != currentProfile {
		// La reutilización orientativa caduca con el catálogo o el perfil.
		prior.SameRevisionClean = false
		prior.CoveredSameSource = []string{}
	}
	if len(priorState.UnitIdentity) == 0 || cat == nil {
		return prior, nil
	}

	staleConfirmed := map[string]bool{}
	staleRejected := map[string]bool{}
	for i := range priorState.Candidates.Items {
		cand := &priorState.Candidates.Items[i]
		if cand.State != CandidateDecided || cand.Final == nil {
			continue
		}
		identity, ok := priorState.UnitIdentity[cand.Unit]
		if !ok {
			continue
		}
		changes, err := EvaluateUnitChanges(cand.Unit, identity, priorState.Ledger, src.root, cat)
		if err != nil {
			return nil, err
		}
		if !changes.Changed() {
			continue
		}
		switch cand.Final.Verdict {
		case VerdictConfirmed:
			staleConfirmed[cand.Fingerprint] = true
		case VerdictRejected:
			staleRejected[cand.Fingerprint] = true
		}
	}

	// Un rechazado con la fuente cambiada se reabre: deja de orientar la
	// prioridad como "rechazado sin cambios" y se exporta como pendiente.
	kept := make([]string, 0, len(prior.RejectedFingerprints))
	for _, fp := range prior.RejectedFingerprints {
		if !staleRejected[fp] {
			kept = append(kept, fp)
		}
	}
	prior.RejectedFingerprints = kept
	prior.StaleRejected = sortedKeys(staleRejected)
	prior.StaleConfirmed = sortedKeys(staleConfirmed)
	return prior, nil
}

// unitFiles devuelve los archivos que forman la identidad de una unidad:
// rutas de partida regulares, o el recorrido acotado de un directorio.
func unitFiles(u *Unit, root string, cat *Catalog) ([]string, error) {
	ignoredSet := setName(cat.IgnoreDirs)
	var out []string
	seen := map[string]bool{}
	scanned := 0
	for _, start := range u.StartingPaths {
		base := filepath.Join(root, filepath.FromSlash(start))
		info, err := os.Stat(base)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !seen[base] {
				seen[base] = true
				out = append(out, base)
			}
			continue
		}
		err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if scanned >= cat.Limits.MaxFilesScanned {
				return fs.SkipAll
			}
			if d.IsDir() {
				if p != base && ignoredSet[d.Name()] {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			scanned++
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("unidad %s: %w", u.CoverageID, err)
		}
	}
	sort.Strings(out)
	return out, nil
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
