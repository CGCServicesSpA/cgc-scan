package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// OutOfScope declara una unidad que la selección de rutas dejó fuera. Nunca
// cuenta como cubierta.
type OutOfScope struct {
	Unit   string
	Path   string
	Reason string
}

// BuildOptions configura la construcción del ledger.
type BuildOptions struct {
	Catalog    *Catalog
	Discovery  discovery.Result
	OutOfScope []OutOfScope
	Profile    string
	// MaxAgentInvocations es el presupuesto total; 0 significa sin presupuesto.
	MaxAgentInvocations int
	RunID               string
	Now                 time.Time
	CLIVersion          string
	SourceRef           string
	Dirty               bool
	// Prior es contexto de una corrida anterior; no suprime unidades.
	Prior *PriorRun
	// Limitations declara recortes de alcance ya decididos por la CLI
	// (--include o exclusiones elegidas).
	Limitations []string
}

// BuildLedger construye el ledger determinista a partir del descubrimiento y
// del catálogo. No lee código: solo reconoce señales y reparte unidades.
func BuildLedger(opts BuildOptions) (*Ledger, error) {
	if opts.Catalog == nil {
		return nil, errors.New("auditoría: falta el catálogo")
	}
	if strings.TrimSpace(opts.Discovery.Root) == "" {
		return nil, errors.New("auditoría: falta la raíz del descubrimiento")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	runID := opts.RunID
	if runID == "" {
		runID = report.NewRunID(now)
	}
	cliVersion := opts.CLIVersion
	if cliVersion == "" {
		cliVersion = version.Version
	}
	sourceRef := opts.SourceRef
	if sourceRef == "" {
		sourceRef = "worktree"
	}
	profile := opts.Profile
	if profile == "" {
		profile = ProfileStandard
	}
	switch profile {
	case ProfileQuick, ProfileStandard, ProfileDeep:
	default:
		return nil, fmt.Errorf("perfil desconocido: %q", profile)
	}

	root := opts.Discovery.Root
	units := make([]Unit, 0, len(opts.Discovery.Units))
	seen := map[string]bool{}
	limitations := append([]string{}, opts.Limitations...)

	ordered := append([]discovery.Unit(nil), opts.Discovery.Units...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Path == ordered[j].Path {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Path < ordered[j].Path
	})

	for _, du := range ordered {
		signals, truncated, err := scanSignals(root, du, opts.Catalog)
		if err != nil {
			return nil, err
		}
		if truncated {
			limitations = append(limitations, fmt.Sprintf(
				"reconocimiento truncado en la unidad %q: se alcanzó el tope de %d archivos",
				du.ID, opts.Catalog.Limits.MaxFilesScanned))
		}
		langs := make([]string, 0, len(du.Languages))
		for _, l := range du.Languages {
			langs = append(langs, string(l))
		}
		for _, class := range opts.Catalog.applicableClasses(langs, signals) {
			starts := startingPaths(class, signals, opts.Catalog.Limits.MaxStartingPaths)
			if len(starts) == 0 {
				continue
			}
			id := coverageID(du.ID, class)
			if seen[id] {
				return nil, fmt.Errorf("auditoría: coverage_id colisiona: %s (unidad %q, clase %q)", id, du.ID, class.ID)
			}
			seen[id] = true
			units = append(units, Unit{
				CoverageID:    id,
				Subsystem:     du.ID,
				Domain:        class.Domain,
				Boundary:      class.Boundary,
				AttackClass:   class.ID,
				StartingPaths: starts,
				State:         StatePlanned,
				Wave:          0,
				ReviewedPaths: []string{},
				Checks:        []Check{},
				Candidates:    []string{},
				Unresolved:    []string{},
				Attempts:      []Attempt{},
			})
		}
	}

	for _, oos := range opts.OutOfScope {
		if strings.TrimSpace(oos.Unit) == "" {
			return nil, errors.New("auditoría: unidad fuera de alcance sin identificador")
		}
		if !ValidRepoPath(oos.Path) && oos.Path != "." {
			return nil, fmt.Errorf("auditoría: ruta fuera de alcance inválida: %q", oos.Path)
		}
		reason := strings.TrimSpace(oos.Reason)
		if reason == "" {
			reason = "fuera de alcance por selección de rutas"
		}
		id := slugID(oos.Unit) + "/scope/excluded"
		if seen[id] {
			return nil, fmt.Errorf("auditoría: coverage_id colisiona: %s", id)
		}
		seen[id] = true
		units = append(units, Unit{
			CoverageID:    id,
			Subsystem:     oos.Unit,
			Domain:        "scope",
			Boundary:      "excluded",
			AttackClass:   "out-of-scope",
			StartingPaths: []string{oos.Path},
			State:         StateOutOfScope,
			Wave:          0,
			ReviewedPaths: []string{},
			Checks:        []Check{},
			Candidates:    []string{},
			Unresolved:    []string{},
			Attempts:      []Attempt{},
			Reason:        reason,
		})
	}

	var budget *Budget
	if opts.MaxAgentInvocations > 0 {
		budget = &Budget{MaxAgentInvocations: opts.MaxAgentInvocations}
	}

	ledger := &Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Run: Run{
			ID: runID, StartedAt: now.Format(time.RFC3339),
			CLIVersion: cliVersion, SourceRef: sourceRef, Dirty: opts.Dirty,
		},
		Target:      Target{Root: root, LocalID: report.LocalID(root)},
		Profile:     profile,
		Budget:      budget,
		RunStatus:   StatusInProgress,
		Units:       units,
		Limitations: limitations,
		Prior:       normalizePrior(opts.Prior),
	}
	ledger.Recompute()
	if err := ValidateLedgerSemantics(ledger); err != nil {
		return nil, fmt.Errorf("auditoría: el ledger generado no cumple el contrato: %w", err)
	}
	return ledger, nil
}

// scanSignals reconoce, con un recorrido acotado, qué señales presenta la
// unidad. Devuelve rutas relativas al repositorio, ordenadas.
func scanSignals(root string, unit discovery.Unit, cat *Catalog) (map[string][]string, bool, error) {
	base := root
	if unit.Path != "" && unit.Path != "." {
		base = filepath.Join(root, filepath.FromSlash(unit.Path))
	}
	info, err := os.Stat(base)
	if err != nil {
		return nil, false, fmt.Errorf("auditoría: abrir unidad %q: %w", unit.ID, err)
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("auditoría: la unidad %q no es un directorio", unit.ID)
	}

	sourceExt := map[string]bool{}
	for _, lang := range unit.Languages {
		spec, ok := cat.Languages[string(lang)]
		if !ok {
			continue
		}
		for _, ext := range spec.Extensions {
			sourceExt[ext] = true
		}
	}
	ignored := map[string]bool{}
	for _, d := range cat.IgnoreDirs {
		ignored[d] = true
	}
	manifestNames := setName(cat.Signals.Manifest.FileNames)
	lockfileNames := setName(cat.Signals.Lockfile.FileNames)
	configExt := setName(cat.Signals.Config.Extensions)

	found := map[string]map[string]bool{}
	add := func(kind, rel string) {
		if found[kind] == nil {
			found[kind] = map[string]bool{}
		}
		found[kind][rel] = true
	}
	scanned := 0
	truncated := false
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != base && ignored[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		scanned++
		if scanned > cat.Limits.MaxFilesScanned {
			truncated = true
			return fs.SkipAll
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		baseName := path.Base(rel)
		if sourceExt[path.Ext(baseName)] {
			add(SignalSource, rel)
		}
		if manifestNames[baseName] {
			add(SignalManifest, rel)
		}
		if lockfileNames[baseName] {
			add(SignalLockfile, rel)
		}
		if matchAnyPath(cat.Signals.CI.PathPatterns, rel) {
			add(SignalCI, rel)
		}
		if matchAnyBase(cat.Signals.Container.FilePatterns, baseName) {
			add(SignalContainer, rel)
		}
		if configExt[path.Ext(baseName)] {
			add(SignalConfig, rel)
		}
		return nil
	})
	if err != nil {
		return nil, truncated, fmt.Errorf("auditoría: recorrer unidad %q: %w", unit.ID, err)
	}

	out := make(map[string][]string, len(found))
	for kind, set := range found {
		list := make([]string, 0, len(set))
		for rel := range set {
			list = append(list, rel)
		}
		sort.Strings(list)
		out[kind] = list
	}
	return out, truncated, nil
}

// startingPaths elige los puntos de partida de una clase respetando el orden
// declarado en requires y el tope del catálogo.
func startingPaths(class Class, signals map[string][]string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	for _, req := range class.Requires {
		for _, rel := range signals[req] {
			if seen[rel] {
				continue
			}
			seen[rel] = true
			out = append(out, rel)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// PriorFrom resume una corrida anterior como contexto. onlySameRevision indica
// que la fuente es la misma y ambos árboles estaban limpios; aun así, el motor
// no omite ninguna unidad actual.
func PriorFrom(prior *Ledger, priorFindings *Findings, currentSourceRef string, currentDirty bool) *PriorRun {
	if prior == nil {
		return nil
	}
	pr := &PriorRun{
		RunID: prior.Run.ID, SourceRef: prior.Run.SourceRef,
		CoveredSameSource:           []string{},
		RejectedFingerprints:        []string{},
		NeedsValidationFingerprints: []string{},
	}
	pr.SameRevisionClean = !currentDirty && !prior.Run.Dirty &&
		prior.Run.SourceRef == currentSourceRef &&
		prior.Run.SourceRef != "" && prior.Run.SourceRef != "worktree"
	for _, u := range prior.Units {
		if u.State == StateCovered {
			pr.CoveredSameSource = append(pr.CoveredSameSource, u.CoverageID)
		}
	}
	if priorFindings != nil {
		for _, r := range priorFindings.Findings {
			switch r.Verdict {
			case VerdictRejected:
				pr.RejectedFingerprints = append(pr.RejectedFingerprints, r.Fingerprint)
			case VerdictNeedsValidation:
				pr.NeedsValidationFingerprints = append(pr.NeedsValidationFingerprints, r.Fingerprint)
			}
		}
	}
	return pr
}

func normalizePrior(p *PriorRun) *PriorRun {
	if p == nil {
		return nil
	}
	out := *p
	out.CoveredSameSource = nonNil(out.CoveredSameSource)
	out.RejectedFingerprints = nonNil(out.RejectedFingerprints)
	out.NeedsValidationFingerprints = nonNil(out.NeedsValidationFingerprints)
	sort.Strings(out.CoveredSameSource)
	sort.Strings(out.RejectedFingerprints)
	sort.Strings(out.NeedsValidationFingerprints)
	return &out
}

func coverageID(unitID string, class Class) string {
	return slugID(unitID) + "/" + class.Domain + "/" + class.ID
}

// slugID convierte un identificador de unidad en un segmento válido para el
// coverage_id.
func slugID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		switch {
		case valid:
			b.WriteRune(r)
			lastDash = r == '-'
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "root"
	}
	return out
}

func setName(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, s := range items {
		out[s] = true
	}
	return out
}

func matchAnyPath(patterns []string, rel string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, rel); err == nil && ok {
			return true
		}
	}
	return false
}

func matchAnyBase(patterns []string, base string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, base); err == nil && ok {
			return true
		}
	}
	return false
}
