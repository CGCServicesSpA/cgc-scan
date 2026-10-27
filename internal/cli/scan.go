package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/trivy"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/policy"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// scanOptions agrupa los flags efectivos de un escaneo.
type scanOptions struct {
	Target           string
	Format           string
	FailOn           string
	ReportOut        string
	TrivyMode        string
	NoAutoInstall    bool
	Offline          bool
	RequireIsolation string
	Include          []string
	Exclude          []string
	Timeout          time.Duration
	Concurrency      int
}

func (a *App) runScan(cmd *cobra.Command, opts scanOptions) error {
	started := a.Now()
	if opts.Target == "" {
		wd, err := os.Getwd()
		if err != nil {
			return IncompleteErrorf("obtener el directorio actual: %v", err)
		}
		opts.Target = wd
	}
	target, err := filepath.Abs(opts.Target)
	if err != nil {
		return UsageErrorf("ruta objetivo inválida: %v", err)
	}

	if err := a.Paths.EnsureDirs(); err != nil {
		return IncompleteErrorf("preparar directorios: %v", err)
	}

	// Paso 2: resolver el runner antes de leer el proyecto (design §1.2).
	mode := opts.TrivyMode
	if mode == "" {
		mode = "global" // H2 incorpora la detección de Docker
	}
	if mode != "global" {
		return IncompleteErrorf("la modalidad %q de Trivy se habilita en H2", mode)
	}

	ms, err := manifest.Load()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	engine, err := ms.Engine("trivy")
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	globalRunner := &runner.Global{Paths: a.Paths}
	level, err := globalRunner.Isolation(cmd.Context())
	if err != nil {
		return IncompleteErrorf("determinar aislamiento: %v", err)
	}
	required := runner.IsolationLevel(opts.RequireIsolation)
	if required.Rank() > level.Rank() {
		return IncompleteErrorf("se exigió aislamiento %s y el runner global ofrece %s; el proyecto no se analizó", required, level)
	}

	slog.Info("preparando Trivy", "version", engine.Version, "mode", mode)

	var binPath string
	if opts.Offline || opts.NoAutoInstall {
		candidate := filepath.Join(a.Paths.EngineDir("trivy", engine.Version), "trivy")
		if _, statErr := os.Stat(candidate); statErr != nil {
			return IncompleteErrorf("no hay un Trivy %s instalado y %s prohíbe descargarlo", engine.Version,
				map[bool]string{true: "--offline", false: "--no-auto-install"}[opts.Offline])
		}
		binPath = candidate
	} else {
		res, err := provision.EnsureTrivy(cmd.Context(), provision.Options{Paths: a.Paths, Manifest: ms})
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		binPath = res.Path
		if res.Installed {
			slog.Info("Trivy instalado", "path", binPath)
		}
	}

	// Paso 3: bloqueo exclusivo, base, bloqueo compartido durante el escaneo.
	cacheDir := a.Paths.TrivyCacheDir()
	lockPath := filepath.Join(a.Paths.LocksDir(), "trivy-cache.lock")
	exclusive, err := platform.Acquire(cmd.Context(), lockPath, false, 5*time.Minute)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	var dbInfo provision.DBInfo
	var prep []report.Preparation
	if opts.Offline {
		dbInfo, err = provision.CheckDBOffline(cacheDir, 72*time.Hour, 7*24*time.Hour)
		if err != nil {
			_ = exclusive.Release()
			return IncompleteErrorf("%v", err)
		}
		prep = append(prep, report.Preparation{Action: "db", Status: "ok", Detail: "offline: base local validada"})
	} else {
		dbInfo, err = provision.UpdateDB(cmd.Context(), globalRunner, binPath, cacheDir, 15*time.Minute)
		if err != nil {
			_ = exclusive.Release()
			return IncompleteErrorf("%v", err)
		}
		prep = append(prep, report.Preparation{Action: "db", Status: "ok", Detail: "base actualizada"})
	}
	if err := exclusive.Release(); err != nil {
		return IncompleteErrorf("%v", err)
	}
	shared, err := platform.Acquire(cmd.Context(), lockPath, true, 5*time.Minute)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	defer func() { _ = shared.Release() }()

	// Paso 4: aislamiento ya verificado; requisitos dependientes del proyecto
	// se comprueban en el adaptador.
	// Paso 5: descubrimiento y plan.
	exclusions := make([]discovery.Exclusion, 0, len(opts.Exclude))
	for _, p := range opts.Exclude {
		exclusions = append(exclusions, discovery.Exclusion{
			Pattern: p, Origin: discovery.OriginCLI, Reason: "exclusión de la línea de comandos",
		})
	}
	disc, err := discovery.Discover(cmd.Context(), discovery.Options{
		Target: target, Exclude: exclusions, ReportOut: opts.ReportOut,
	})
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	p := plan.Build(disc, []string{"trivy"})
	p.Include = opts.Include
	p.Exclude = opts.Exclude
	plan.ApplySelection(&p)

	salt, err := masking.LoadOrCreateSalt(a.Paths.SaltFile())
	if err != nil {
		return IncompleteErrorf("cargar la sal de enmascarado: %v", err)
	}
	masker, err := masking.NewMasker(salt)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	trivyAdapter := trivy.New(masker)
	trivyAdapter.CacheDir = cacheDir
	trivyAdapter.Binary = binPath
	trivyAdapter.RunnerKind = mode

	// Paso 6: ejecución.
	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = 4
	}
	out := orchestrator.Execute(cmd.Context(), p, []orchestrator.Engine{{
		ID:        trivy.ID,
		Version:   engine.Version,
		Mode:      mode,
		Adapter:   trivyAdapter,
		Runner:    globalRunner,
		Isolation: level,
	}}, concurrency)

	// Pasos 7 y 8: política.
	failOn := normalizeSeverity(opts.FailOn)
	eval := policy.Evaluate(out.Findings, failOn, true, nil)

	// Paso 9: reporte.
	doc := buildDocument(cmd, opts, started, time.Since(started), disc, out, dbInfo, prep, binPath, level, eval, engine.Image)

	if opts.ReportOut != "" {
		if err := a.validateReportOut(target, doc, opts.ReportOut); err != nil {
			return IncompleteErrorf("%v", err)
		}
		if err := report.WriteFile(opts.ReportOut, doc); err != nil {
			return IncompleteErrorf("%v", err)
		}
	}
	if err := report.Emit(a.Stdout, doc, opts.Format); err != nil {
		return IncompleteErrorf("%v", err)
	}

	code := policy.Decide(
		policy.RunOutcome{Complete: out.Complete, Canceled: out.Canceled},
		policy.PolicyOutcome{Violated: eval.Violated},
	)
	if code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

func normalizeSeverity(s string) normalize.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return normalize.SeverityCritical
	case "high", "":
		return normalize.SeverityHigh
	case "medium":
		return normalize.SeverityMedium
	case "low":
		return normalize.SeverityLow
	case "info":
		return normalize.SeverityInformational
	default:
		return normalize.SeverityUnknown
	}
}

// validateReportOut impide sobrescribir código del proyecto y exige que el
// destino sea escribible.
func (a *App) validateReportOut(root string, _ *report.Document, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if rel, err := discovery.Rel(root, abs); err == nil && rel != "" {
		if info, statErr := os.Stat(abs); statErr == nil && info.Mode().IsRegular() {
			if !strings.EqualFold(filepath.Ext(abs), ".json") {
				return fmt.Errorf("--report-out se niega a sobrescribir %s: no es un archivo JSON", rel)
			}
		}
	}
	return nil
}

func buildDocument(cmd *cobra.Command, opts scanOptions, started time.Time, elapsed time.Duration,
	disc discovery.Result, out orchestrator.Outcome, db provision.DBInfo, prep []report.Preparation,
	binPath string, level runner.IsolationLevel, eval policy.Evaluation, image string) *report.Document {

	units := make([]report.UnitInfo, 0, len(disc.Units))
	for _, u := range disc.Units {
		units = append(units, report.UnitInfo{
			ID: u.ID, Path: u.Path, Kind: u.Kind, Languages: u.Languages, Manifests: u.Manifests,
		})
	}
	exclusions := make([]report.ExclusionReport, 0, len(disc.Exclusions))
	for _, e := range disc.Exclusions {
		exclusions = append(exclusions, report.ExclusionReport{
			Pattern: e.Pattern, Origin: string(e.Origin), Reason: e.Reason,
		})
	}
	notAnalyzed := make([]report.NotAnalyzedReport, 0, len(out.Plan.NotAnalyzed))
	for _, n := range out.Plan.NotAnalyzed {
		notAnalyzed = append(notAnalyzed, report.NotAnalyzedReport{
			Unit: n.Unit, Path: n.Path, Reason: n.Reason, Patterns: n.Patterns,
		})
	}

	// Estado por unidad y contadores por motor.
	findingsByUnitEngine := map[string]map[string]int{}
	for _, e := range out.Engines {
		for _, st := range e.Units {
			if findingsByUnitEngine[st.Unit] == nil {
				findingsByUnitEngine[st.Unit] = map[string]int{}
			}
			findingsByUnitEngine[st.Unit][e.ID] = st.Findings
		}
	}
	coverageUnits := make([]report.UnitCoverage, 0, len(out.Plan.Units))
	for _, u := range out.Plan.Units {
		cu := report.UnitCoverage{
			ID: u.Unit.ID, Path: u.Unit.Path, Languages: u.Unit.Languages,
			Status: out.Plan.UnitStatus(u.Unit.ID),
		}
		for _, e := range u.Engines {
			cu.Engines = append(cu.Engines, report.EngineState{
				ID: e.ID, Status: e.Status, Reason: e.Reason,
				Findings: findingsByUnitEngine[u.Unit.ID][e.ID],
			})
		}
		coverageUnits = append(coverageUnits, cu)
	}

	engines := make([]report.EngineReport, 0, len(out.Engines))
	for _, e := range out.Engines {
		er := report.EngineReport{
			ID: e.ID, Version: e.Version, Status: e.Status, Mode: e.Mode,
			Isolation: string(e.Isolation), DurationMS: e.Duration.Milliseconds(),
			Path: binPath, Image: image,
		}
		for _, st := range e.Units {
			er.Units = append(er.Units, report.EngineState{
				ID: st.Unit, Status: st.Status, Reason: st.Reason, Findings: st.Findings,
			})
		}
		updated := db.UpdatedAt.UTC().Format(time.RFC3339)
		age := db.AgeSeconds
		schema := db.Schema
		er.DB = &report.DBState{
			Source: "trivy-db", Status: db.Status, UpdatedAt: &updated,
			AgeSeconds: &age, Schema: &schema,
		}
		er.Preparation = prep
		if db.Status == "stale" {
			er.Limitations = append(er.Limitations, "base con antigüedad superior al aviso")
		}
		er.Limitations = append(er.Limitations, "checks de configuración embebidos (sin bundle descargado)")
		engines = append(engines, er)
	}

	limitations := []string{}
	if len(disc.Units) == 0 {
		limitations = append(limitations, "no se detectaron unidades analizables en el alcance")
	}
	if opts.Offline {
		limitations = append(limitations, "modo offline: no se actualizaron motores ni bases")
	}

	include := opts.Include
	if include == nil {
		include = []string{}
	}
	exclude := opts.Exclude
	if exclude == nil {
		exclude = []string{}
	}
	args := map[string]any{
		"format":            opts.Format,
		"fail_on":           opts.FailOn,
		"offline":           opts.Offline,
		"trivy_mode":        out.Engines[0].Mode,
		"require_isolation": opts.RequireIsolation,
		"no_auto_install":   opts.NoAutoInstall,
		"include":           include,
		"exclude":           exclude,
	}
	origins := []report.ConfigOrigin{
		{Key: "fail_on", Value: opts.FailOn, Origin: originOf(cmd, "fail-on", "default")},
		{Key: "trivy_mode", Value: out.Engines[0].Mode, Origin: originOf(cmd, "trivy-mode", "default")},
		{Key: "offline", Value: opts.Offline, Origin: originOf(cmd, "offline", "default")},
	}

	errs := make([]report.Error, 0, len(out.Errors))
	for _, e := range out.Errors {
		errs = append(errs, report.Error{Code: e.Code, Scope: e.Scope, Message: e.Message, Retryable: e.Retryable})
	}

	doc := &report.Document{
		SchemaVersion: version.SchemaVersion,
		Run:           report.NewRun(report.NewRunID(started), started, elapsed, args),
		Target: report.Target{
			Root: disc.Root, LocalID: report.LocalID(disc.Root),
			VCS: report.VCS{Available: false}, Units: units,
		},
		Coverage: report.Coverage{
			Partial:     out.Plan.Partial,
			Scope:       report.Scope{Root: disc.Root, Include: opts.Include, Exclude: opts.Exclude},
			Exclusions:  exclusions,
			NotAnalyzed: notAnalyzed,
			Units:       coverageUnits,
			Limitations: limitations,
		},
		Tools:      report.Tools{Engines: engines},
		Isolation:  report.Isolation{Level: string(level), VerifiedBy: ""},
		Validation: report.Validation{Recipes: []report.Recipe{}, Unresolved: []report.Unresolved{}},
		Findings:   out.Findings,
		Policy: report.Policy{
			FailOn: string(eval.FailOn), Violated: eval.Violated, UnknownCounts: eval.UnknownCounts,
			Exceptions: []report.ExceptionReport{}, SuppressedCount: eval.SuppressedCount,
		},
		Errors: errs,
	}
	doc.Run.ConfigOrigin = origins
	if out.Canceled {
		doc.Run.Cancelled = true
	}
	doc.Normalize()
	return doc
}

func originOf(cmd *cobra.Command, flag, fallback string) string {
	if cmd != nil && cmd.Flags().Changed(flag) {
		return "flag"
	}
	return fallback
}
