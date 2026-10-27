package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/trivy"
	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/policy"
	"github.com/CGCServicesSpA/cgc-scan/internal/policyfile"
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

func (a *App) runScan(cmd *cobra.Command, opts scanOptions) (retErr error) {
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
	cfg, err := config.Load(a.Paths.ConfigFile())
	if err != nil {
		return UsageErrorf("%v", err)
	}
	targetRef := target
	emitted := false
	defer func() {
		if retErr == nil || emitted || opts.Format != "json" {
			return
		}
		var ee *ExitError
		if !errors.As(retErr, &ee) || ee.Code != 3 {
			return
		}
		doc := failureDocument(started, targetRef, retErr)
		_ = report.Emit(a.Stdout, doc, "json")
	}()

	rootGuess := discovery.DetectRoot(target)
	pol, err := policyfile.Load(rootGuess, started)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	ms, err := manifest.Load()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	engine, err := ms.Engine("trivy")
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	slog.Info("preparando Trivy", "version", engine.Version, "mode", opts.TrivyMode)
	setup, err := a.setupEngine(cmd.Context(), opts, cfg, ms, engine)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	defer func() { _ = setup.Shared.Release() }()
	if setup.FallbackReason != "" {
		slog.Warn("selección de runner", "mode", setup.Mode, "reason", setup.FallbackReason)
	}
	level, err := setup.Runner.Isolation(cmd.Context())
	if err != nil {
		return IncompleteErrorf("determinar aislamiento: %v", err)
	}

	// Paso 5: descubrimiento y plan.
	var exclusions []discovery.Exclusion
	if len(opts.Exclude) > 0 {
		// --exclude reemplaza las exclusiones de usuario y de política
		// (PRD §6.8); las intrínsecas se conservan siempre.
		for _, p := range opts.Exclude {
			exclusions = append(exclusions, discovery.Exclusion{
				Pattern: p, Origin: discovery.OriginCLI, Reason: "exclusión de la línea de comandos",
			})
		}
	} else {
		for _, p := range pol.Exclude {
			exclusions = append(exclusions, discovery.Exclusion{
				Pattern: p, Origin: discovery.OriginPolicy, Reason: "exclusión de la política del proyecto",
			})
		}
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
	trivyAdapter.CacheDir = setup.CacheDir
	trivyAdapter.Binary = setup.Binary
	trivyAdapter.RunnerKind = setup.Mode

	// Paso 6: ejecución.
	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = 4
	}
	out := orchestrator.Execute(cmd.Context(), p, []orchestrator.Engine{{
		ID:        trivy.ID,
		Version:   engine.Version,
		Mode:      setup.Mode,
		Adapter:   trivyAdapter,
		Runner:    setup.Runner,
		Isolation: level,
	}}, concurrency)

	// Pasos 7 y 8: política.
	failOn, thresholdIssues := policyfile.EffectiveFailOn(
		cmd.Flags().Changed("fail-on"), opts.FailOn, pol, normalize.SeverityHigh)
	pol.Issues = append(pol.Issues, thresholdIssues...)
	eval := policy.Evaluate(out.Findings, failOn, true, pol.Exceptions)

	// Paso 9: reporte.
	doc := buildDocument(cmd, opts, cfg, pol, failOn, setup, disc, out, started, time.Since(started), level, eval)

	if opts.ReportOut != "" {
		if err := a.validateReportOut(target, doc, opts.ReportOut); err != nil {
			return IncompleteErrorf("%v", err)
		}
		if err := report.WriteFile(opts.ReportOut, doc); err != nil {
			return IncompleteErrorf("%v", err)
		}
	}
	if err := report.Emit(a.Stdout, doc, opts.Format); err != nil {
		emitted = true
		return IncompleteErrorf("%v", err)
	}
	emitted = true

	code := policy.Decide(
		policy.RunOutcome{Complete: out.Complete, Canceled: out.Canceled},
		policy.PolicyOutcome{Violated: eval.Violated},
	)
	if code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

// failureDocument construye un reporte mínimo con el error estructurado, para
// que un consumidor de JSON nunca reciba stdout vacío ante un fallo de
// preparación (PRD §9, RF-08).
func failureDocument(started time.Time, target string, cause error) *report.Document {
	doc := &report.Document{
		SchemaVersion: version.SchemaVersion,
		Run:           report.NewRun(report.NewRunID(started), started, time.Since(started), map[string]any{"failed": true}),
		Target: report.Target{
			Root: target, LocalID: report.LocalID(target),
			VCS: report.VCS{Available: false}, Units: []report.UnitInfo{},
		},
		Coverage: report.Coverage{
			Partial:     true,
			Scope:       report.Scope{Root: target},
			Limitations: []string{"la preparación o el escaneo no se completaron"},
		},
		Tools:      report.Tools{Engines: []report.EngineReport{}},
		Isolation:  report.Isolation{Level: "configured", VerifiedBy: ""},
		Validation: report.Validation{},
		Policy:     report.Policy{FailOn: "high", UnknownCounts: true},
		Errors: []report.Error{{
			Code: "scan_failed", Scope: "scan", Message: cause.Error(), Retryable: true,
		}},
	}
	doc.Normalize()
	return doc
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

func buildDocument(cmd *cobra.Command, opts scanOptions, cfg config.Config, pol policyfile.Policy,
	failOn normalize.Severity, setup *engineSetup, disc discovery.Result, out orchestrator.Outcome,
	started time.Time, elapsed time.Duration, level runner.IsolationLevel, eval policy.Evaluation) *report.Document {

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
			Path: setup.Binary, Image: setup.Image,
		}
		for _, st := range e.Units {
			er.Units = append(er.Units, report.EngineState{
				ID: st.Unit, Status: st.Status, Reason: st.Reason, Findings: st.Findings,
			})
		}
		updated := setup.DB.UpdatedAt.UTC().Format(time.RFC3339)
		age := setup.DB.AgeSeconds
		schema := setup.DB.Schema
		er.DB = &report.DBState{
			Source: "trivy-db", Status: setup.DB.Status, UpdatedAt: &updated,
			AgeSeconds: &age, Schema: &schema,
		}
		er.Preparation = setup.Preparations
		if setup.DB.Status == "stale" {
			er.Limitations = append(er.Limitations, "base con antigüedad superior al aviso")
		}
		for _, p := range setup.Preparations {
			if p.Action == "checks" && p.Status == "failed" {
				er.Limitations = append(er.Limitations, "checks de configuración embebidos (el bundle no se pudo actualizar)")
			}
		}
		engines = append(engines, er)
	}

	limitations := []string{}
	if len(disc.Units) == 0 {
		limitations = append(limitations, "no se detectaron unidades analizables en el alcance")
	}
	if opts.Offline {
		limitations = append(limitations, "modo offline: no se actualizaron motores ni bases")
	}
	if setup.FallbackReason != "" {
		limitations = append(limitations, setup.FallbackReason)
	}
	for _, issue := range pol.Issues {
		if issue.Code == "policy_key_ignored" || issue.Code == "policy_invalid_toml" {
			limitations = append(limitations, "la política del proyecto se aplicó parcialmente")
			break
		}
	}

	include := opts.Include
	if include == nil {
		include = []string{}
	}
	excludeList := opts.Exclude
	if excludeList == nil {
		excludeList = []string{}
	}
	mode := "global"
	if len(out.Engines) > 0 {
		mode = out.Engines[0].Mode
	}
	args := map[string]any{
		"format":            opts.Format,
		"fail_on":           string(failOn),
		"offline":           opts.Offline,
		"trivy_mode":        mode,
		"require_isolation": opts.RequireIsolation,
		"no_auto_install":   opts.NoAutoInstall,
		"include":           include,
		"exclude":           excludeList,
	}
	failOnOrigin := "default"
	switch {
	case cmd != nil && cmd.Flags().Changed("fail-on"):
		failOnOrigin = "flag"
	case pol.FailOn != "":
		failOnOrigin = "project_policy"
	}
	modeOrigin := "default"
	switch {
	case opts.TrivyMode != "":
		modeOrigin = "flag"
	case cfg.TrivyMode != "":
		modeOrigin = "setup"
	}
	origins := []report.ConfigOrigin{
		{Key: "fail_on", Value: string(failOn), Origin: failOnOrigin},
		{Key: "trivy_mode", Value: mode, Origin: modeOrigin},
		{Key: "offline", Value: opts.Offline, Origin: originOf(cmd, "offline", "default")},
		{Key: "cache_dir", Value: setup.CacheDir, Origin: cacheOrigin(cfg)},
	}

	errs := make([]report.Error, 0, len(out.Errors)+len(pol.Issues))
	for _, e := range out.Errors {
		errs = append(errs, report.Error{Code: e.Code, Scope: e.Scope, Message: e.Message, Retryable: e.Retryable})
	}
	for _, issue := range pol.Issues {
		errs = append(errs, report.Error{Code: issue.Code, Scope: "policy", Message: issue.Message, Retryable: false})
	}

	exceptions := make([]report.ExceptionReport, 0, len(pol.Exceptions))
	for _, ex := range pol.Exceptions {
		exceptions = append(exceptions, report.ExceptionReport{
			Fingerprint: ex.Fingerprint, Reason: ex.Reason, Owner: ex.Owner,
			Expires: ex.Expires, Effective: ex.Effective,
		})
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
			Scope:       report.Scope{Root: disc.Root, Include: include, Exclude: excludeList},
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
			FailOn: string(failOn), Violated: eval.Violated, UnknownCounts: eval.UnknownCounts,
			Exceptions: exceptions, SuppressedCount: eval.SuppressedCount,
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

func cacheOrigin(cfg config.Config) string {
	if cfg.Cache.Dir != "" {
		return "user"
	}
	return "default"
}

func originOf(cmd *cobra.Command, flag, fallback string) string {
	if cmd != nil && cmd.Flags().Changed(flag) {
		return "flag"
	}
	return fallback
}
