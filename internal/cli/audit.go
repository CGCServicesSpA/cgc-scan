package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/policyfile"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// auditLockWait es la espera máxima por el bloqueo de la corrida. El bloqueo
// muere con su proceso, así que no hay cerrojos huérfanos; el tope evita
// esperas indefinidas ante un ciclo anómalo.
const auditLockWait = 30 * time.Second

// sourceForRun resuelve la fuente declarada por el estado de la corrida. Una
// revisión no disponible es un bloqueo explícito.
func sourceForRun(st *audit.RunState) (*audit.Source, error) {
	src, err := audit.SourceFrom(st.Ledger.Target.Root, *st.Source)
	if err != nil {
		return nil, err
	}
	return src, nil
}

// sourceStamper devuelve el sellador que usa el broker: valida la cita (ya
// comprobada antes de aplicar) y registra el hash de la fuente de cada
// archivo citado en el momento del registro.
func sourceStamper(src *audit.Source) audit.SourceStamper {
	return func(fingerprint, role string, record *audit.Record) (map[string]string, error) {
		hashes := map[string]string{}
		for _, file := range audit.CitedFiles(record) {
			hash, err := src.HashFile(file)
			if err != nil {
				return nil, fmt.Errorf("el candidato %s cita %q: %w", fingerprint, file, err)
			}
			hashes[file] = hash
		}
		return hashes, nil
	}
}

// AuditStatusSchema identifica el resumen de estado de una auditoría.
const AuditStatusSchema = "audit-status-1.0.0"

// AuditReportSchema identifica el resultado de `audit report`.
const AuditReportSchema = "audit-report-1.0.0"

type auditCandidateCounts struct {
	Pending    int `json:"pending"`
	Escalation int `json:"escalation"`
	Decided    int `json:"decided"`
	Review     int `json:"review_pending"`
}

type auditStatusDocument struct {
	SchemaVersion string               `json:"schema_version"`
	Run           audit.Run            `json:"run"`
	Target        audit.Target         `json:"target"`
	Status        string               `json:"run_status"`
	Incomplete    string               `json:"incomplete_reason,omitempty"`
	Profile       string               `json:"profile"`
	Budget        *audit.Budget        `json:"budget"`
	Coverage      audit.Summary        `json:"coverage"`
	Candidates    auditCandidateCounts `json:"candidates"`
	Dir           string               `json:"dir"`
}

type auditReportSummary struct {
	SchemaVersion string                `json:"schema_version"`
	Status        string                `json:"status"`
	Incomplete    string                `json:"incomplete_reason,omitempty"`
	Findings      audit.FindingsSummary `json:"findings"`
	Coverage      audit.Summary         `json:"coverage"`
	Budget        *audit.Budget         `json:"budget"`
	FindingsPath  string                `json:"findings_path"`
	ReportPath    string                `json:"report_path"`
	DetailPath    string                `json:"detail_path"`
	NeedsPath     string                `json:"needs_validation_path"`
}

func (a *App) newAuditCommand() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Protocolo de auditoría asistida: cobertura, asignaciones y veredictos",
		Long: `Orquesta una auditoría con un agente externo sin ejecutar código del
proyecto ni llamar a un modelo. El motor construye el ledger de cobertura,
reparte asignaciones, valida estructura e independencia, contabiliza el
presupuesto y deriva los reportes. La evidencia la aporta el agente.`,
		Args: cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&out, "out", "", "directorio de la corrida (por defecto, el estado del proyecto)")

	cmd.AddCommand(
		a.newAuditInitCommand(&out),
		a.newAuditNextCommand(&out),
		a.newAuditSubmitCommand(&out),
		a.newAuditReportCommand(&out),
		a.newAuditStatusCommand(&out),
		a.newAuditResetUnitCommand(&out),
	)
	return cmd
}

func (a *App) newAuditResetUnitCommand(out *string) *cobra.Command {
	var (
		format     string
		coverageID string
		reason     string
	)
	cmd := &cobra.Command{
		Use:   "reset-unit [ruta]",
		Short: "Devuelve una unidad abandonada a planned y archiva el intento",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			if strings.TrimSpace(coverageID) == "" {
				return UsageErrorf("--coverage-id es obligatorio")
			}
			if strings.TrimSpace(reason) == "" {
				return UsageErrorf("--reason es obligatorio y no puede quedar vacío")
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAuditResetUnit(cmd.Context(), auditTarget(target), *out, format, coverageID, reason)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text")
	cmd.Flags().StringVar(&coverageID, "coverage-id", "", "identificador de la unidad a reiniciar")
	cmd.Flags().StringVar(&reason, "reason", "", "razón del abandono, archivada con el intento")
	return cmd
}

func (a *App) runAuditResetUnit(ctx context.Context, target, out, format, coverageID, reason string) error {
	store, err := a.auditStore(target, out)
	if err != nil {
		return err
	}
	var unit *audit.Unit
	if err := store.WithRunLock(ctx, auditLockWait, func() error {
		st, err := store.LoadState()
		if err != nil {
			return err
		}
		if err := audit.ResetUnit(st.Ledger, coverageID, reason); err != nil {
			return err
		}
		unit = st.Ledger.UnitByID(coverageID)
		return store.CommitState(st)
	}); err != nil {
		return IncompleteErrorf("%v", err)
	}
	if format == "json" {
		payload, err := json.MarshalIndent(map[string]any{
			"schema_version": "audit-reset-unit-1.0.0",
			"coverage_id":    unit.CoverageID,
			"state":          unit.State,
			"attempts":       len(unit.Attempts),
		}, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, append(payload, '\n'))
	}
	_, err = fmt.Fprintf(a.Stdout, "Unidad %s devuelta a planned; intento archivado como blocked (%d en total)\n",
		unit.CoverageID, len(unit.Attempts))
	return err
}

func (a *App) newAuditInitCommand(out *string) *cobra.Command {
	var (
		format   string
		profile  string
		budget   int
		include  []string
		exclude  []string
		priorDir string
	)
	cmd := &cobra.Command{
		Use:   "init [ruta]",
		Short: "Construye el ledger de cobertura y deja la corrida lista",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			if err := oneOf("profile", profile, audit.ProfileQuick, audit.ProfileStandard, audit.ProfileDeep); err != nil {
				return err
			}
			if budget < 0 {
				return UsageErrorf("--budget no puede ser negativo")
			}
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAuditInit(cmd, target, *out, format, profile, budget, include, exclude, priorDir)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text")
	cmd.Flags().StringVar(&profile, "profile", audit.ProfileStandard, "perfil: quick|standard|deep")
	cmd.Flags().IntVar(&budget, "budget", 0, "máximo de invocaciones de agente (0 = sin límite)")
	cmd.Flags().StringArrayVar(&include, "include", nil, "patrón de rutas a incluir (repetible)")
	cmd.Flags().StringArrayVar(&exclude, "exclude", nil, "patrón de rutas a excluir (repetible)")
	cmd.Flags().StringVar(&priorDir, "prior", "", "corrida anterior cuyo contexto se expone (no suprime trabajo)")
	return cmd
}

func (a *App) newAuditNextCommand(out *string) *cobra.Command {
	var (
		format   string
		agent    string
		maxUnits int
	)
	cmd := &cobra.Command{
		Use:   "next [ruta]",
		Short: "Entrega la siguiente asignación al agente",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			if agent == "" {
				return UsageErrorf("--agent es obligatorio")
			}
			if !audit.ValidAgentID(agent) {
				return UsageErrorf("--agent inválido: %q (minúsculas, [a-z0-9_-], máximo 64)", agent)
			}
			if maxUnits < 0 {
				return UsageErrorf("--max-units no puede ser negativo")
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAuditNext(cmd, target, *out, format, agent, maxUnits)
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "formato: json|text")
	cmd.Flags().StringVar(&agent, "agent", "", "identificador canónico del agente que recibe la asignación")
	cmd.Flags().IntVar(&maxUnits, "max-units", 0, "máximo de unidades por asignación (0 = tope del catálogo)")
	return cmd
}

func (a *App) newAuditSubmitCommand(out *string) *cobra.Command {
	var (
		format string
		file   string
	)
	cmd := &cobra.Command{
		Use:   "submit [ruta]",
		Short: "Aplica la entrega de un agente al ledger",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			if file == "" {
				return UsageErrorf("--file es obligatorio (- para la entrada estándar)")
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAuditSubmit(cmd, target, *out, format, file)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text")
	cmd.Flags().StringVar(&file, "file", "", "archivo de la entrega, o - para la entrada estándar")
	return cmd
}

func (a *App) newAuditReportCommand(out *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "report [ruta]",
		Short: "Sella la corrida y deriva findings.json y los reportes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAuditReport(cmd.Context(), auditTarget(target), *out, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text")
	return cmd
}

func (a *App) newAuditStatusCommand(out *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "status [ruta]",
		Short: "Resume una corrida de auditoría sin modificar nada",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAuditStatus(cmd.Context(), auditTarget(target), *out, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text")
	return cmd
}

func auditTarget(target string) string {
	if target != "" {
		return target
	}
	return "."
}

func (a *App) auditStore(target, out string) (*audit.Store, error) {
	if out != "" {
		store, err := audit.OpenStore(out)
		if err != nil {
			return nil, UsageErrorf("%v", err)
		}
		return store, nil
	}
	store, err := a.projectStore(target)
	if err != nil {
		return nil, err
	}
	s, err := audit.OpenStore(filepath.Join(store.Dir(), "audit"))
	if err != nil {
		return nil, IncompleteErrorf("%v", err)
	}
	return s, nil
}

func (a *App) runAuditInit(cmd *cobra.Command, target, out, format, profile string, budget int, include, exclude []string, priorDir string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return UsageErrorf("ruta objetivo inválida: %v", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return UsageErrorf("abrir %s: %v", abs, err)
	}
	if !info.IsDir() {
		return UsageErrorf("%s no es un directorio", abs)
	}
	if err := a.Paths.EnsureDirs(); err != nil {
		return IncompleteErrorf("preparar directorios: %v", err)
	}
	rootGuess := discovery.DetectRoot(abs)
	pol, err := policyfile.Load(rootGuess, a.Now())
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	var exclusions []discovery.Exclusion
	if len(exclude) > 0 {
		for _, p := range exclude {
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
	disc, err := discovery.Discover(cmd.Context(), discovery.Options{Target: abs, Exclude: exclusions})
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	p := plan.Build(disc, nil)
	p.Include = include
	p.Exclude = exclude
	plan.ApplySelection(&p)

	kept := make([]discovery.Unit, 0, len(p.Units))
	for _, up := range p.Units {
		kept = append(kept, up.Unit)
	}
	disc.Units = kept
	disc.Partial = disc.Partial || p.Partial

	oos := make([]audit.OutOfScope, 0, len(p.NotAnalyzed))
	for _, n := range p.NotAnalyzed {
		oos = append(oos, audit.OutOfScope{Unit: n.Unit, Path: n.Path, Reason: n.Reason})
	}

	catalog, err := audit.LoadCatalog()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	vcs := collectVCS(disc.Root)
	sourceRef := "worktree"
	if vcs.Available && vcs.Revision != "" {
		sourceRef = vcs.Revision
	}
	src, err := audit.ResolveSource(abs, sourceRef, vcs.Dirty)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	var prior *audit.PriorRun
	if priorDir != "" {
		priorStore, err := audit.OpenStore(priorDir)
		if err != nil {
			return UsageErrorf("--prior: %v", err)
		}
		priorState, err := priorStore.LoadState()
		if err != nil {
			return UsageErrorf("--prior: %v", err)
		}
		prior = audit.PriorFrom(priorState.Ledger, priorState.Findings, sourceRef, vcs.Dirty)
	}
	var limitations []string
	if p.Partial {
		limitations = append(limitations,
			"alcance restringido por --include o exclusiones elegidas; lo no analizado no se declara resuelto")
	}
	ledger, err := audit.BuildLedger(audit.BuildOptions{
		Catalog: catalog, Discovery: disc, OutOfScope: oos,
		Profile: profile, MaxAgentInvocations: budget, Prior: prior,
		Limitations: limitations,
		RunID:       report.NewRunID(a.Now()), Now: a.Now(),
		CLIVersion: version.Version, SourceRef: sourceRef, Dirty: vcs.Dirty,
	})
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	store, err := a.auditStore(abs, out)
	if err != nil {
		return err
	}
	// El bloqueo cubre la creación completa de la corrida: otro proceso que
	// llegue detrás espera y observa el estado íntegro, no un ledger sin
	// estado de verificación.
	if err := store.WithLock(cmd.Context(), auditLockWait, func() error {
		st := &audit.RunState{
			Source:     &src.Info,
			Ledger:     ledger,
			Candidates: &audit.Candidates{SchemaVersion: audit.CandidatesSchemaVersion, RunID: ledger.Run.ID, Items: []audit.Candidate{}},
		}
		return store.CommitState(st)
	}); err != nil {
		return IncompleteErrorf("%v", err)
	}

	if format == "json" {
		data, err := ledger.JSON()
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		if err := report.EmitRaw(a.Stdout, data); err != nil {
			return IncompleteErrorf("%v", err)
		}
		return nil
	}
	_, err = fmt.Fprint(a.Stdout, renderAuditInit(ledger, store.Dir()))
	return err
}

func (a *App) runAuditNext(cmd *cobra.Command, target, out, format, agent string, maxUnits int) error {
	store, err := a.auditStore(auditTarget(target), out)
	if err != nil {
		return err
	}
	var (
		ledger *audit.Ledger
		task   *audit.Task
	)
	err = store.WithRunLock(cmd.Context(), auditLockWait, func() error {
		st, inner := store.LoadState()
		if inner != nil {
			return inner
		}
		ledger = st.Ledger
		catalog, inner := audit.LoadCatalog()
		if inner != nil {
			return inner
		}
		task, inner = audit.Next(st.Ledger, st.Candidates, audit.NextOptions{
			AgentID: agent, Catalog: catalog, MaxUnits: maxUnits,
		})
		if err := inner; err != nil {
			if errors.Is(err, audit.ErrBudgetExhausted) {
				// El agotamiento difiere el resto y sella la corrida: ese
				// cambio de estado se persiste antes de responder.
				if saveErr := store.CommitState(st); saveErr != nil {
					return saveErr
				}
			}
			return err
		}
		return store.CommitState(st)
	})
	if err != nil {
		switch {
		case errors.Is(err, audit.ErrNoTask):
			if ledger != nil && ledger.RunStatus == audit.StatusIncomplete {
				_, werr := fmt.Fprintf(a.Stdout, "No hay trabajo pendiente: la corrida está incompleta (%s).\n", ledger.IncompleteReason)
				if werr != nil {
					return werr
				}
				return IncompleteErrorf("la corrida está incompleta: %s", ledger.IncompleteReason)
			}
			_, werr := fmt.Fprintf(a.Stdout, "No hay trabajo pendiente para este agente.\n")
			return werr
		case errors.Is(err, audit.ErrBudgetExhausted):
			return IncompleteErrorf("%v; las unidades pendientes quedaron diferidas y la corrida es incompleta", err)
		case errors.Is(err, audit.ErrAgentIneligible):
			return IncompleteErrorf("%v; usa un identificador de agente distinto del cazador y de los verificadores previos", err)
		default:
			return IncompleteErrorf("%v", err)
		}
	}
	if format == "json" {
		data, err := task.JSON()
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, data)
	}
	_, err = fmt.Fprint(a.Stdout, renderAuditTask(task))
	return err
}

func (a *App) runAuditSubmit(cmd *cobra.Command, target, out, format, file string) error {
	data, err := readSubmission(a.Stdin, file)
	if err != nil {
		return UsageErrorf("%v", err)
	}
	sub, err := audit.DecodeSubmission(data)
	if err != nil {
		return UsageErrorf("%v", err)
	}
	if !audit.ValidAgentID(sub.AgentID) {
		return UsageErrorf("agent_id inválido en la entrega: %q", sub.AgentID)
	}
	store, err := a.auditStore(auditTarget(target), out)
	if err != nil {
		return err
	}
	var result *audit.SubmitOutcome
	if err := store.WithRunLock(cmd.Context(), auditLockWait, func() error {
		st, err := store.LoadState()
		if err != nil {
			return err
		}
		src, err := sourceForRun(st)
		if err != nil {
			return err
		}
		// Las citas de la entrega se validan contra la fuente declarada por
		// la corrida antes de aplicar cualquier cambio: una traza fabricada
		// se rechaza aquí.
		for i := range sub.Candidates {
			if err := src.ValidateRecord(fmt.Sprintf("candidato %q", sub.Candidates[i].Fingerprint), &sub.Candidates[i]); err != nil {
				return err
			}
		}
		if sub.Verification != nil && sub.Verification.Record != nil {
			where := fmt.Sprintf("verificación %q", sub.Verification.Fingerprint)
			if err := src.ValidateRecord(where, sub.Verification.Record); err != nil {
				return err
			}
		}
		result, err = audit.SubmitWithOptions(st.Ledger, st.Candidates, sub, audit.SubmitOptions{
			Source: sourceStamper(src),
		})
		if err != nil {
			return err
		}
		return store.CommitState(st)
	}); err != nil {
		return IncompleteErrorf("%v", err)
	}
	if format == "json" {
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, append(payload, '\n'))
	}
	_, err = fmt.Fprint(a.Stdout, renderSubmitOutcome(result))
	return err
}

func (a *App) runAuditReport(ctx context.Context, target, out, format string) error {
	store, err := a.auditStore(target, out)
	if err != nil {
		return err
	}
	var (
		summary    auditReportSummary
		findings   *audit.Findings
		runID      string
		status     string
		incomplete string
	)
	if err := store.WithRunLock(ctx, auditLockWait, func() error {
		st, err := store.LoadState()
		if err != nil {
			return err
		}
		ledger := st.Ledger
		findings, err = audit.BuildFindings(ledger, st.Candidates)
		if err != nil {
			return err
		}
		// Vigencia actual: si la corrida describe el árbol de trabajo y los
		// archivos citados cambiaron desde su registro, el sellado no puede
		// presentarlos como vigentes. Se declara el cambio y se exige
		// revalidación; no se fabrica un needs_validation automático.
		src, err := sourceForRun(st)
		if err != nil {
			return err
		}
		diverged, err := src.CheckDivergence(st.Candidates)
		if err != nil {
			return err
		}
		if len(diverged) > 0 {
			ledger.Limitations = append(ledger.Limitations, fmt.Sprintf(
				"%d archivo(s) citado(s) por registros finales cambiaron o desaparecieron desde su registro: esos hallazgos exigen revalidación antes de presentarse como vigentes",
				len(diverged)))
			if ledger.RunStatus == audit.StatusComplete {
				ledger.RunStatus = audit.StatusIncomplete
				ledger.IncompleteReason = audit.IncompleteSourceDiverged
			}
			ledger.Recompute()
		}
		st.Findings = findings
		if err := store.CommitState(st); err != nil {
			return err
		}
		artifacts := []struct {
			name    string
			content []byte
		}{
			{"REPORT.md", audit.RenderReport(ledger, findings)},
			{"FINDINGS-DETAIL.md", audit.RenderFindingsDetail(ledger, findings)},
			{"NEEDS-VALIDATION.md", audit.RenderNeedsValidation(findings)},
		}
		for _, art := range artifacts {
			if err := store.WriteArtifact(art.name, art.content); err != nil {
				return fmt.Errorf("escribir %s: %w", art.name, err)
			}
		}
		summary = auditReportSummary{
			SchemaVersion: AuditReportSchema,
			Status:        ledger.RunStatus,
			Incomplete:    ledger.IncompleteReason,
			Findings:      findings.Summary,
			Coverage:      ledger.Summary,
			Budget:        ledger.Budget,
			FindingsPath:  store.FindingsPath(),
			ReportPath:    store.ArtifactPath("REPORT.md"),
			DetailPath:    store.ArtifactPath("FINDINGS-DETAIL.md"),
			NeedsPath:     store.ArtifactPath("NEEDS-VALIDATION.md"),
		}
		runID, status, incomplete = ledger.Run.ID, ledger.RunStatus, ledger.IncompleteReason
		return nil
	}); err != nil {
		return IncompleteErrorf("%v", err)
	}
	if format == "json" {
		payload, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		if err := report.EmitRaw(a.Stdout, append(payload, '\n')); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(a.Stdout, "Auditoría %s: %s\n", runID, status); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(a.Stdout, "Hallazgos: %d confirmados, %d por validar, %d rechazados\n",
			findings.Summary.Confirmed, findings.Summary.NeedsValidation, findings.Summary.Rejected); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(a.Stdout, "Informe: %s\n", summary.ReportPath); err != nil {
			return err
		}
	}
	if status != audit.StatusComplete {
		return IncompleteErrorf("la auditoría quedó incompleta: %s", incomplete)
	}
	return nil
}

func (a *App) runAuditStatus(ctx context.Context, target, out, format string) error {
	store, err := a.auditStore(target, out)
	if err != nil {
		return err
	}
	var doc *auditStatusDocument
	// status es lector: bloqueo compartido, convive con otros lectores y no
	// observa una escritura a medio operar.
	if err := store.WithSharedRunLock(ctx, auditLockWait, func() error {
		st, err := store.LoadState()
		if err != nil {
			return err
		}
		ledger, candidates := st.Ledger, st.Candidates
		pending, escalation, decided, review := 0, 0, 0, 0
		for _, c := range candidates.Items {
			switch c.State {
			case audit.CandidatePending:
				pending++
			case audit.CandidateEscalation:
				escalation++
			case audit.CandidateDecided:
				decided++
			case audit.CandidateReviewPending:
				review++
			}
		}
		d := auditStatusDocument{
			SchemaVersion: AuditStatusSchema,
			Run:           ledger.Run, Target: ledger.Target,
			Status: ledger.RunStatus, Incomplete: ledger.IncompleteReason,
			Profile: ledger.Profile, Budget: ledger.Budget, Coverage: ledger.Summary,
			Dir: store.Dir(),
		}
		d.Candidates.Pending = pending
		d.Candidates.Escalation = escalation
		d.Candidates.Decided = decided
		d.Candidates.Review = review
		doc = &d
		return nil
	}); err != nil {
		return IncompleteErrorf("%v", err)
	}
	if format == "json" {
		payload, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, append(payload, '\n'))
	}
	_, err = fmt.Fprint(a.Stdout, renderAuditStatus(*doc))
	return err
}

func readSubmission(stdin io.Reader, file string) ([]byte, error) {
	if file == "-" {
		data, err := io.ReadAll(io.LimitReader(stdin, audit.MaxSubmissionBytes+1))
		if err != nil {
			return nil, fmt.Errorf("leer entrada estándar: %w", err)
		}
		if len(data) > audit.MaxSubmissionBytes {
			return nil, fmt.Errorf("la entrega supera el límite de %d bytes", audit.MaxSubmissionBytes)
		}
		return data, nil
	}
	// Lectura acotada: el archivo se recorta antes de validarlo, no se lee
	// completo para después comprobar su tamaño.
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("leer entrega: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, audit.MaxSubmissionBytes+1))
	if err != nil {
		return nil, fmt.Errorf("leer entrega: %w", err)
	}
	if len(data) > audit.MaxSubmissionBytes {
		return nil, fmt.Errorf("la entrega supera el límite de %d bytes", audit.MaxSubmissionBytes)
	}
	return data, nil
}

func renderAuditInit(l *audit.Ledger, dir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Auditoría %s creada en %s\n", l.Run.ID, dir)
	fmt.Fprintf(&b, "Perfil %s · %d unidad(es): %d planificadas, %d fuera de alcance\n",
		l.Profile, l.Summary.UnitsTotal, l.Summary.Planned, l.Summary.OutOfScope)
	if l.Budget != nil {
		fmt.Fprintf(&b, "Presupuesto: %d invocaciones de agente\n", l.Budget.MaxAgentInvocations)
	} else {
		b.WriteString("Presupuesto: sin límite declarado\n")
	}
	b.WriteString("Siguiente paso: cgc-scan audit next --agent <id> --format json\n")
	return b.String()
}

func renderAuditTask(t *audit.Task) string {
	var b strings.Builder
	switch t.Kind {
	case "hunt":
		fmt.Fprintf(&b, "Asignación de caza para %s (%d unidad(es))\n", t.AgentID, len(t.Units))
		for _, u := range t.Units {
			fmt.Fprintf(&b, "  %s [%s/%s] clase %s\n", u.Unit.CoverageID, u.Unit.Domain, u.Unit.Boundary, u.Unit.AttackClass)
			fmt.Fprintf(&b, "    rutas: %s\n", strings.Join(u.Unit.StartingPaths, ", "))
			if u.Class.Invariant != "" {
				fmt.Fprintf(&b, "    invariante: %s\n", u.Class.Invariant)
			}
		}
	default:
		if t.Candidate != nil {
			fmt.Fprintf(&b, "Verificación %s para %s: candidato %s\n", t.Kind, t.AgentID, t.Candidate.Fingerprint)
			fmt.Fprintf(&b, "  unidad: %s\n  título: %s\n", t.Candidate.Unit, t.Candidate.Proposed.Title)
		}
	}
	if t.Budget != nil {
		fmt.Fprintf(&b, "Presupuesto usado: %d/%d\n", t.Budget.Used, t.Budget.MaxAgentInvocations)
	}
	return b.String()
}

func renderSubmitOutcome(o *audit.SubmitOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Entrega aplicada: %d unidad(es)", o.AppliedUnits)
	if o.Pending > 0 {
		fmt.Fprintf(&b, ", %d candidato(s) en verificación", o.Pending)
	}
	if o.Decided > 0 {
		fmt.Fprintf(&b, ", %d decidido(s)", o.Decided)
	}
	if o.Escalations > 0 {
		fmt.Fprintf(&b, ", %d escalación(es)", o.Escalations)
	}
	b.WriteString("\n")
	for _, name := range o.AddedUnits {
		fmt.Fprintf(&b, "  unidad añadida: %s\n", name)
	}
	for _, note := range o.Notes {
		fmt.Fprintf(&b, "  nota: %s\n", note)
	}
	return b.String()
}

func renderAuditStatus(doc auditStatusDocument) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Auditoría %s: %s (%s)\n", doc.Run.ID, doc.Status, doc.Profile)
	if doc.Incomplete != "" {
		fmt.Fprintf(&b, "Incompleta: %s\n", doc.Incomplete)
	}
	fmt.Fprintf(&b, "Unidades: %d; cubiertas %d, con candidato %d, bloqueadas %d, diferidas %d, fuera de alcance %d\n",
		doc.Coverage.UnitsTotal, doc.Coverage.Covered, doc.Coverage.Candidate,
		doc.Coverage.Blocked, doc.Coverage.Deferred, doc.Coverage.OutOfScope)
	fmt.Fprintf(&b, "Candidatos: %d pendientes, %d en escalación, %d decididos, %d en revisión final\n",
		doc.Candidates.Pending, doc.Candidates.Escalation, doc.Candidates.Decided, doc.Candidates.Review)
	if doc.Budget != nil {
		fmt.Fprintf(&b, "Presupuesto: %d/%d\n", doc.Budget.Used, doc.Budget.MaxAgentInvocations)
	}
	return b.String()
}
