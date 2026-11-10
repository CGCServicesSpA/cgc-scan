package cli

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/agent"
	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func (a *App) newAgentCommand() *cobra.Command {
	var (
		failOn           string
		reportOut        string
		trivyMode        string
		noAutoInstall    bool
		offline          bool
		requireIsolation string
		include          []string
		exclude          []string
		timeout          time.Duration
		concurrency      int
		confirmRecipes   bool
		maxGroups        int
		only             []string
		engines          []string
		changed          bool
		noCache          bool
		minSeverity      string
	)
	cmd := &cobra.Command{
		Use:   "agent [ruta]",
		Short: "Escanea una vez y entrega grupos, prioridades, delta y próximas acciones",
		Long: `One-shot para agentes: prepara motores y bases, escanea, construye el plan
de remediación, lo compara con la línea base (creándola en la primera
ejecución) y emite un JSON compacto con report_path al reporte canónico.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("fail-on", failOn, "critical", "high", "medium", "low", "info", "unknown"); err != nil {
				return err
			}
			if trivyMode != "" {
				if err := oneOf("trivy-mode", trivyMode, "docker", "global"); err != nil {
					return err
				}
			}
			if err := oneOf("require-isolation", requireIsolation, "configured", "enforced"); err != nil {
				return err
			}
			if timeout <= 0 {
				return UsageErrorf("--timeout debe ser positivo")
			}
			if concurrency < 0 {
				return UsageErrorf("--concurrency no puede ser negativo")
			}
			if maxGroups < 0 {
				return UsageErrorf("--max-groups no puede ser negativo")
			}
			if err := validateOnly(only); err != nil {
				return err
			}
			if err := validateEngines(engines); err != nil {
				return err
			}
			if minSeverity != "" {
				if err := oneOf("min-severity", minSeverity, "critical", "high", "medium", "low", "info", "unknown"); err != nil {
					return err
				}
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return a.runAgent(cmd, scanOptions{
				Target: target, Format: "json", FailOn: failOn, ReportOut: reportOut,
				TrivyMode: trivyMode, NoAutoInstall: noAutoInstall, Offline: offline,
				RequireIsolation: requireIsolation, Include: include, Exclude: exclude,
				Timeout: timeout, Concurrency: concurrency,
				ConfirmRecipes: confirmRecipes, MaxGroups: maxGroups,
				Only: only, Engines: engines, Changed: changed, NoCache: noCache,
				MinSeverity: minSeverity,
			})
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "severidad mínima que bloquea")
	cmd.Flags().StringVar(&reportOut, "report-out", "", "escribe además el JSON canónico en este archivo")
	cmd.Flags().StringVar(&trivyMode, "trivy-mode", "", "modalidad de Trivy: docker|global")
	cmd.Flags().BoolVar(&noAutoInstall, "no-auto-install", false, "no adquiere motores ni imágenes")
	cmd.Flags().BoolVar(&offline, "offline", false, "sin descargas ni consultas remotas")
	cmd.Flags().StringVar(&requireIsolation, "require-isolation", "configured", "nivel mínimo de aislamiento: configured|enforced")
	cmd.Flags().StringArrayVar(&include, "include", nil, "patrón de rutas a incluir (repetible)")
	cmd.Flags().StringArrayVar(&exclude, "exclude", nil, "patrón de rutas a excluir (repetible)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "tiempo máximo por invocación")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "invocaciones concurrentes (0 = automático)")
	cmd.Flags().BoolVar(&confirmRecipes, "confirm-recipes", false, "confirma y guarda los candidatos detectados")
	cmd.Flags().IntVar(&maxGroups, "max-groups", 0, "máximo de grupos (0 = todos; el resumen declara el truncamiento)")
	cmd.Flags().StringSliceVar(&only, "only", nil, "categorías a analizar: deps,secrets,code,config")
	cmd.Flags().StringSliceVar(&engines, "engines", nil, "motores a ejecutar (repetible o separado por comas)")
	cmd.Flags().BoolVar(&changed, "changed", false, "solo unidades con cambios desde la línea base (Git local)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "ignora la caché incremental por unidad y motor")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "filtro de vista; no cambia la política ni el reporte canónico")
	return cmd
}

func (a *App) runAgent(cmd *cobra.Command, opts scanOptions) error {
	res, err := a.executeScan(cmd, opts)
	if err != nil {
		doc := failureDocument(a.Now(), targetOrCWD(opts.Target), err)
		_ = a.emitAgentDocument(agent.Build(doc, agent.Options{ExitCode: CodeOf(err)}), opts.MaxGroups)
		return err
	}
	doc := res.Doc
	store, storeErr := projectstate.Open(a.Paths, doc.Target.Root)
	baselineCreated := false
	if storeErr == nil && !store.HasBaseline() {
		if err := store.SaveBaseline(doc); err != nil {
			return IncompleteErrorf("guardar la línea base: %v", err)
		}
		baselineCreated = true
		doc.Delta = compare.ReportDelta(compare.Compare(doc, doc))
		if err := store.SaveLatest(doc); err != nil {
			return IncompleteErrorf("guardar el último reporte: %v", err)
		}
	}
	opts.AgentBaselineCreated = baselineCreated
	if err := a.emitAgentWithBaseline(doc, opts, res.ExitCode, baselineCreated); err != nil {
		return IncompleteErrorf("%v", err)
	}
	if res.ExitCode != 0 {
		return &ExitError{Code: res.ExitCode}
	}
	return nil
}

// emitAgent se usa desde `scan --format agent`; no crea línea base.
func (a *App) emitAgent(doc *report.Document, opts scanOptions, exitCode int) error {
	return a.emitAgentWithBaseline(doc, opts, exitCode, false)
}

func (a *App) emitAgentWithBaseline(doc *report.Document, opts scanOptions, exitCode int, created bool) error {
	reportPath := ""
	if store, err := projectstate.Open(a.Paths, doc.Target.Root); err == nil {
		reportPath = store.LatestPath()
	}
	adoc := agent.Build(doc, agent.Options{
		ExitCode: exitCode, ReportPath: reportPath,
		BaselineCreated: created, MaxGroups: opts.MaxGroups,
		MinSeverity: normalize.Severity(opts.MinSeverity),
	})
	return a.emitAgentDocument(adoc, opts.MaxGroups)
}

func (a *App) emitAgentDocument(doc agent.Document, _ int) error {
	data, err := doc.JSON()
	if err != nil {
		return err
	}
	return report.EmitRaw(a.Stdout, data)
}

func targetOrCWD(target string) string {
	if target != "" {
		return target
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}
