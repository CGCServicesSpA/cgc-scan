package cli

import (
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func oneOf(flag, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return UsageErrorf("valor inválido para --%s: %q (admitidos: %v)", flag, value, allowed)
}

var knownCategories = []string{"deps", "secrets", "code", "config"}

var knownEngines = []string{"trivy", "govulncheck", "eslint", "psalm", "bandit", "cargo-audit", "semgrep"}

func validateOnly(values []string) error {
	for _, v := range values {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if err := oneOf("only", p, knownCategories...); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEngines(values []string) error {
	for _, v := range values {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if err := oneOf("engines", p, knownEngines...); err != nil {
				return err
			}
		}
	}
	return nil
}

func expandList(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func (a *App) newSetupCommand() *cobra.Command {
	var (
		trivyMode      string
		semgrep        string
		nonInteractive bool
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configura la modalidad de Trivy y el análisis opcional con Semgrep",
		Long: `Detecta Docker, pregunta (o recibe por flags) si Trivy se usa como
contenedor o como binario global, decide si se habilita Semgrep CE y guarda la
elección en la configuración de usuario. Nunca modifica el proyecto.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if trivyMode != "" {
				if err := oneOf("trivy-mode", trivyMode, "docker", "global"); err != nil {
					return err
				}
			}
			if semgrep != "" {
				if err := oneOf("semgrep", semgrep, "enable", "disable"); err != nil {
					return err
				}
			}
			return a.runSetup(cmd, setupOptions{TrivyMode: trivyMode, Semgrep: semgrep, NonInteractive: nonInteractive})
		},
	}
	cmd.Flags().StringVar(&trivyMode, "trivy-mode", "", "modalidad de Trivy: docker|global")
	cmd.Flags().StringVar(&semgrep, "semgrep", "", "habilita Semgrep CE: enable|disable")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "no solicita entrada")
	return cmd
}

func (a *App) newDoctorCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnostica motores, bases, aislamiento y adaptadores",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			return a.runDoctor(cmd, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato de salida: text|json")
	return cmd
}

func (a *App) newScanCommand() *cobra.Command {
	var (
		format           string
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
		Use:   "scan [ruta]",
		Short: "Analiza un proyecto y emite el reporte",
		Long: `Analiza el directorio indicado (o el actual) y emite JSON, texto o un
prompt de remediación. La selección de rutas con --include y --exclude queda
registrada en coverage y marca el escaneo como parcial cuando corresponde.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text", "prompt", "agent"); err != nil {
				return err
			}
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
			return a.runScan(cmd, scanOptions{
				Target: target, Format: format, FailOn: failOn, ReportOut: reportOut,
				TrivyMode: trivyMode, NoAutoInstall: noAutoInstall, Offline: offline,
				RequireIsolation: requireIsolation, Include: include, Exclude: exclude,
				Timeout: timeout, Concurrency: concurrency,
				ConfirmRecipes: confirmRecipes, MaxGroups: maxGroups,
				Only: only, Engines: engines, Changed: changed, NoCache: noCache,
				MinSeverity: minSeverity,
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text|prompt|agent")
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
	cmd.Flags().BoolVar(&confirmRecipes, "confirm-recipes", false, "confirma y guarda los candidatos detectados para este proyecto")
	cmd.Flags().IntVar(&maxGroups, "max-groups", 0, "máximo de grupos en --format agent (0 = todos)")
	cmd.Flags().StringSliceVar(&only, "only", nil, "categorías a analizar: deps,secrets,code,config")
	cmd.Flags().StringSliceVar(&engines, "engines", nil, "motores a ejecutar: trivy,govulncheck,eslint,psalm,bandit,cargo-audit,semgrep")
	cmd.Flags().BoolVar(&changed, "changed", false, "solo unidades con cambios desde la línea base (Git local)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "ignora la caché incremental por unidad y motor")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "filtro de vista (texto/agent); no cambia la política ni el JSON canónico")
	return cmd
}

func (a *App) newCompareCommand() *cobra.Command {
	var (
		format   string
		baseline bool
	)
	cmd := &cobra.Command{
		Use:   "compare [anterior.json actual.json] [ruta]",
		Short: "Compara dos reportes o el último resultado con la línea base",
		Long: `Con dos rutas compara esos reportes. Con --baseline compara latest.json
contra baseline.json del proyecto sin volver a escanear, sin pasar rutas.`,
		Args: cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			if baseline {
				target := ""
				switch len(args) {
				case 0:
				case 1:
					target = args[0]
				default:
					return UsageErrorf("compare --baseline acepta como máximo una ruta de proyecto")
				}
				return a.runCompareBaseline(target, format)
			}
			if len(args) != 2 {
				return UsageErrorf("compare requiere dos reportes o --baseline")
			}
			return a.runCompare(cmd.Context(), args[0], args[1], format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "formato: json|text")
	cmd.Flags().BoolVar(&baseline, "baseline", false, "compara el último reporte contra la línea base guardada")
	return cmd
}

func (a *App) newUpdateDBCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-db",
		Short: "Actualiza las bases de datos de los motores",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runUpdateDB(cmd)
		},
	}
	return cmd
}

func (a *App) newRecipesCommand() *cobra.Command {
	var (
		setFile string
		clear   bool
		format  string
	)
	cmd := &cobra.Command{
		Use:   "recipes",
		Short: "Lista candidatos y recetas de validación confirmadas",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if clear && setFile != "" {
				return UsageErrorf("--set y --clear son mutuamente excluyentes")
			}
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			return a.runRecipes(cmd, setFile, clear, format)
		},
	}
	cmd.Flags().StringVar(&setFile, "set", "", "confirma las recetas declaradas en este archivo")
	cmd.Flags().BoolVar(&clear, "clear", false, "elimina las recetas confirmadas del proyecto")
	cmd.Flags().StringVar(&format, "format", "text", "formato: text|json")
	return cmd
}

// FormatAllowed valida y normaliza un formato de salida.
func FormatAllowed(format string) (string, error) {
	if err := oneOf("format", format, "json", "text", "prompt", "agent"); err != nil {
		return "", err
	}
	return format, nil
}
