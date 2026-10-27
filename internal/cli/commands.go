package cli

import (
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
		RunE: func(_ *cobra.Command, _ []string) error {
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
			return notImplemented("setup", "H3")
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
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := oneOf("format", format, "text", "json"); err != nil {
				return err
			}
			return notImplemented("doctor", "H3")
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
	)
	cmd := &cobra.Command{
		Use:   "scan [ruta]",
		Short: "Analiza un proyecto y emite el reporte",
		Long: `Analiza el directorio indicado (o el actual) y emite JSON, texto o un
prompt de remediación. La selección de rutas con --include y --exclude queda
registrada en coverage y marca el escaneo como parcial cuando corresponde.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := oneOf("format", format, "json", "text", "prompt"); err != nil {
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
			return notImplemented("scan", "H1")
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "formato: json|text|prompt")
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
	return cmd
}

func (a *App) newCompareCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "compare <anterior.json> <actual.json>",
		Short: "Compara dos reportes: nuevo, persistente, resuelto y no evaluado",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := oneOf("format", format, "json", "text"); err != nil {
				return err
			}
			return notImplemented("compare", "H5")
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "formato: json|text")
	return cmd
}

func (a *App) newUpdateDBCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-db",
		Short: "Actualiza las bases de datos de los motores",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return notImplemented("update-db", "H2")
		},
	}
	return cmd
}

func (a *App) newRecipesCommand() *cobra.Command {
	var (
		setFile string
		clear   bool
	)
	cmd := &cobra.Command{
		Use:   "recipes",
		Short: "Lista candidatos y recetas de validación confirmadas",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if clear && setFile != "" {
				return UsageErrorf("--set y --clear son mutuamente excluyentes")
			}
			if clear {
				return notImplemented("recipes --clear", "H5")
			}
			if setFile != "" {
				return notImplemented("recipes --set", "H5")
			}
			return notImplemented("recipes", "H5")
		},
	}
	cmd.Flags().StringVar(&setFile, "set", "", "confirma las recetas declaradas en este archivo")
	cmd.Flags().BoolVar(&clear, "clear", false, "elimina las recetas confirmadas del proyecto")
	return cmd
}

// FormatAllowed valida y normaliza un formato de salida.
func FormatAllowed(format string) (string, error) {
	if err := oneOf("format", format, "json", "text", "prompt"); err != nil {
		return "", err
	}
	return format, nil
}
