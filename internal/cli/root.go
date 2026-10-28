// Package cli define los comandos públicos de cgc-scan y la traducción de
// resultados a códigos de salida.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/policy"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// App agrupa el estado de una ejecución de la CLI. Es inyectable para pruebas.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Paths  platform.Paths
	Now    func() time.Time
	IsTTY  bool
}

// Option permite ajustar la App en pruebas.
type Option func(*App)

// WithPaths sustituye las ubicaciones resueltas.
func WithPaths(p platform.Paths) Option { return func(a *App) { a.Paths = p } }

// WithNow sustituye el reloj.
func WithNow(now func() time.Time) Option { return func(a *App) { a.Now = now } }

// WithTTY fuerza la detección de terminal.
func WithTTY(tty bool) Option { return func(a *App) { a.IsTTY = tty } }

// WithStdin sustituye la entrada estándar (para setup interactivo en pruebas).
func WithStdin(r io.Reader) Option { return func(a *App) { a.Stdin = r } }

// New construye la App resolviendo las ubicaciones de plataforma.
func New(stdout, stderr io.Writer, opts ...Option) (*App, error) {
	p, err := platform.Resolve()
	if err != nil {
		return nil, err
	}
	a := &App{
		Stdin:  os.Stdin,
		Stdout: stdout,
		Stderr: stderr,
		Paths:  p,
		Now:    time.Now,
		IsTTY:  isTerminal(stdout),
	}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Execute corre la CLI y devuelve el código de salida. Es el único punto que
// conoce los códigos; main solo hace os.Exit.
func (a *App) Execute(ctx context.Context, args []string) int {
	root := a.newRootCommand()
	root.SetArgs(args)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)
	err := root.ExecuteContext(ctx)
	if ctx.Err() != nil {
		return policy.ExitCanceled
	}
	if err != nil {
		// Un código de política no es un error de la CLI: no se imprime.
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Err != nil {
			_, _ = fmt.Fprintf(a.Stderr, "%s: %v\n", version.Name, err)
		}
		return CodeOf(err)
	}
	return 0
}

// ColorEnabled informa si se puede usar color: hace falta TTY y que NO_COLOR
// no esté definida (RF-32).
func (a *App) ColorEnabled() bool {
	if !a.IsTTY {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return !strings.EqualFold(os.Getenv("TERM"), "dumb")
}

func (a *App) newRootCommand() *cobra.Command {
	var (
		logFormat string
		logLevel  string
		quiet     bool
		verbose   bool
	)

	root := &cobra.Command{
		Use:   version.Name,
		Short: "Análisis de seguridad local con cobertura honesta",
		Long: `cgc-scan analiza un proyecto local y combina Trivy con adaptadores por
lenguaje. Entrega JSON, texto o un prompt de remediación, y nunca declara un
resultado limpio si la cobertura fue incompleta.`,
		Version:       versionLine(),
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("version") {
				return nil
			}
			level, err := parseLevel(logLevel, quiet, verbose)
			if err != nil {
				return UsageErrorf("%v", err)
			}
			var handler slog.Handler
			opts := &slog.HandlerOptions{Level: level}
			if logFormat == "json" {
				handler = slog.NewJSONHandler(a.Stderr, opts)
			} else {
				handler = slog.NewTextHandler(a.Stderr, opts)
			}
			slog.SetDefault(slog.New(handler))
			return nil
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return UsageErrorf("%v", err)
	})
	root.PersistentFlags().StringVar(&logFormat, "log-format", "text", "formato de logs: text|json")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "", "nivel de log: debug|info|warn|error")
	root.PersistentFlags().BoolVar(&quiet, "quiet", false, "silencia el progreso; solo errores")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "progreso detallado")

	root.AddCommand(
		a.newSetupCommand(),
		a.newDoctorCommand(),
		a.newScanCommand(),
		a.newCompareCommand(),
		a.newUpdateDBCommand(),
		a.newRecipesCommand(),
	)
	return root
}

// versionLine incluye la CLI, el esquema y las versiones de motores fijadas
// (RF-32, CA-51).
func versionLine() string {
	line := version.String()
	m, err := manifest.Load()
	if err != nil {
		return line
	}
	ids := make([]string, 0, len(m.Engines))
	for id := range m.Engines {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id+"="+m.Engines[id].Version)
	}
	return line + " motores[" + strings.Join(parts, ",") + "]"
}

func parseLevel(level string, quiet, verbose bool) (slog.Level, error) {
	if quiet && verbose {
		return 0, fmt.Errorf("--quiet y --verbose son mutuamente excluyentes")
	}
	if quiet {
		return slog.LevelError, nil
	}
	var l slog.Level
	switch strings.ToLower(level) {
	case "":
		if verbose {
			return slog.LevelDebug, nil
		}
		return slog.LevelInfo, nil
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		return 0, fmt.Errorf("--log-level inválido: %q", level)
	}
	if verbose {
		return slog.LevelDebug, nil
	}
	return l, nil
}
