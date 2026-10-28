package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

type setupOptions struct {
	TrivyMode      string
	Semgrep        string
	NonInteractive bool
}

// setupDecision es la elección resuelta antes de preparar nada.
type setupDecision struct {
	Mode    string
	Semgrep bool
}

// runSetup implementa setup interactivo y no interactivo (PRD §6.2).
func (a *App) runSetup(cmd *cobra.Command, opts setupOptions) error {
	if err := a.Paths.EnsureDirs(); err != nil {
		return IncompleteErrorf("preparar directorios: %v", err)
	}
	cfg, err := config.Load(a.Paths.ConfigFile())
	if err != nil {
		return UsageErrorf("%v", err)
	}
	state, err := config.LoadState(a.Paths.StateFile())
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	interactive := !opts.NonInteractive && a.IsTTY
	reader := bufio.NewReader(a.Stdin)

	var dockerErr error
	if opts.TrivyMode != "global" {
		_, dockerErr = runner.DetectDocker(cmd.Context())
	}

	decision, err := decideSetup(opts, cfg, interactive, reader, a.Stderr, dockerErr)
	if err != nil {
		return err
	}

	ms, err := manifest.Load()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	engine, err := ms.Engine("trivy")
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return IncompleteErrorf("resolver HOME: %v", err)
	}

	if decision.Semgrep {
		spec, err := ms.Adapter("semgrep")
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		if decision.Mode == "docker" {
			if _, err := provision.EnsureDockerImage(cmd.Context(), "docker", spec.Image, true); err != nil {
				return IncompleteErrorf("preparar Semgrep: %v", err)
			}
		} else {
			bin, err := exec.LookPath("semgrep")
			if err != nil {
				return IncompleteErrorf("Semgrep está habilitado y no se encontró en PATH; instálalo en su versión %s o usa Docker", spec.Version)
			}
			if err := provision.VerifySemgrepVersion(cmd.Context(), bin, spec.Version); err != nil {
				return IncompleteErrorf("Semgrep habilitado: %v", err)
			}
		}
		preparationsSemgrep := "Semgrep " + spec.Version + " verificado"
		defer func() { slog.Info("preparado", "detalle", preparationsSemgrep) }()
	}

	var preparations []string
	switch decision.Mode {
	case "docker":
		if _, err := provision.EnsureDockerImage(cmd.Context(), "docker", engine.Image, true); err != nil {
			return IncompleteErrorf("%v", err)
		}
		volume := runner.VolumeName(os.Getuid())
		if _, err := provision.EnsureVolume(cmd.Context(), "docker", volume); err != nil {
			return IncompleteErrorf("%v", err)
		}
		state.DockerVolume = volume
		preparations = append(preparations, "imagen "+engine.Image, "volumen "+volume)

	case "global":
		res, err := provision.EnsureTrivy(cmd.Context(), provision.Options{Paths: a.Paths, Manifest: ms})
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		preparations = append(preparations, "Trivy "+engine.Version+" en "+res.Path)
		state.RecordInstall(config.Install{
			Engine: "trivy", Version: engine.Version, Path: res.Path, SHA256: res.SHA256,
			InstalledAt: a.Now().UTC(),
		})

		link := filepath.Join(platform.UserBinDir(home), "trivy")
		changed, err := platform.EnsureUserLink(link, res.Path, filepath.Join(a.Paths.DataDir, "engines"))
		if err != nil {
			return IncompleteErrorf("enlace global de Trivy: %v", err)
		}
		if changed {
			preparations = append(preparations, "enlace "+link)
		}

		shell, shellErr := platform.ShellFromEnv()
		if shellErr != nil {
			slog.Warn("perfil de shell no editado", "error", shellErr, "sugerencia", "agrega $HOME/.local/bin al PATH manualmente")
		} else {
			prof, err := platform.EnsureProfilePATH(home, shell, a.Now())
			if err != nil {
				return IncompleteErrorf("editar perfil de shell: %v", err)
			}
			if prof.Changed {
				state.RecordProfileEdit(config.ProfileEdit{
					File: prof.File, Marker: platform.ProfileMarkerStart,
					BackupPath: prof.BackupPath, AppliedAt: a.Now().UTC(),
				})
				preparations = append(preparations, "perfil "+prof.File+" (abre una terminal nueva)")
			}
		}
	default:
		return IncompleteErrorf("modalidad desconocida: %q", decision.Mode)
	}

	cfg.TrivyMode = decision.Mode
	cfg.SemgrepEnabled = decision.Semgrep
	state.TrivyModeOrigin = "setup"

	if err := config.SaveState(a.Paths.StateFile(), state); err != nil {
		return IncompleteErrorf("%v", err)
	}
	if err := config.Save(a.Paths.ConfigFile(), cfg); err != nil {
		return IncompleteErrorf("%v", err)
	}

	slog.Info("setup completado", "trivy_mode", decision.Mode, "semgrep", decision.Semgrep)
	for _, p := range preparations {
		slog.Info("preparado", "detalle", p)
	}
	if decision.Semgrep {
		slog.Info("Semgrep queda habilitado en la configuración; su aprovisionamiento se completa en H6")
	}
	return nil
}

// decideSetup aplica la precedencia: flag → preferencia guardada → pregunta (si
// hay terminal) → default. Nunca cambia de modalidad de forma silenciosa.
func decideSetup(opts setupOptions, cfg config.Config, interactive bool, reader *bufio.Reader, w io.Writer, dockerErr error) (setupDecision, error) {
	decision := setupDecision{Semgrep: cfg.SemgrepEnabled}

	switch opts.TrivyMode {
	case "docker":
		if dockerErr != nil {
			return decision, &DockerSetupError{Err: dockerErr}
		}
		decision.Mode = "docker"
	case "global":
		decision.Mode = "global"
	case "":
		if cfg.TrivyMode != "" {
			decision.Mode = cfg.TrivyMode
			if decision.Mode == "docker" && dockerErr != nil {
				return decision, &DockerSetupError{Err: dockerErr}
			}
			break
		}
		if interactive {
			mode, err := askTrivyMode(reader, w, dockerErr)
			if err != nil {
				return decision, err
			}
			decision.Mode = mode
			break
		}
		if dockerErr == nil {
			decision.Mode = "docker"
		} else {
			decision.Mode = "global"
		}
	default:
		return decision, UsageErrorf("--trivy-mode inválido: %q", opts.TrivyMode)
	}

	switch opts.Semgrep {
	case "enable":
		decision.Semgrep = true
	case "disable":
		decision.Semgrep = false
	case "":
		if interactive {
			enabled, err := askSemgrep(reader, w, cfg.SemgrepEnabled)
			if err != nil {
				return decision, err
			}
			decision.Semgrep = enabled
		}
	}
	return decision, nil
}

// DockerSetupError explica que la modalidad elegida no puede prepararse.
type DockerSetupError struct{ Err error }

func (e *DockerSetupError) Error() string {
	return fmt.Sprintf("se eligió Docker y no está operativo: %v", e.Err)
}

func (e *DockerSetupError) Unwrap() error { return e.Err }

func askTrivyMode(reader *bufio.Reader, w io.Writer, dockerErr error) (string, error) {
	if dockerErr != nil {
		_, _ = fmt.Fprintf(w, "Docker no está disponible (%v).\nSe instalará Trivy globalmente. ¿Continuar? [s/N]: ", dockerErr)
		answer, err := readAnswer(reader)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(strings.ToLower(answer), "s") {
			return "", errors.New("setup cancelado por el usuario")
		}
		return "global", nil
	}
	_, _ = fmt.Fprint(w, "¿Cómo deseas utilizar Trivy?\n  1. Usar Docker (recomendado), con volumen persistente para las bases.\n  2. Instalar Trivy globalmente, como comando disponible en la terminal.\nElige 1 o 2: ")
	answer, err := readAnswer(reader)
	if err != nil {
		return "", err
	}
	switch answer {
	case "1", "":
		return "docker", nil
	case "2":
		return "global", nil
	default:
		return "", errors.New("respuesta inválida en setup")
	}
}

func askSemgrep(reader *bufio.Reader, w io.Writer, current bool) (bool, error) {
	def := "s/N"
	if current {
		def = "S/n"
	}
	_, _ = fmt.Fprintf(w, "¿Deseas habilitar Semgrep CE? Es opcional y está desactivado por defecto [%s]: ", def)
	answer, err := readAnswer(reader)
	if err != nil {
		return false, err
	}
	if answer == "" {
		return current, nil
	}
	return strings.HasPrefix(strings.ToLower(answer), "s"), nil
}

func readAnswer(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("entrada cancelada: %w", err)
	}
	return strings.TrimSpace(line), nil
}
