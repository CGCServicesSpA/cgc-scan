package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DockerInfo describe el daemon local.
type DockerInfo struct {
	Version  string
	Arch     string
	Context  string
	Endpoint string
}

// DockerError clasifica un fallo de detección.
type DockerError struct {
	Code    string
	Message string
	Err     error
}

func (e *DockerError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *DockerError) Unwrap() error { return e.Err }

// DetectDocker comprueba que el daemon responde, que el contexto es local y
// que la arquitectura está soportada. Nunca cambia el contexto ni arranca
// Docker Desktop (PRD §6.3).
func DetectDocker(ctx context.Context) (DockerInfo, error) {
	dockerBin := "docker"
	if _, err := exec.LookPath(dockerBin); err != nil {
		return DockerInfo{}, &DockerError{Code: "docker_unavailable", Message: "el CLI de Docker no está instalado", Err: err}
	}

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// Contexto y endpoint efectivos.
	out, err := exec.CommandContext(dctx, dockerBin, "context", "inspect", "--format", "{{.Name}}|{{.Endpoints.docker.Host}}").Output()
	if err != nil {
		return DockerInfo{}, &DockerError{Code: "docker_unavailable", Message: "no se pudo inspeccionar el contexto de Docker", Err: err}
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	info := DockerInfo{}
	if len(parts) == 2 {
		info.Context, info.Endpoint = parts[0], parts[1]
	}
	if remoteEndpoint(info.Endpoint) {
		return info, &DockerError{
			Code:    "docker_remote_context",
			Message: fmt.Sprintf("el contexto %q apunta a un daemon remoto (%s); no es elegible", info.Context, info.Endpoint),
		}
	}
	if v := os.Getenv("DOCKER_HOST"); remoteEndpoint(v) {
		return info, &DockerError{
			Code:    "docker_remote_context",
			Message: fmt.Sprintf("DOCKER_HOST apunta a un daemon remoto (%s); no es elegible", v),
		}
	}

	// Daemon y arquitectura.
	out, err = exec.CommandContext(dctx, dockerBin, "version", "--format", "{{.Server.Version}}|{{.Server.Arch}}").Output()
	if err != nil {
		return info, &DockerError{Code: "docker_unavailable", Message: "el daemon de Docker no responde", Err: err}
	}
	parts = strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(parts) != 2 || parts[0] == "" {
		return info, &DockerError{Code: "docker_unavailable", Message: "respuesta inesperada de docker version"}
	}
	info.Version, info.Arch = parts[0], parts[1]
	switch info.Arch {
	case "amd64", "arm64", "x86_64", "aarch64":
	default:
		return info, &DockerError{
			Code:    "docker_arch_unsupported",
			Message: fmt.Sprintf("la arquitectura del daemon %q no está soportada", info.Arch),
		}
	}
	return info, nil
}

func remoteEndpoint(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return strings.HasPrefix(h, "tcp://") || strings.HasPrefix(h, "ssh://") || strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://")
}

// ResolveRequest es la entrada de la matriz de selección del runner.
type ResolveRequest struct {
	// Explicit es el valor de --trivy-mode (vacío si no se pasó).
	Explicit string
	// Stored es la preferencia guardada por setup (vacía si no existe).
	Stored string
	// DockerOK indica si DetectDocker tuvo éxito.
	DockerOK bool
	// DockerErr es la causa cuando DockerOK es falso.
	DockerErr error
}

// ResolveResult es la decisión y su origen.
type ResolveResult struct {
	Mode           string // docker | global
	Origin         string // flag | setup | default
	FallbackReason string // solo cuando no había preferencia y Docker no estaba disponible
}

// Resolve aplica la matriz de PRD §6.2: una elección explícita o guardada
// nunca cae en fallback silencioso; sin elección se prefiere Docker local y,
// si no está operativo, se usa la instalación global.
func Resolve(in ResolveRequest) (ResolveResult, error) {
	mode, origin := in.Explicit, "flag"
	if mode == "" {
		mode, origin = in.Stored, "setup"
	}
	switch mode {
	case "":
		if in.DockerOK {
			return ResolveResult{Mode: "docker", Origin: "default"}, nil
		}
		return ResolveResult{
			Mode: "global", Origin: "default",
			FallbackReason: fmt.Sprintf("Docker no está disponible: %v", in.DockerErr),
		}, nil
	case "docker":
		if !in.DockerOK {
			return ResolveResult{}, &DockerError{
				Code:    "docker_unavailable",
				Message: "se eligió Docker y el daemon local no está operativo; no se cambia de modalidad",
				Err:     in.DockerErr,
			}
		}
		return ResolveResult{Mode: "docker", Origin: origin}, nil
	case "global":
		return ResolveResult{Mode: "global", Origin: origin}, nil
	default:
		return ResolveResult{}, fmt.Errorf("modalidad de Trivy desconocida: %q", mode)
	}
}
