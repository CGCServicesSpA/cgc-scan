package provision

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// DBSource es una fuente de datos actualizable por `update-db` (design §7.4).
type DBSource interface {
	ID() string
	Update(ctx context.Context) (DBInfo, error)
	State(ctx context.Context) (DBInfo, error)
}

// TrivySource implementa las fuentes de Trivy: trivy-db, trivy-java-db y
// trivy-checks.
type TrivySource struct {
	Kind     string // trivy-db | trivy-java-db | trivy-checks
	Runner   runner.Runner
	Docker   *runner.Docker
	Binary   string
	CacheDir string
	Timeout  time.Duration
}

// ID identifica la fuente.
func (s *TrivySource) ID() string { return s.Kind }

// Update actualiza la fuente. Debe llamarse con el bloqueo exclusivo tomado.
func (s *TrivySource) Update(ctx context.Context) (DBInfo, error) {
	if s.Timeout == 0 {
		s.Timeout = 15 * time.Minute
	}
	switch s.Kind {
	case "trivy-db":
		if s.Docker != nil {
			return UpdateDBDocker(ctx, s.Docker, s.Timeout)
		}
		return UpdateDB(ctx, s.Runner, s.Binary, s.CacheDir, s.Timeout)
	case "trivy-java-db":
		return s.updateOnly(ctx, "--download-java-db-only")
	case "trivy-checks":
		if err := UpdateChecks(ctx, s.Runner, s.Binary, s.CacheDir, s.Timeout); err != nil {
			return DBInfo{}, err
		}
		return DBInfo{Source: s.Kind, Status: "updated"}, nil
	default:
		return DBInfo{}, fmt.Errorf("fuente de Trivy desconocida: %q", s.Kind)
	}
}

func (s *TrivySource) updateOnly(ctx context.Context, flag string) (DBInfo, error) {
	args := []string{"fs", flag, "--disable-telemetry", "--skip-version-check", "--no-progress"}
	cacheDir := s.CacheDir
	if s.Docker != nil {
		cacheDir = "/cache"
	}
	args = append(args, "--cache-dir", cacheDir)
	inv := runner.Invocation{
		Engine:       "trivy",
		Binary:       s.Binary,
		Args:         args,
		AllowNetwork: true,
		Timeout:      s.Timeout,
		MaxOutput:    1 << 20,
	}
	if s.Runner.Kind() == "global" {
		inv.Env = map[string]string{"TRIVY_SKIP_VERSION_CHECK": "true"}
	}
	res, err := s.Runner.Run(ctx, inv)
	if err != nil {
		return DBInfo{}, fmt.Errorf("actualizar %s: %w", s.Kind, err)
	}
	if res.ExitCode != 0 {
		return DBInfo{}, fmt.Errorf("actualizar %s: código %d: %s", s.Kind, res.ExitCode, lastLine(res.Stderr))
	}
	return DBInfo{Source: s.Kind, Status: "updated"}, nil
}

// State lee el estado sin modificar nada.
func (s *TrivySource) State(ctx context.Context) (DBInfo, error) {
	switch s.Kind {
	case "trivy-db":
		if s.Docker != nil {
			return DockerDBMetadata(ctx, s.Docker)
		}
		return ReadDBInfo(s.CacheDir)
	case "trivy-java-db":
		path := filepath.Join(s.CacheDir, "java-db", "metadata.json")
		if s.Docker != nil {
			return DBInfo{Source: s.Kind, Status: "present"}, nil
		}
		if _, err := os.Stat(path); err != nil {
			return DBInfo{}, ErrDBAbsent
		}
		return DBInfo{Source: s.Kind, Status: "present", Path: path}, nil
	case "trivy-checks":
		if s.Docker != nil {
			return DBInfo{Source: s.Kind, Status: "present"}, nil
		}
		dir := filepath.Join(s.CacheDir, "policy", "content")
		if _, err := os.Stat(dir); err != nil {
			return DBInfo{}, ErrDBAbsent
		}
		return DBInfo{Source: s.Kind, Status: "present", Path: dir}, nil
	}
	return DBInfo{}, errors.New("fuente desconocida")
}

// Sources construye la lista completa de fuentes de Trivy para update-db.
func Sources(r runner.Runner, docker *runner.Docker, binary, cacheDir string, timeout time.Duration) []DBSource {
	out := []DBSource{
		&TrivySource{Kind: "trivy-db", Runner: r, Docker: docker, Binary: binary, CacheDir: cacheDir, Timeout: timeout},
		&TrivySource{Kind: "trivy-java-db", Runner: r, Docker: docker, Binary: binary, CacheDir: cacheDir, Timeout: timeout},
		&TrivySource{Kind: "trivy-checks", Runner: r, Docker: docker, Binary: binary, CacheDir: cacheDir, Timeout: timeout},
	}
	return out
}

// GoVulnSource actualiza el espejo local de la base de Go.
type GoVulnSource struct {
	Dir    string
	Client *http.Client
}

func (s *GoVulnSource) ID() string { return "go-vulndb" }
func (s *GoVulnSource) Update(ctx context.Context) (DBInfo, error) {
	return EnsureGoVulnDB(ctx, s.Client, s.Dir, false)
}
func (s *GoVulnSource) State(context.Context) (DBInfo, error) {
	info, ok := goVulnState(s.Dir)
	if !ok {
		return DBInfo{}, ErrDBAbsent
	}
	return info, nil
}

// RustSecSource actualiza el snapshot de RustSec.
type RustSecSource struct {
	Dir    string
	Client *http.Client
}

func (s *RustSecSource) ID() string { return "rustsec" }
func (s *RustSecSource) Update(ctx context.Context) (DBInfo, error) {
	return EnsureRustSecDB(ctx, s.Client, s.Dir, false)
}
func (s *RustSecSource) State(context.Context) (DBInfo, error) {
	sha, ok := rustSecState(s.Dir)
	if !ok {
		return DBInfo{}, ErrDBAbsent
	}
	return DBInfo{Source: "rustsec", Status: "present", Detail: sha}, nil
}
