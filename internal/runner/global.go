package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// Límites por defecto del runner global.
const (
	DefaultMaxOutput = 64 << 20
	DefaultMaxStderr = 1 << 20
	DefaultTimeout   = 10 * time.Minute
	// invalidProxy no debe tener nada escuchando: los motores que respetan el
	// proxy fallan en lugar de conectarse (design §6.2).
	invalidProxy = "http://127.0.0.1:9"
)

// Global ejecuta motores instalados en el equipo, con el entorno mínimo y el
// grupo de procesos descritos en design §6.2 y §6.4.
type Global struct {
	Paths     platform.Paths
	MaxOutput int64
	MaxStderr int64
	// BasePATH es el PATH mínimo que se entrega a los motores. Si está vacío
	// se usa el del sistema más el directorio del binario.
	BasePATH string
	// Proxy permite sustituir el proxy inválido en pruebas.
	Proxy string
}

// Kind identifica el runner en el reporte.
func (g *Global) Kind() string { return "global" }

// Isolation declara el nivel que este runner garantiza hoy. `enforced` en
// Linux es una extensión opcional fuera de v1 (design §6.3).
func (g *Global) Isolation(context.Context) (IsolationLevel, error) {
	return IsolationConfigured, nil
}

// Run ejecuta una invocación. Un código de salida distinto de cero no es un
// error de Run: el adaptador decide qué significa. Un error se devuelve solo
// cuando el proceso no pudo iniciarse o el contexto se agotó.
func (g *Global) Run(ctx context.Context, inv Invocation) (Result, error) {
	if inv.Binary == "" || !filepath.IsAbs(inv.Binary) {
		return Result{}, fmt.Errorf("runner global: el binario debe ser una ruta absoluta, recibido %q", inv.Binary)
	}
	if inv.MaxOutput == 0 {
		inv.MaxOutput = g.maxOutput()
	}
	timeout := inv.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	env, err := g.buildEnv(inv)
	if err != nil {
		return Result{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// #nosec G204 -- el binario es una ruta absoluta verificada y los
	// argumentos no pasan por shell.
	cmd := exec.CommandContext(runCtx, inv.Binary, inv.Args...)
	cmd.Dir = inv.Dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout := &cappedBuffer{limit: inv.MaxOutput, onExceed: cancel}
	stderr := &cappedBuffer{limit: g.maxStderr()}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// SIGTERM al grupo completo; WaitDelay remata con SIGKILL si no termina.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = 5 * time.Second

	start := time.Now()
	waitErr := cmd.Run()
	result := Result{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Duration:  time.Since(start),
		Truncated: stdout.Truncated() || stderr.Truncated(),
		Canceled:  ctx.Err() != nil,
		TimedOut:  errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil,
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		result.ExitCode = -1
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return result, fmt.Errorf("ejecutar %s: %w", inv.Binary, waitErr)
		}
	}
	if result.Truncated {
		return result, fmt.Errorf("la salida de %s superó el tope de %d bytes", inv.Engine, inv.MaxOutput)
	}
	return result, nil
}

func (g *Global) maxOutput() int64 {
	if g.MaxOutput > 0 {
		return g.MaxOutput
	}
	return DefaultMaxOutput
}

func (g *Global) maxStderr() int64 {
	if g.MaxStderr > 0 {
		return g.MaxStderr
	}
	return DefaultMaxStderr
}

// buildEnv construye el entorno por lista permitida. No hereda nada del
// proceso padre salvo los valores que se enumeran aquí.
func (g *Global) buildEnv(inv Invocation) ([]string, error) {
	home := g.Paths.SandboxHome(inv.Engine)
	tmp := filepath.Join(home, "tmp")
	if err := platform.EnsurePrivateDir(home); err != nil {
		return nil, err
	}
	if err := platform.EnsurePrivateDir(tmp); err != nil {
		return nil, err
	}

	pathValue := g.BasePATH
	if pathValue == "" {
		pathValue = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	}
	pathValue = filepath.Dir(inv.Binary) + ":" + pathValue

	proxy := g.Proxy
	if proxy == "" {
		proxy = invalidProxy
	}

	env := map[string]string{
		"PATH":   pathValue,
		"HOME":   home,
		"TMPDIR": tmp,
		"LANG":   "C.UTF-8",
		"LC_ALL": "C.UTF-8",
		"TZ":     "UTC",
	}
	if !inv.AllowNetwork {
		env["HTTP_PROXY"] = proxy
		env["HTTPS_PROXY"] = proxy
		env["ALL_PROXY"] = proxy
		env["NO_PROXY"] = ""
	}

	for k, v := range inv.Env {
		if !allowedEnvKey(k) {
			return nil, fmt.Errorf("variable de entorno no permitida para %s: %q", inv.Engine, k)
		}
		if strings.ContainsAny(v, "\x00\n") {
			return nil, fmt.Errorf("valor inválido para %s", k)
		}
		env[k] = v
	}

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out, nil
}

// allowedEnvKey acota lo que un adaptador puede añadir al entorno.
func allowedEnvKey(k string) bool {
	switch k {
	case "NO_COLOR", "CI", "GOTOOLCHAIN", "GOFLAGS", "GOMODCACHE", "GOCACHE", "GOPATH", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GOWORK":
		return true
	}
	for _, prefix := range []string{"TRIVY_", "SEMGREP_", "BANDIT_", "ESLINT_", "PSALM_", "CGC_SCAN_"} {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// cappedBuffer acumula hasta limit bytes y marca el exceso, sin bloquear al
// proceso hijo ni reservar memoria sin control.
type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
	onExceed  func()
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := c.limit - int64(c.buf.Len())
	if remaining > 0 {
		if int64(len(p)) <= remaining {
			_, _ = c.buf.Write(p)
		} else {
			_, _ = c.buf.Write(p[:remaining])
			remaining = 0
		}
	}
	if int64(len(p)) > remaining || remaining == 0 {
		if !c.truncated {
			c.truncated = true
			if c.onExceed != nil {
				c.onExceed()
			}
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.buf.Len())
	copy(out, c.buf.Bytes())
	return out
}

func (c *cappedBuffer) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

var _ io.Writer = (*cappedBuffer)(nil)
