// Package platform resuelve las ubicaciones de estado de la CLI y las
// operaciones de archivo que deben ser atómicas o privadas.
package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Variables de entorno que sobrescriben las ubicaciones.
const (
	EnvConfigDir = "CGC_SCAN_CONFIG_DIR"
	EnvDataDir   = "CGC_SCAN_DATA_DIR"
	EnvCacheDir  = "CGC_SCAN_CACHE_DIR"
)

// Paths agrupa los tres directorios raíz de la CLI. Cada uno apunta ya al
// directorio propio de cgc-scan, no a su padre.
type Paths struct {
	ConfigDir string
	DataDir   string
	CacheDir  string
}

// Resolve calcula las ubicaciones. En Linux respeta XDG; en macOS usa los
// directorios estándar de usuario. Las variables CGC_SCAN_*_DIR tienen
// prioridad y se usan tal cual.
func Resolve() (Paths, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolver directorio de configuración: %w", err)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolver directorio de caché: %w", err)
	}

	p := Paths{
		ConfigDir: filepath.Join(config, "cgc-scan"),
		DataDir:   filepath.Join(config, "cgc-scan"),
		CacheDir:  filepath.Join(cache, "cgc-scan"),
	}

	if runtime.GOOS != "darwin" {
		// En Linux (y otros Unix) se prefieren las variables XDG.
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			p.ConfigDir = filepath.Join(xdg, "cgc-scan")
		}
		data := os.Getenv("XDG_DATA_HOME")
		if data == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return Paths{}, fmt.Errorf("resolver HOME: %w", err)
			}
			data = filepath.Join(home, ".local", "share")
		}
		p.DataDir = filepath.Join(data, "cgc-scan")
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
			p.CacheDir = filepath.Join(xdg, "cgc-scan")
		}
	}

	if v := os.Getenv(EnvConfigDir); v != "" {
		p.ConfigDir = v
	}
	if v := os.Getenv(EnvDataDir); v != "" {
		p.DataDir = v
	}
	if v := os.Getenv(EnvCacheDir); v != "" {
		p.CacheDir = v
	}

	for _, dir := range []string{p.ConfigDir, p.DataDir, p.CacheDir} {
		if !filepath.IsAbs(dir) {
			return Paths{}, fmt.Errorf("la ruta %q no es absoluta", dir)
		}
	}
	return p, nil
}

// ConfigFile es el archivo de configuración de usuario.
func (p Paths) ConfigFile() string { return filepath.Join(p.ConfigDir, "config.toml") }

// StateFile es el registro de instalaciones y ediciones de perfil.
func (p Paths) StateFile() string { return filepath.Join(p.DataDir, "state.json") }

// SaltFile contiene la sal por instalación usada para la huella de secretos.
func (p Paths) SaltFile() string { return filepath.Join(p.DataDir, "secret.salt") }

// EngineDir es el directorio de una versión instalada de un motor.
func (p Paths) EngineDir(engine, version string) string {
	return filepath.Join(p.DataDir, "engines", engine, version)
}

// TrivyCacheDir es la caché de bases del runner global.
func (p Paths) TrivyCacheDir() string { return filepath.Join(p.CacheDir, "trivy") }

// RunsDir es el directorio de salidas originales de una ejecución.
func (p Paths) RunsDir(runID string) string { return filepath.Join(p.CacheDir, "runs", runID) }

// LocksDir es el directorio de bloqueos de archivo.
func (p Paths) LocksDir() string { return filepath.Join(p.DataDir, "locks") }

// SandboxHome es el HOME aislado de un motor.
func (p Paths) SandboxHome(engine string) string {
	return filepath.Join(p.DataDir, "sandbox-home", engine)
}

// EnsureDirs crea los directorios raíz con permisos 0700. Es idempotente.
func (p Paths) EnsureDirs() error {
	for _, dir := range []string{p.ConfigDir, p.DataDir, p.CacheDir} {
		if err := EnsurePrivateDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// EnsurePrivateDir crea un directorio (y sus padres) con permisos 0700.
// Si ya existe, no cambia sus permisos: solo verifica que sea un directorio.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("crear directorio %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("verificar directorio %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s no es un directorio", dir)
	}
	return nil
}

// ErrNotRegular se devuelve cuando una ruta esperada como archivo es otra cosa.
var ErrNotRegular = errors.New("la ruta no es un archivo regular")
