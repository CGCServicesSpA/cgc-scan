// Package config lee y escribe la configuración de usuario (config.toml) y el
// estado local (state.json). Ambos son privados y se escriben de forma atómica.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// Defaults de la configuración.
const (
	DefaultWarnAfter         = 72 * time.Hour
	DefaultBlockAfterOffline = 168 * time.Hour
	DefaultTrivyMode         = "" // sin preferencia: decide la matriz de scan
)

// Config es el contenido de config.toml.
type Config struct {
	TrivyMode      string   `toml:"trivy_mode,omitempty"`
	SemgrepEnabled bool     `toml:"semgrep_enabled"`
	Cache          Cache    `toml:"cache"`
	DB             DB       `toml:"db"`
	Recipes        []Recipe `toml:"recipes,omitempty"`
}

// Cache agrupa la configuración de caché.
type Cache struct {
	Dir string `toml:"dir,omitempty"`
}

// DB agrupa la política de antigüedad de bases.
type DB struct {
	WarnAfter         string `toml:"warn_after,omitempty"`
	BlockAfterOffline string `toml:"block_after_offline,omitempty"`
}

// Recipe es una receta de validación confirmada por el usuario.
type Recipe struct {
	Project string   `toml:"project"`
	Unit    string   `toml:"unit"`
	Test    *Command `toml:"test,omitempty"`
	Build   *Command `toml:"build,omitempty"`
}

// Command es el comando y directorio de una receta.
type Command struct {
	Command string `toml:"command"`
	Workdir string `toml:"workdir,omitempty"`
}

// Default devuelve la configuración por defecto.
func Default() Config {
	return Config{
		DB: DB{
			WarnAfter:         "72h",
			BlockAfterOffline: "168h",
		},
	}
}

// Load lee config.toml. Si no existe, devuelve los valores por defecto sin
// error. Un archivo inválido es un error de configuración (código 2).
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, fmt.Errorf("leer %s: %w", path, err)
	}
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("configuración inválida en %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("configuración inválida en %s: %w", path, err)
	}
	return cfg, nil
}

// Validate comprueba valores y completa defaults vacíos.
func (c *Config) Validate() error {
	switch c.TrivyMode {
	case "", "docker", "global":
	default:
		return fmt.Errorf("trivy_mode inválido: %q", c.TrivyMode)
	}
	if c.Cache.Dir != "" && !filepath.IsAbs(c.Cache.Dir) {
		return fmt.Errorf("cache.dir debe ser absoluto: %q", c.Cache.Dir)
	}
	if c.DB.WarnAfter == "" {
		c.DB.WarnAfter = "72h"
	}
	if c.DB.BlockAfterOffline == "" {
		c.DB.BlockAfterOffline = "168h"
	}
	if _, err := time.ParseDuration(c.DB.WarnAfter); err != nil {
		return fmt.Errorf("db.warn_after inválido: %w", err)
	}
	if _, err := time.ParseDuration(c.DB.BlockAfterOffline); err != nil {
		return fmt.Errorf("db.block_after_offline inválido: %w", err)
	}
	for i := range c.Recipes {
		r := &c.Recipes[i]
		if r.Project == "" || !filepath.IsAbs(r.Project) {
			return fmt.Errorf("recetas[%d].project debe ser absoluto", i)
		}
		if r.Unit == "" {
			return fmt.Errorf("recetas[%d].unit es obligatorio", i)
		}
		for kind, cmd := range map[string]*Command{"test": r.Test, "build": r.Build} {
			if cmd == nil {
				continue
			}
			if strings.TrimSpace(cmd.Command) == "" {
				return fmt.Errorf("recetas[%d].%s.command es obligatorio", i, kind)
			}
			if cmd.Workdir != "" && filepath.IsAbs(cmd.Workdir) {
				return fmt.Errorf("recetas[%d].%s.workdir debe ser relativo", i, kind)
			}
		}
	}
	return nil
}

// Save escribe config.toml con permisos 0600 y escritura atómica.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serializar configuración: %w", err)
	}
	if err := platform.WritePrivateFile(path, data); err != nil {
		return fmt.Errorf("guardar configuración: %w", err)
	}
	return nil
}

// WarnAfter devuelve el umbral de aviso.
func (c Config) WarnAfter() time.Duration {
	d, _ := time.ParseDuration(c.DB.WarnAfter)
	return d
}

// BlockAfterOffline devuelve el umbral de bloqueo offline.
func (c Config) BlockAfterOffline() time.Duration {
	d, _ := time.ParseDuration(c.DB.BlockAfterOffline)
	return d
}

// CacheDir resuelve la caché efectiva.
func (c Config) CacheDir(defaultDir string) string {
	if c.Cache.Dir != "" {
		return c.Cache.Dir
	}
	return defaultDir
}
