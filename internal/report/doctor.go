package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// DoctorReport es el diagnóstico de solo lectura de la CLI (RF-03).
type DoctorReport struct {
	GeneratedAt string                   `json:"generated_at"`
	Config      DoctorConfig             `json:"config"`
	Docker      DoctorDocker             `json:"docker"`
	Trivy       DoctorTrivy              `json:"trivy"`
	Isolation   DoctorIsolation          `json:"isolation"`
	Semgrep     DoctorSemgrep            `json:"semgrep"`
	Adapters    map[string]DoctorAdapter `json:"adapters"`
	Policy      DoctorPolicy             `json:"project_policy"`
}

// DoctorConfig describe la configuración efectiva.
type DoctorConfig struct {
	Path           string `json:"path"`
	Present        bool   `json:"present"`
	TrivyMode      string `json:"trivy_mode"`
	SemgrepEnabled bool   `json:"semgrep_enabled"`
	CacheDir       string `json:"cache_dir"`
	DBWarnAfter    string `json:"db_warn_after"`
	DBBlockOffline string `json:"db_block_after_offline"`
	Error          string `json:"error,omitempty"`
}

// DoctorDocker describe el daemon.
type DoctorDocker struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Context   string `json:"context,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Error     string `json:"error,omitempty"`
}

// DoctorTrivy describe la instalación y la base.
type DoctorTrivy struct {
	Installed bool     `json:"installed"`
	Path      string   `json:"path,omitempty"`
	Version   string   `json:"version,omitempty"`
	Link      string   `json:"link,omitempty"`
	LinkOK    bool     `json:"link_ok"`
	DB        *DBState `json:"db,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// DoctorIsolation declara el nivel disponible.
type DoctorIsolation struct {
	Level  string `json:"level"`
	Reason string `json:"reason"`
}

// DoctorSemgrep describe el análisis opcional.
type DoctorSemgrep struct {
	Enabled   bool   `json:"enabled"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Note      string `json:"note,omitempty"`
}

// DoctorAdapter describe un adaptador y su toolchain.
type DoctorAdapter struct {
	Toolchain string `json:"toolchain"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

// DoctorPolicy describe la política del proyecto en el directorio actual.
type DoctorPolicy struct {
	Present bool   `json:"present"`
	Path    string `json:"path,omitempty"`
	Issues  int    `json:"issues"`
	Error   string `json:"error,omitempty"`
}

// EmitDoctor escribe el diagnóstico en el formato pedido.
func EmitDoctor(w io.Writer, r *DoctorReport, format string) error {
	if format == "json" {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(data, '\n'))
		return err
	}
	_, err := io.WriteString(w, renderDoctorText(r))
	return err
}

func renderDoctorText(r *DoctorReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CGC Scan doctor - %s\n", r.GeneratedAt)
	cfg := r.Config
	fmt.Fprintf(&b, "Configuracion: %s", cfg.Path)
	if cfg.Present {
		fmt.Fprintf(&b, " (trivy_mode=%s, semgrep=%v, cache=%s)\n", cfg.TrivyMode, cfg.SemgrepEnabled, cfg.CacheDir)
	} else {
		fmt.Fprintln(&b, " (no existe; se usan valores por defecto)")
	}
	if cfg.Error != "" {
		fmt.Fprintf(&b, "  error: %s\n", cfg.Error)
	}
	if r.Docker.Available {
		fmt.Fprintf(&b, "Docker: OK %s %s (contexto %s)\n", r.Docker.Version, r.Docker.Arch, r.Docker.Context)
	} else {
		fmt.Fprintf(&b, "Docker: no disponible (%s)\n", r.Docker.Error)
	}
	if r.Trivy.Installed {
		fmt.Fprintf(&b, "Trivy: OK %s (%s)\n", r.Trivy.Version, r.Trivy.Path)
		if r.Trivy.Link != "" {
			state := "roto o ausente"
			if r.Trivy.LinkOK {
				state = "OK"
			}
			fmt.Fprintf(&b, "Enlace global: %s (%s)\n", r.Trivy.Link, state)
		}
		if r.Trivy.DB != nil {
			fmt.Fprintf(&b, "Base: %s", r.Trivy.DB.Status)
			if r.Trivy.DB.UpdatedAt != nil && *r.Trivy.DB.UpdatedAt != "" {
				fmt.Fprintf(&b, " (actualizada %s)", *r.Trivy.DB.UpdatedAt)
			}
			fmt.Fprintln(&b)
		}
	} else {
		fmt.Fprintf(&b, "Trivy: no instalado (%s)\n", r.Trivy.Error)
	}
	fmt.Fprintf(&b, "Aislamiento disponible: %s (%s)\n", r.Isolation.Level, r.Isolation.Reason)
	fmt.Fprintf(&b, "Semgrep: enabled=%v, instalado=%v", r.Semgrep.Enabled, r.Semgrep.Available)
	if r.Semgrep.Version != "" {
		fmt.Fprintf(&b, " (%s)", r.Semgrep.Version)
	}
	if r.Semgrep.Note != "" {
		fmt.Fprintf(&b, " - %s", r.Semgrep.Note)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Adaptadores:")
	keys := make([]string, 0, len(r.Adapters))
	for k := range r.Adapters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := r.Adapters[k]
		status := "falta"
		if a.Available {
			status = "OK"
		}
		fmt.Fprintf(&b, "  %-12s %-5s %s", k, status, a.Toolchain)
		if a.Version != "" {
			fmt.Fprintf(&b, " %s", a.Version)
		}
		if a.Error != "" {
			fmt.Fprintf(&b, " (%s)", a.Error)
		}
		fmt.Fprintln(&b)
	}
	if r.Policy.Present {
		fmt.Fprintf(&b, "Politica del proyecto: %s (%d problemas)\n", r.Policy.Path, r.Policy.Issues)
	} else {
		fmt.Fprintln(&b, "Politica del proyecto: no encontrada")
	}
	return b.String()
}
