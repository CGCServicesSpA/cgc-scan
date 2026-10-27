package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// DBInfo es el estado de la base de Trivy leído de la caché.
type DBInfo struct {
	Source     string
	Status     string
	UpdatedAt  time.Time
	AgeSeconds int64
	Schema     int
	Path       string
	Detail     string
}

// ErrDBAbsent indica que no hay base local.
var ErrDBAbsent = errors.New("no hay base de datos local de Trivy")

// ReadDBInfo lee <cache>/db/metadata.json sin modificar nada.
func ReadDBInfo(cacheDir string) (DBInfo, error) {
	path := filepath.Join(cacheDir, "db", "metadata.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DBInfo{}, ErrDBAbsent
		}
		return DBInfo{}, fmt.Errorf("leer metadatos de la base: %w", err)
	}
	return parseDBMetadata(data)
}

func parseDBMetadata(data []byte) (DBInfo, error) {
	var meta struct {
		Version      int    `json:"Version"`
		UpdatedAt    string `json:"UpdatedAt"`
		DownloadedAt string `json:"DownloadedAt"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return DBInfo{}, fmt.Errorf("metadatos de la base inválidos: %w", err)
	}
	updated := meta.UpdatedAt
	if updated == "" {
		updated = meta.DownloadedAt
	}
	t, err := time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return DBInfo{}, fmt.Errorf("fecha de la base inválida: %w", err)
	}
	return DBInfo{
		Source:     "trivy-db",
		UpdatedAt:  t.UTC(),
		Schema:     meta.Version,
		AgeSeconds: int64(time.Since(t).Seconds()),
	}, nil
}

// UpdateDB ejecuta el actualizador de Trivy sobre la caché indicada. Debe
// llamarse con el bloqueo exclusivo tomado y sin el proyecto montado.
func UpdateDB(ctx context.Context, r runner.Runner, binary, cacheDir string, timeout time.Duration) (DBInfo, error) {
	args := []string{
		"fs", "--download-db-only",
		"--cache-dir", cacheDir,
		"--disable-telemetry", "--skip-version-check", "--no-progress",
	}
	inv := runner.Invocation{
		Engine:       "trivy",
		Binary:       binary,
		Args:         args,
		Env:          map[string]string{"TRIVY_SKIP_VERSION_CHECK": "true"},
		AllowNetwork: true, // la preparación puede descargar; el escaneo no
		Timeout:      timeout,
		MaxOutput:    1 << 20,
	}
	res, err := r.Run(ctx, inv)
	if err != nil {
		return DBInfo{}, fmt.Errorf("actualizar la base de Trivy: %w", err)
	}
	if res.ExitCode != 0 {
		return DBInfo{}, fmt.Errorf("actualizar la base de Trivy: el motor terminó con código %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	info, err := ReadDBInfo(cacheDir)
	if err != nil {
		return DBInfo{}, err
	}
	info.Status = "updated"
	return info, nil
}

// CheckDBOffline valida la base con la política de antigüedad. No hace red.
func CheckDBOffline(cacheDir string, warnAfter, blockAfter time.Duration) (DBInfo, error) {
	info, err := ReadDBInfo(cacheDir)
	if err != nil {
		return DBInfo{}, err
	}
	if err := CheckDBAge(&info, warnAfter, blockAfter); err != nil {
		return info, err
	}
	return info, nil
}

// CheckDBAge aplica la política de antigüedad a una base ya leída.
func CheckDBAge(info *DBInfo, warnAfter, blockAfter time.Duration) error {
	if info.UpdatedAt.IsZero() {
		info.Status = "missing"
		return ErrDBAbsent
	}
	age := time.Since(info.UpdatedAt)
	switch {
	case blockAfter > 0 && age > blockAfter:
		info.Status = "stale"
		return fmt.Errorf("la base local tiene %s de antigüedad y supera el máximo offline de %s", age.Round(time.Hour), blockAfter)
	case warnAfter > 0 && age > warnAfter:
		info.Status = "stale"
	default:
		info.Status = "offline"
	}
	return nil
}

func lastLine(b []byte) string {
	s := string(b)
	line := ""
	for _, l := range splitLines(s) {
		if l != "" {
			line = l
		}
	}
	return line
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
