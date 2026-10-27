// Package provision instala motores verificados contra el manifiesto de
// confianza (design §7). Nunca ejecuta scripts remotos ni escribe en el
// proyecto.
package provision

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// Límites de descarga y extracción. El archivo de Trivy ronda los 60 MB; el
// tope deja margen sin permitir un disco lleno por un artefacto manipulado.
const (
	DefaultMaxDownload = 250 << 20
	DefaultMaxBinary   = 300 << 20
)

// Options configura la instalación.
type Options struct {
	Paths       platform.Paths
	Manifest    *manifest.Manifest
	HTTPClient  *http.Client
	GOOS        string
	GOARCH      string
	MaxDownload int64
	// Now permite fijar el reloj en pruebas.
	Now func() time.Time
}

// Result describe una instalación o reutilización.
type Result struct {
	Path      string
	Version   string
	Installed bool // verdadero si se descargó en esta llamada
	SHA256    string
}

// EnsureTrivy devuelve la ruta absoluta del binario fijado, instalándolo si
// falta. Es idempotente y seguro ante ejecuciones concurrentes.
func EnsureTrivy(ctx context.Context, opts Options) (Result, error) {
	if opts.Manifest == nil {
		return Result{}, errors.New("provisión: manifiesto ausente")
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 5 * time.Minute}
	}
	if opts.MaxDownload == 0 {
		opts.MaxDownload = DefaultMaxDownload
	}

	engine, err := opts.Manifest.Engine("trivy")
	if err != nil {
		return Result{}, err
	}
	archive, err := engine.Archive(opts.GOOS, opts.GOARCH)
	if err != nil {
		return Result{}, err
	}

	dir := opts.Paths.EngineDir("trivy", engine.Version)
	binPath := filepath.Join(dir, "trivy")

	// Camino rápido: ya está instalado y responde con la versión fijada.
	if ok, _ := verifyBinary(ctx, binPath, engine.Version); ok {
		return Result{Path: binPath, Version: engine.Version, SHA256: archive.SHA256}, nil
	}

	lock, err := platform.Acquire(ctx, filepath.Join(opts.Paths.LocksDir(), "engine-trivy.lock"), false, 5*time.Minute)
	if err != nil {
		return Result{}, fmt.Errorf("bloquear instalación de trivy: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Otra ejecución pudo instalarlo mientras esperábamos el bloqueo.
	if ok, _ := verifyBinary(ctx, binPath, engine.Version); ok {
		return Result{Path: binPath, Version: engine.Version, SHA256: archive.SHA256}, nil
	}

	if err := platform.EnsurePrivateDir(dir); err != nil {
		return Result{}, err
	}

	tmpArchive, err := os.CreateTemp(dir, ".trivy-download-*")
	if err != nil {
		return Result{}, fmt.Errorf("crear temporal de descarga: %w", err)
	}
	tmpArchivePath := tmpArchive.Name()
	defer func() { _ = os.Remove(tmpArchivePath) }()

	sum, err := downloadVerified(ctx, opts.HTTPClient, archive.URL, archive.SHA256, opts.MaxDownload, tmpArchive)
	if err != nil {
		_ = tmpArchive.Close()
		return Result{}, err
	}
	if err := tmpArchive.Close(); err != nil {
		return Result{}, err
	}

	binTmp, err := os.CreateTemp(dir, ".trivy-bin-*")
	if err != nil {
		return Result{}, err
	}
	binTmpPath := binTmp.Name()
	defer func() { _ = os.Remove(binTmpPath) }()

	if err := extractBinary(tmpArchivePath, "trivy", binTmp); err != nil {
		_ = binTmp.Close()
		return Result{}, err
	}
	if err := binTmp.Sync(); err != nil {
		_ = binTmp.Close()
		return Result{}, err
	}
	if err := binTmp.Close(); err != nil {
		return Result{}, err
	}
	if err := os.Chmod(binTmpPath, 0o755); err != nil { //nolint:gosec // el binario debe ser ejecutable
		return Result{}, err
	}
	if ok, detail := verifyBinary(ctx, binTmpPath, engine.Version); !ok {
		return Result{}, fmt.Errorf("el binario descargado no responde con la versión %s: %s", engine.Version, detail)
	}
	if err := os.Rename(binTmpPath, binPath); err != nil {
		return Result{}, fmt.Errorf("publicar trivy: %w", err)
	}
	return Result{Path: binPath, Version: engine.Version, Installed: true, SHA256: sum}, nil
}

// downloadVerified copia el cuerpo a dst calculando el SHA-256 y aplicando el
// tope de tamaño. Si el hash no coincide, borra el destino.
func downloadVerified(ctx context.Context, client *http.Client, url, want string, max int64, dst *os.File) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("descargar %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("descargar %s: HTTP %d", url, resp.StatusCode)
	}

	h := sha256.New()
	limited := io.LimitReader(resp.Body, max+1)
	n, err := io.Copy(io.MultiWriter(dst, h), limited)
	if err != nil {
		return "", fmt.Errorf("descargar %s: %w", url, err)
	}
	if n > max {
		return "", fmt.Errorf("descargar %s: supera el tope de %d bytes", url, max)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return "", fmt.Errorf("checksum de %s no coincide: got %s, want %s", path.Base(url), got, want)
	}
	return got, nil
}

// extractBinary extrae solo el miembro indicado, rechazando rutas absolutas,
// `..`, enlaces y tipos distintos de archivo regular.
func extractBinary(archivePath, want string, dst io.Writer) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("archivo no es gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("leer tar: %w", err)
		}
		clean := path.Clean(hdr.Name)
		if path.IsAbs(hdr.Name) || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("archivo contiene una ruta insegura: %q", hdr.Name)
		}
		if path.Base(clean) != want {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%s no es un archivo regular (tipo %c)", hdr.Name, hdr.Typeflag)
		}
		if found {
			return fmt.Errorf("archivo contiene %s más de una vez", want)
		}
		if hdr.Size > DefaultMaxBinary {
			return fmt.Errorf("%s supera el tamaño máximo", want)
		}
		if _, err := io.CopyN(dst, tr, hdr.Size); err != nil {
			return fmt.Errorf("extraer %s: %w", want, err)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("archivo no contiene %s", want)
	}
	return nil
}

// verifyBinary ejecuta el binario con --version y comprueba la versión fijada.
func verifyBinary(ctx context.Context, bin, want string) (bool, string) {
	if _, err := os.Stat(bin); err != nil {
		return false, err.Error()
	}
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, bin, "--version").CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("ejecutar --version: %v", err)
	}
	text := string(out)
	if strings.Contains(text, "Version: "+want) || strings.Contains(text, "version "+want) {
		return true, text
	}
	return false, "versión inesperada: " + strings.TrimSpace(text)
}
