package provision

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const goVulnBase = "https://vuln.go.dev"

var goIDRe = regexp.MustCompile(`^GO-[0-9]{4}-[0-9]{4,}$`)

// EnsureGoVulnDB prepara un espejo local de la base de Go. Si existe, la
// reutiliza; si no, la descarga completa en un directorio temporal y publica
// el espejo con un rename (H4-09).
func EnsureGoVulnDB(ctx context.Context, client *http.Client, dir string, offline bool) (DBInfo, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	if info, ok := goVulnState(dir); ok {
		return info, nil
	}
	if offline {
		return DBInfo{}, ErrDBAbsent
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return DBInfo{}, err
	}
	tmp, err := os.MkdirTemp(parent, ".go-vulndb-*")
	if err != nil {
		return DBInfo{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if err := os.MkdirAll(filepath.Join(tmp, "index"), 0o700); err != nil {
		return DBInfo{}, err
	}
	var vulns []struct {
		ID string `json:"id"`
	}
	for _, name := range []string{"modules.json", "vulns.json"} {
		body, err := fetchBytes(ctx, client, goVulnBase+"/index/"+name, 64<<20)
		if err != nil {
			return DBInfo{}, err
		}
		if name == "vulns.json" {
			if err := json.Unmarshal(body, &vulns); err != nil {
				return DBInfo{}, fmt.Errorf("índice de vulnerabilidades de Go inválido: %w", err)
			}
		}
		if err := os.WriteFile(filepath.Join(tmp, "index", name), body, 0o600); err != nil {
			return DBInfo{}, err
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "ID"), 0o700); err != nil {
		return DBInfo{}, err
	}

	ids := make(chan string)
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	workers := 8
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range ids {
				if !goIDRe.MatchString(id) {
					continue
				}
				body, err := fetchBytes(ctx, client, goVulnBase+"/ID/"+id+".json", 8<<20)
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					continue
				}
				if err := os.WriteFile(filepath.Join(tmp, "ID", id+".json"), body, 0o600); err != nil {
					select {
					case errs <- err:
					default:
					}
				}
			}
		}()
	}
	for _, v := range vulns {
		select {
		case <-ctx.Done():
			close(ids)
			wg.Wait()
			return DBInfo{}, ctx.Err()
		case ids <- v.ID:
		}
	}
	close(ids)
	wg.Wait()
	select {
	case err := <-errs:
		return DBInfo{}, fmt.Errorf("descargar base de Go: %w", err)
	default:
	}

	// Publicación atómica: se aparta la base anterior y se publica la nueva.
	old := dir + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return DBInfo{}, err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.Rename(old, dir)
		return DBInfo{}, err
	}
	_ = os.RemoveAll(old)
	return DBInfo{Source: "go-vulndb", Status: "updated", UpdatedAt: time.Now().UTC(),
		Detail: fmt.Sprintf("%d avisos", len(vulns))}, nil
}

func goVulnState(dir string) (DBInfo, bool) {
	for _, name := range []string{"index/modules.json", "index/vulns.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return DBInfo{}, false
		}
	}
	info, err := os.Stat(filepath.Join(dir, "index", "vulns.json"))
	if err != nil {
		return DBInfo{}, false
	}
	return DBInfo{Source: "go-vulndb", Status: "reused", UpdatedAt: info.ModTime().UTC()}, true
}

func fetchBytes(ctx context.Context, client *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("descargar %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("descargar %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%s supera el límite de %d bytes", url, max)
	}
	return body, nil
}

// EnsureRustSecDB descarga un snapshot de RustSec fijado por commit. Sin red
// durante el escaneo (H4-09).
func EnsureRustSecDB(ctx context.Context, client *http.Client, dir string, offline bool) (DBInfo, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if sha, ok := rustSecState(dir); ok {
		return DBInfo{Source: "rustsec", Status: "reused", Detail: sha}, nil
	}
	if offline {
		return DBInfo{}, ErrDBAbsent
	}
	sha, err := latestRustSecCommit(ctx, client)
	if err != nil {
		return DBInfo{}, err
	}
	url := "https://codeload.github.com/rustsec/advisory-db/tar.gz/" + sha
	body, err := fetchBytes(ctx, client, url, 128<<20)
	if err != nil {
		return DBInfo{}, err
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return DBInfo{}, err
	}
	tmp, err := os.MkdirTemp(parent, ".rustsec-*")
	if err != nil {
		return DBInfo{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := extractTarGz(body, tmp); err != nil {
		return DBInfo{}, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "VERSION"), []byte(sha), 0o600); err != nil {
		return DBInfo{}, err
	}
	old := dir + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return DBInfo{}, err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.Rename(old, dir)
		return DBInfo{}, err
	}
	_ = os.RemoveAll(old)
	return DBInfo{Source: "rustsec", Status: "updated", Detail: sha}, nil
}

func rustSecState(dir string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return "", false
	}
	sha := strings.TrimSpace(string(data))
	if len(sha) < 7 {
		return "", false
	}
	if _, err := os.Stat(filepath.Join(dir, "crates")); err != nil {
		return "", false
	}
	return sha, true
}

func latestRustSecCommit(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/rustsec/advisory-db/commits/main", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "cgc-scan")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolver commit de RustSec: HTTP %d", resp.StatusCode)
	}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.SHA) < 7 {
		return "", errors.New("commit de RustSec inválido")
	}
	return out.SHA, nil
}

// extractTarGz extrae un tar.gz rechazando rutas absolutas, `..` y enlaces.
func extractTarGz(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := path.Clean(hdr.Name)
		if path.IsAbs(hdr.Name) || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("archivo con ruta insegura: %q", hdr.Name)
		}
		// El tar de GitHub tiene un directorio raíz; se descarta.
		parts := strings.SplitN(clean, "/", 2)
		if len(parts) < 2 {
			continue
		}
		rel := parts[1]
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("archivo contiene un enlace no permitido: %q", hdr.Name)
		}
	}
	return nil
}
