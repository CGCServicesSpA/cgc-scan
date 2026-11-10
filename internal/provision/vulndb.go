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
	"time"
)

var goVulnBase = "https://vuln.go.dev"

var goIDRe = regexp.MustCompile(`^GO-[0-9]{4}-[0-9]{4,}$`)

// goVulnIndexEntry es una entrada del índice de avisos de Go.
type goVulnIndexEntry struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// goVulnSyncState registra la versión de cada aviso descargado.
type goVulnSyncState struct {
	Schema  int               `json:"schema"`
	Updated string            `json:"updated"`
	IDs     map[string]string `json:"ids"`
}

// EnsureGoVulnDB prepara un espejo local de la base de Go. Reutiliza el
// espejo existente sin consultar la red; para actualizarlo usa
// EnsureGoVulnDBWithRefresh o update-db.
func EnsureGoVulnDB(ctx context.Context, client *http.Client, dir string, offline bool) (DBInfo, error) {
	return EnsureGoVulnDBWithRefresh(ctx, client, dir, offline, 0)
}

// EnsureGoVulnDBWithRefresh reutiliza el espejo si es más reciente que
// refresh y, si no, descarga solo los avisos nuevos o modificados.
func EnsureGoVulnDBWithRefresh(ctx context.Context, client *http.Client, dir string, offline bool, refresh time.Duration) (DBInfo, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	if info, ok := goVulnState(dir); ok {
		if offline || (refresh > 0 && time.Since(info.UpdatedAt) < refresh) {
			return info, nil
		}
		return syncGoVulnDB(ctx, client, dir, false)
	}
	if offline {
		return DBInfo{}, ErrDBAbsent
	}
	return syncGoVulnDB(ctx, client, dir, true)
}

// syncGoVulnDB descarga el índice y solo los avisos que cambiaron. Con force
// descarga todos, como en la primera ejecución.
func syncGoVulnDB(ctx context.Context, client *http.Client, dir string, force bool) (DBInfo, error) {
	if err := os.MkdirAll(filepath.Join(dir, "index"), 0o700); err != nil {
		return DBInfo{}, err
	}
	var vulns []goVulnIndexEntry
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
		if err := writeAtomic(filepath.Join(dir, "index", name), body); err != nil {
			return DBInfo{}, err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "ID"), 0o700); err != nil {
		return DBInfo{}, err
	}
	state := goVulnSyncState{Schema: 1, IDs: map[string]string{}}
	if !force {
		state = loadGoVulnState(dir)
	}
	wanted := map[string]bool{}
	downloaded := 0
	for _, v := range vulns {
		if !goIDRe.MatchString(v.ID) {
			continue
		}
		wanted[v.ID] = true
		path := filepath.Join(dir, "ID", v.ID+".json")
		if !force && state.IDs[v.ID] == v.Modified {
			if _, err := os.Stat(path); err == nil {
				continue
			}
		}
		body, err := fetchBytes(ctx, client, goVulnBase+"/ID/"+v.ID+".json", 8<<20)
		if err != nil {
			return DBInfo{}, fmt.Errorf("descargar aviso %s: %w", v.ID, err)
		}
		if err := writeAtomic(path, body); err != nil {
			return DBInfo{}, err
		}
		state.IDs[v.ID] = v.Modified
		downloaded++
	}
	// Retirar avisos que ya no están en el índice.
	entries, _ := os.ReadDir(filepath.Join(dir, "ID"))
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if !wanted[id] {
			_ = os.Remove(filepath.Join(dir, "ID", e.Name()))
			delete(state.IDs, id)
		}
	}
	state.Schema = 1
	state.Updated = time.Now().UTC().Format(time.RFC3339)
	if err := writeGoVulnState(dir, state); err != nil {
		return DBInfo{}, err
	}
	return DBInfo{Source: "go-vulndb", Status: "updated", UpdatedAt: time.Now().UTC(),
		Detail: fmt.Sprintf("%d avisos (%d descargados)", len(wanted), downloaded)}, nil
}

func loadGoVulnState(dir string) goVulnSyncState {
	st := goVulnSyncState{Schema: 1, IDs: map[string]string{}}
	data, err := os.ReadFile(filepath.Join(dir, "index", "state.json"))
	if err != nil {
		return st
	}
	if json.Unmarshal(data, &st) != nil || st.IDs == nil {
		return goVulnSyncState{Schema: 1, IDs: map[string]string{}}
	}
	return st
}

func writeGoVulnState(dir string, st goVulnSyncState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "index", "state.json"), append(data, '\n'))
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
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
