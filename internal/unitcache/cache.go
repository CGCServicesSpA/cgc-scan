// Package unitcache implementa la caché incremental por unidad y motor.
// La clave combina versión del motor, base, configuración efectiva y el hash
// de los manifiestos/lockfiles o del árbol fuente según el tipo de motor.
package unitcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// Schema es la versión del archivo de caché.
const Schema = 1

// Entry es un resultado cacheado.
type Entry struct {
	Schema   int                 `json:"schema"`
	Key      string              `json:"cache_key"`
	Engine   string              `json:"engine"`
	Unit     string              `json:"unit"`
	Status   string              `json:"status"`
	Reason   string              `json:"reason,omitempty"`
	At       time.Time           `json:"saved_at"`
	Findings []normalize.Finding `json:"findings"`
}

// Store guarda resultados bajo la caché del proyecto.
type Store struct {
	dir string
}

// Open resuelve el directorio de caché del proyecto.
func Open(paths platform.Paths, root string) (*Store, error) {
	ps, err := projectstate.Open(paths, root)
	if err != nil {
		return nil, err
	}
	return &Store{dir: filepath.Join(ps.Dir(), "cache")}, nil
}

// Dir es la raíz de la caché del proyecto.
func (s *Store) Dir() string { return s.dir }

// Lookup devuelve un resultado si la clave coincide.
func (s *Store) Lookup(req orchestrator.CacheRequest) (orchestrator.CachedUnit, bool) {
	key := s.Key(req)
	path := s.entryPath(req)
	data, err := platform.ReadFileBounded(path, 64<<20)
	if err != nil {
		return orchestrator.CachedUnit{}, false
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil || e.Schema != Schema || e.Key != key {
		return orchestrator.CachedUnit{}, false
	}
	return orchestrator.CachedUnit{Status: e.Status, Reason: e.Reason, Findings: e.Findings}, true
}

// Save persiste un resultado con su clave.
func (s *Store) Save(req orchestrator.CacheRequest, res orchestrator.CachedUnit) error {
	if req.EngineID == "" || req.UnitID == "" {
		return errors.New("unitcache: motor y unidad son obligatorios")
	}
	if res.Findings == nil {
		res.Findings = []normalize.Finding{}
	}
	e := Entry{
		Schema: Schema, Key: s.Key(req), Engine: req.EngineID, Unit: req.UnitID,
		Status: res.Status, Reason: res.Reason, At: time.Now().UTC(), Findings: res.Findings,
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := platform.WritePrivateFile(s.entryPath(req), data); err != nil {
		return fmt.Errorf("guardar caché de unidad: %w", err)
	}
	return nil
}

// Key calcula la clave estable de un resultado.
func (s *Store) Key(req orchestrator.CacheRequest) string {
	h := sha256.New()
	writeField(h, "schema", fmt.Sprint(Schema))
	writeField(h, "report_schema", version.SchemaVersion)
	writeField(h, "cli_version", version.Version)
	writeField(h, "engine", req.EngineID)
	writeField(h, "version", req.EngineVersion)
	writeField(h, "mode", req.Mode)
	writeField(h, "db", req.DBKey)
	writeField(h, "root", filepath.Clean(req.Root))
	writeField(h, "unit", req.UnitID)
	writeField(h, "unit_path", filepath.ToSlash(req.UnitPath))
	for i := range req.Invocations {
		inv := req.Invocations[i]
		writeField(h, "inv_entrypoint", inv.Entrypoint)
		writeField(h, "inv_dir", relDir(req.Root, inv.Dir))
		writeField(h, "inv_image", inv.Image)
		writeField(h, "inv_network", fmt.Sprint(inv.AllowNetwork))
		for _, m := range inv.Mounts {
			// El origen es un directorio temporal por ejecución; su contenido
			// relevante (la base) ya entra por DBKey.
			writeField(h, "inv_mount", m.Target+"|"+fmt.Sprint(m.ReadOnly))
		}
		envKeys := make([]string, 0, len(inv.Env))
		for k := range inv.Env {
			envKeys = append(envKeys, k)
		}
		sort.Strings(envKeys)
		for _, k := range envKeys {
			writeField(h, "inv_env", k+"="+inv.Env[k])
		}
		for _, a := range inv.Args {
			writeField(h, "arg", a)
		}
	}
	deps, source, err := s.hashes(req)
	if err != nil {
		// Un fallo de lectura invalida la clave (nunca reutiliza a ciegas).
		writeField(h, "hash_error", err.Error())
		return hex.EncodeToString(h.Sum(nil))[:32]
	}
	switch req.Mode {
	case "deps":
		writeField(h, "deps", deps)
	case "source":
		writeField(h, "source", source)
	case "full":
		writeField(h, "source", source)
	default:
		writeField(h, "deps", deps)
		writeField(h, "source", source)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (s *Store) entryPath(req orchestrator.CacheRequest) string {
	return filepath.Join(s.dir, "units", sanitize(req.UnitID)+"."+sanitize(req.EngineID)+".json")
}

func relDir(root, dir string) string {
	if dir == "" {
		return "."
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return filepath.ToSlash(dir)
	}
	return filepath.ToSlash(rel)
}

func writeField(h interface{ Write([]byte) (int, error) }, name, value string) {
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))
	_, _ = h.Write([]byte{0})
}

// hashes devuelve el hash de manifiestos/lockfiles y el del árbol fuente.
func (s *Store) hashes(req orchestrator.CacheRequest) (deps, source string, err error) {
	base := filepath.Join(req.Root, req.UnitPath)
	deps, err = hashFiles(base, manifestFiles)
	if err != nil {
		return "", "", err
	}
	source, err = hashTree(base)
	if err != nil {
		return "", "", err
	}
	return deps, source, nil
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"target": true, "dist": true, "build": true, ".next": true, "coverage": true,
}

var manifestNames = map[string]bool{
	"go.mod": true, "go.sum": true, "go.work": true, "go.work.sum": true,
	"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"yarn.lock": true, "pnpm-lock.yaml": true,
	"Cargo.toml": true, "Cargo.lock": true,
	"composer.json": true, "composer.lock": true,
	"requirements.txt": true, "Pipfile": true, "Pipfile.lock": true,
	"poetry.lock": true, "pyproject.toml": true, "setup.py": true, "setup.cfg": true,
	"Gemfile.lock": true, "pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
}

func manifestFiles(path string) bool {
	return manifestNames[filepath.Base(path)]
}

// hashTree hashea contenido y rutas del árbol fuente, omitiendo directorios
// intrínsecos. Los archivos enormes se hashean por tamaño y fecha para no
// convertir la caché en un recorrido prohibitivo.
func hashTree(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if path == root {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if manifestFiles(path) {
			// El hash de dependencias cubre estos archivos; incluirlos también
			// aquí no cambia la corrección.
		}
		return hashOne(h, root, path, d)
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

func hashFiles(root string, accept func(string) bool) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if !accept(path) {
			return nil
		}
		return hashOne(h, root, path, d)
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

func hashOne(h interface{ Write([]byte) (int, error) }, root, path string, d fs.DirEntry) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	writeField(h, "path", filepath.ToSlash(rel))
	info, err := d.Info()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		writeField(h, "link", target)
		return nil
	}
	if info.Size() > 8<<20 {
		writeField(h, "size", fmt.Sprint(info.Size()))
		writeField(h, "mtime", info.ModTime().UTC().Format(time.RFC3339Nano))
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	writeField(h, "sha", platform.HashBytes(data))
	return nil
}

func sanitize(s string) string {
	s = strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(s)
	s = strings.Trim(s, ".")
	if s == "" {
		return "_"
	}
	return s
}
