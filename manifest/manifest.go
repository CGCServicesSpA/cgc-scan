// Package manifest carga el manifiesto de confianza embebido: versiones,
// digests y checksums de los motores (ADR-07).
package manifest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

//go:embed trust.json
var trustJSON []byte

// SchemaVersion es la versión del formato del manifiesto.
const SchemaVersion = 1

// Archive es un artefacto descargable de un motor.
type Archive struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Engine describe un motor fijado.
type Engine struct {
	Version  string             `json:"version"`
	Image    string             `json:"image,omitempty"`
	Archives map[string]Archive `json:"archives,omitempty"`
}

// Adapter describe una herramienta de adaptador fijada.
type Adapter struct {
	Version            string             `json:"version"`
	Mode               string             `json:"mode"` // library | npm | phar | binary | venv
	DB                 string             `json:"db,omitempty"`
	URL                string             `json:"url,omitempty"`
	SHA256             string             `json:"sha256,omitempty"`
	LockfileSHA256     string             `json:"lockfile_sha256,omitempty"`
	RequirementsSHA256 string             `json:"requirements_sha256,omitempty"`
	Archives           map[string]Archive `json:"archives,omitempty"`
}

// Manifest es el contenido de manifest/trust.json.
type Manifest struct {
	Schema   int                `json:"schema"`
	Engines  map[string]Engine  `json:"engines"`
	Adapters map[string]Adapter `json:"adapters"`
}

var (
	sha256Re = regexp.MustCompile(`^[a-f0-9]{64}$`)
	semverRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
)

// Load parsea y valida el manifiesto embebido.
func Load() (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(trustJSON))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifiesto de confianza inválido: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate comprueba la forma mínima del manifiesto.
func (m *Manifest) Validate() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("manifiesto: esquema %d, se esperaba %d", m.Schema, SchemaVersion)
	}
	if len(m.Engines) == 0 {
		return fmt.Errorf("manifiesto: no hay motores")
	}
	for id, e := range m.Engines {
		if id == "" {
			return fmt.Errorf("manifiesto: motor sin identificador")
		}
		if !semverRe.MatchString(e.Version) {
			return fmt.Errorf("manifiesto: %s tiene versión inválida %q", id, e.Version)
		}
		for platform, a := range e.Archives {
			if platform == "" {
				return fmt.Errorf("manifiesto: %s tiene un archivo sin plataforma", id)
			}
			if a.URL == "" || a.SHA256 == "" {
				return fmt.Errorf("manifiesto: %s/%s incompleto", id, platform)
			}
			if !sha256Re.MatchString(a.SHA256) {
				return fmt.Errorf("manifiesto: %s/%s tiene sha256 inválido", id, platform)
			}
			if len(a.URL) < 8 || a.URL[:8] != "https://" {
				return fmt.Errorf("manifiesto: %s/%s no usa https", id, platform)
			}
		}
	}
	for id, a := range m.Adapters {
		if id == "" {
			return fmt.Errorf("manifiesto: adaptador sin identificador")
		}
		if !semverRe.MatchString(a.Version) {
			return fmt.Errorf("manifiesto: adaptador %s tiene versión inválida %q", id, a.Version)
		}
		switch a.Mode {
		case "library", "npm", "phar", "binary", "venv":
		default:
			return fmt.Errorf("manifiesto: adaptador %s tiene modo inválido %q", id, a.Mode)
		}
		for name, sum := range map[string]string{
			"sha256": a.SHA256, "lockfile_sha256": a.LockfileSHA256,
			"requirements_sha256": a.RequirementsSHA256,
		} {
			if sum != "" && !sha256Re.MatchString(sum) {
				return fmt.Errorf("manifiesto: adaptador %s tiene %s inválido", id, name)
			}
		}
		if a.URL != "" && (len(a.URL) < 8 || a.URL[:8] != "https://") {
			return fmt.Errorf("manifiesto: adaptador %s no usa https", id)
		}
		if a.Mode == "binary" && len(a.Archives) == 0 {
			return fmt.Errorf("manifiesto: adaptador binario %s sin archivos", id)
		}
		for platform, ar := range a.Archives {
			if platform == "" || ar.URL == "" || !sha256Re.MatchString(ar.SHA256) {
				return fmt.Errorf("manifiesto: adaptador %s/%s incompleto", id, platform)
			}
		}
	}
	if len(m.Adapters) == 0 {
		return fmt.Errorf("manifiesto: no hay adaptadores")
	}
	return nil
}

// Adapter devuelve un adaptador por identificador.
func (m *Manifest) Adapter(id string) (Adapter, error) {
	a, ok := m.Adapters[id]
	if !ok {
		return Adapter{}, fmt.Errorf("el adaptador %q no está en el manifiesto", id)
	}
	return a, nil
}

// Archive devuelve el artefacto de un adaptador binario.
func (a Adapter) Archive(goos, goarch string) (Archive, error) {
	key := PlatformKey(goos, goarch)
	ar, ok := a.Archives[key]
	if !ok {
		return Archive{}, fmt.Errorf("no hay artefacto para %s", key)
	}
	return ar, nil
}

// Engine devuelve un motor por identificador.
func (m *Manifest) Engine(id string) (Engine, error) {
	e, ok := m.Engines[id]
	if !ok {
		return Engine{}, fmt.Errorf("el motor %q no está en el manifiesto", id)
	}
	return e, nil
}

// PlatformKey normaliza GOOS/GOARCH a la clave del manifiesto.
func PlatformKey(goos, goarch string) string {
	return goos + "-" + goarch
}

// Archive devuelve el artefacto de una plataforma.
func (e Engine) Archive(goos, goarch string) (Archive, error) {
	key := PlatformKey(goos, goarch)
	a, ok := e.Archives[key]
	if !ok {
		return Archive{}, fmt.Errorf("no hay artefacto para %s (plataformas: %v)", key, e.Platforms())
	}
	return a, nil
}

// Platforms lista las plataformas disponibles, ordenadas.
func (e Engine) Platforms() []string {
	out := make([]string, 0, len(e.Archives))
	for k := range e.Archives {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PinnedVersions devuelve las versiones fijadas, ordenadas por motor. Se usa
// en --version y en el reporte (RF-12).
func (m *Manifest) PinnedVersions() map[string]string {
	out := make(map[string]string, len(m.Engines)+len(m.Adapters))
	for id, e := range m.Engines {
		out[id] = e.Version
	}
	for id, a := range m.Adapters {
		out[id] = a.Version
	}
	return out
}

// Bytes devuelve el manifiesto embebido tal cual, para verificarlo en CI.
func Bytes() []byte { return trustJSON }
