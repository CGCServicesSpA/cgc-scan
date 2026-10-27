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

// Manifest es el contenido de manifest/trust.json.
type Manifest struct {
	Schema  int               `json:"schema"`
	Engines map[string]Engine `json:"engines"`
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
	return nil
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
	out := make(map[string]string, len(m.Engines))
	for id, e := range m.Engines {
		out[id] = e.Version
	}
	return out
}

// Bytes devuelve el manifiesto embebido tal cual, para verificarlo en CI.
func Bytes() []byte { return trustJSON }
