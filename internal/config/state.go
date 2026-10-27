package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// StateSchema es la versión del formato de estado.
const StateSchema = 1

// State es el contenido de state.json. Solo lo escribe la CLI.
type State struct {
	Schema          int           `json:"schema"`
	TrivyModeOrigin string        `json:"trivy_mode_origin,omitempty"`
	Installs        []Install     `json:"installs"`
	ProfileEdits    []ProfileEdit `json:"profile_edits"`
	DockerVolume    string        `json:"docker_volume,omitempty"`
}

// Install registra un motor instalado.
type Install struct {
	Engine      string    `json:"engine"`
	Version     string    `json:"version"`
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256,omitempty"`
	InstalledAt time.Time `json:"installed_at"`
}

// ProfileEdit registra una edición del perfil de shell.
type ProfileEdit struct {
	File       string    `json:"file"`
	Marker     string    `json:"marker"`
	BackupPath string    `json:"backup_path,omitempty"`
	AppliedAt  time.Time `json:"applied_at"`
}

// LoadState lee state.json; si no existe devuelve un estado vacío válido.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{Schema: StateSchema, Installs: []Install{}, ProfileEdits: []ProfileEdit{}}, nil
		}
		return nil, fmt.Errorf("leer estado: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("estado inválido: %w", err)
	}
	if st.Schema != StateSchema {
		return nil, fmt.Errorf("estado con esquema %d, se esperaba %d", st.Schema, StateSchema)
	}
	if st.Installs == nil {
		st.Installs = []Install{}
	}
	if st.ProfileEdits == nil {
		st.ProfileEdits = []ProfileEdit{}
	}
	return &st, nil
}

// SaveState escribe state.json con permisos 0600 y escritura atómica.
func SaveState(path string, st *State) error {
	if st == nil {
		return errors.New("estado nulo")
	}
	st.Schema = StateSchema
	if st.Installs == nil {
		st.Installs = []Install{}
	}
	if st.ProfileEdits == nil {
		st.ProfileEdits = []ProfileEdit{}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := platform.WritePrivateFile(path, data); err != nil {
		return fmt.Errorf("guardar estado: %w", err)
	}
	return nil
}

// RecordInstall agrega o reemplaza el registro de un motor.
func (s *State) RecordInstall(in Install) {
	if in.InstalledAt.IsZero() {
		in.InstalledAt = time.Now().UTC()
	}
	for i := range s.Installs {
		if s.Installs[i].Engine == in.Engine && s.Installs[i].Version == in.Version {
			s.Installs[i] = in
			return
		}
	}
	s.Installs = append(s.Installs, in)
}

// RecordProfileEdit agrega o reemplaza la edición de un perfil.
func (s *State) RecordProfileEdit(edit ProfileEdit) {
	if edit.AppliedAt.IsZero() {
		edit.AppliedAt = time.Now().UTC()
	}
	for i := range s.ProfileEdits {
		if s.ProfileEdits[i].File == edit.File && s.ProfileEdits[i].Marker == edit.Marker {
			s.ProfileEdits[i] = edit
			return
		}
	}
	s.ProfileEdits = append(s.ProfileEdits, edit)
}
