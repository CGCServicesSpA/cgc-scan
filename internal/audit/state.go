package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// StateSchemaVersion es la versión del contrato del estado autoritativo.
const StateSchemaVersion = "audit-state-1.0.0"

// RunState es el estado autoritativo de una corrida: el ledger y el estado de
// verificación —y, si la corrida ya se selló, el documento de hallazgos— en
// una sola frontera de commit. Se escribe y se lee atómicamente, así que una
// interrupción deja íntegro el estado anterior o el nuevo, nunca un punto
// intermedio. ledger.json, candidates.json y findings.json son vistas
// derivadas informativas que se regeneran desde aquí tras cada commit.
type RunState struct {
	SchemaVersion string      `json:"schema_version"`
	Source        *SourceInfo `json:"source"`
	Ledger        *Ledger     `json:"ledger"`
	Candidates    *Candidates `json:"candidates"`
	Findings      *Findings   `json:"findings,omitempty"`
}

// Normalize completa el estado: versiones, slices, resúmenes derivados y, si
// falta, el modo de fuente derivado del ledger (estados anteriores a la
// declaración explícita).
func (st *RunState) Normalize() {
	if st.SchemaVersion == "" {
		st.SchemaVersion = StateSchemaVersion
	}
	if st.Source == nil && st.Ledger != nil {
		info := DeriveSourceInfo(st.Ledger)
		st.Source = &info
	}
	if st.Ledger != nil {
		st.Ledger.Recompute()
	}
	if st.Candidates != nil {
		st.Candidates.Normalize()
	}
	if st.Findings != nil {
		st.Findings.Recompute()
	}
}

// ValidateRunState valida la coherencia interna de cada documento y entre
// documentos: misma corrida en ledger, candidatos y hallazgos.
func ValidateRunState(st *RunState) error {
	if st == nil {
		return errors.New("contrato inválido: estado nulo")
	}
	var is Issues
	if st.SchemaVersion != StateSchemaVersion {
		is.addf("schema_version %q, se esperaba %q", st.SchemaVersion, StateSchemaVersion)
	}
	if st.Ledger == nil {
		is.addf("el estado exige un ledger")
	}
	if st.Candidates == nil {
		is.addf("el estado exige un estado de verificación")
	}
	if err := is.err(); err != nil {
		return err
	}
	switch st.Source.Mode {
	case SourceModeRevision:
		if strings.TrimSpace(st.Source.Revision) == "" {
			is.addf("el modo revisión exige una revisión declarada")
		}
	case SourceModeWorktree:
	default:
		is.addf("modo de fuente desconocido: %q", st.Source.Mode)
	}
	if err := ValidateLedgerSemantics(st.Ledger); err != nil {
		return fmt.Errorf("auditoría: ledger inválido: %w", err)
	}
	if err := ValidateCandidates(st.Candidates, st.Ledger); err != nil {
		return fmt.Errorf("auditoría: %w", err)
	}
	if st.Findings != nil {
		if err := ValidateFindingsSemantics(st.Findings); err != nil {
			return fmt.Errorf("auditoría: hallazgos inválidos: %w", err)
		}
		if st.Findings.Run.ID != st.Ledger.Run.ID {
			return fmt.Errorf("auditoría: los hallazgos corresponden a la corrida %q y el ledger a %q",
				st.Findings.Run.ID, st.Ledger.Run.ID)
		}
	}
	return nil
}

// DecodeRunState lee y decodifica el estado autoritativo, rechazando campos
// desconocidos y contenido posterior al objeto.
func DecodeRunState(data []byte) (*RunState, error) {
	if err := checkSize(data, MaxRunStateBytes, "el estado de la corrida"); err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, errors.New("el estado de la corrida no es JSON válido")
	}
	if err := checkJSONDepth(data, MaxJSONDepth); err != nil {
		return nil, fmt.Errorf("estado de la corrida inválido: %w", err)
	}
	var st RunState
	if err := decodeStrict(data, &st); err != nil {
		return nil, fmt.Errorf("estado de la corrida inválido: %w", err)
	}
	if st.SchemaVersion != StateSchemaVersion {
		return nil, fmt.Errorf("estado con esquema %q, se esperaba %q", st.SchemaVersion, StateSchemaVersion)
	}
	st.Normalize()
	return &st, nil
}

// StatePath es la ruta del estado autoritativo.
func (s *Store) StatePath() string { return s.ArtifactPath(StateFilename) }

// StateFilename es el nombre del archivo de estado autoritativo.
const StateFilename = "state.json"

// Límites de lectura del store: ledger y estado de verificación 16 MiB,
// hallazgos 32 MiB, estado autoritativo la suma de los tres.
const (
	ledgerReadLimit     = MaxLedgerBytes
	candidatesReadLimit = MaxCandidatesBytes
	findingsReadLimit   = MaxFindingsBytes
)

// LoadState devuelve el estado autoritativo de la corrida. Si el directorio
// solo tiene el formato heredado de dos archivos, lo carga de forma explícita
// como legado; la primera escritura lo migra a state.json. Un legado
// inconsistente se rechaza: nunca se reinterpreta silenciosamente un estado
// antiguo.
func (s *Store) LoadState() (*RunState, error) {
	data, err := platform.ReadFileBounded(s.StatePath(), MaxRunStateBytes)
	switch {
	case err == nil:
		st, err := DecodeRunState(data)
		if err != nil {
			return nil, err
		}
		if err := ValidateRunState(st); err != nil {
			return nil, err
		}
		return st, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("auditoría: leer estado: %w", err)
	}

	// Legado: ledger.json + candidates.json independientes.
	ledger, err := s.LoadLedger()
	if err != nil {
		return nil, err
	}
	candidates, err := s.LoadCandidates(ledger)
	if err != nil {
		return nil, err
	}
	st := &RunState{SchemaVersion: StateSchemaVersion, Ledger: ledger, Candidates: candidates}
	if findings, ferr := s.loadFindingsLegacy(ledger); ferr == nil {
		st.Findings = findings
	} else if !errors.Is(ferr, ErrNoAudit) {
		return nil, ferr
	}
	return st, nil
}

// loadFindingsLegacy lee findings.json del formato heredado y comprueba que
// corresponda a la misma corrida.
func (s *Store) loadFindingsLegacy(ledger *Ledger) (*Findings, error) {
	findings, err := s.LoadFindings()
	if err != nil {
		return nil, err
	}
	if findings.Run.ID != ledger.Run.ID {
		return nil, fmt.Errorf("auditoría: findings.json corresponde a la corrida %q y el ledger a %q",
			findings.Run.ID, ledger.Run.ID)
	}
	return findings, nil
}

// CommitState valida el estado completo y lo escribe en una sola frontera
// atómica. Después regenera las vistas derivadas desde el estado
// autoritativo; si una vista falla, el estado ya quedó íntegro y el error lo
// declara: repetir el commit es seguro y no vuelve a aplicar operación alguna.
func (s *Store) CommitState(st *RunState) error {
	if st == nil {
		return errors.New("auditoría: estado nulo")
	}
	st.Normalize()
	if err := ValidateRunState(st); err != nil {
		return fmt.Errorf("auditoría: el estado no cumple el contrato: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := platform.WritePrivateFile(s.StatePath(), data); err != nil {
		return err
	}
	if err := s.regenerateViews(st); err != nil {
		return fmt.Errorf("auditoría: el estado quedó confirmado pero una vista derivada no se pudo actualizar: %w", err)
	}
	return nil
}

// regenerateViews reescribe las vistas derivadas desde el estado
// autoritativo. findings.json solo se regenera si la corrida está sellada con
// hallazgos; un informe anterior no se borra por una mutación posterior.
func (s *Store) regenerateViews(st *RunState) error {
	if err := s.writeLedgerView(st.Ledger); err != nil {
		return err
	}
	if err := s.writeCandidatesView(st.Candidates); err != nil {
		return err
	}
	if st.Findings != nil {
		if err := s.writeFindingsView(st.Findings); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) writeLedgerView(l *Ledger) error {
	if l == nil {
		return errors.New("auditoría: ledger nulo")
	}
	l.Recompute()
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := ValidateLedger(data); err != nil {
		return fmt.Errorf("auditoría: el ledger no cumple el contrato: %w", err)
	}
	return platform.WritePrivateFile(s.LedgerPath(), data)
}

func (s *Store) writeCandidatesView(c *Candidates) error {
	if c == nil {
		return errors.New("auditoría: candidatos nulos")
	}
	c.Normalize()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return platform.WritePrivateFile(s.CandidatesPath(), data)
}

func (s *Store) writeFindingsView(f *Findings) error {
	if f == nil {
		return errors.New("auditoría: hallazgos nulos")
	}
	f.Recompute()
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := ValidateFindings(data); err != nil {
		return fmt.Errorf("auditoría: los hallazgos no cumplen el contrato: %w", err)
	}
	if err := ValidateFindingsSemantics(f); err != nil {
		return err
	}
	return platform.WritePrivateFile(s.FindingsPath(), data)
}

// Exists informa si hay una corrida: estado autoritativo o formato heredado.
func (s *Store) Exists() bool {
	if info, err := os.Stat(s.StatePath()); err == nil && info.Mode().IsRegular() {
		return true
	}
	info, err := os.Stat(s.LedgerPath())
	return err == nil && info.Mode().IsRegular()
}
