package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// ErrNoAudit indica que el directorio no contiene una corrida de auditoría.
var ErrNoAudit = errors.New("no hay una auditoría guardada en este directorio; ejecuta cgc-scan audit init")

// ErrNoCandidates indica que hay corrida pero falta el estado de verificación:
// una corrida en ese estado está dañada y no se reinterpreta silenciosamente.
var ErrNoCandidates = errors.New("auditoría: la corrida no tiene estado de verificación; vuelve a crearla con audit init")

// Nombres de archivo de una corrida.
const (
	LedgerFilename     = "ledger.json"
	CandidatesFilename = "candidates.json"
	FindingsFilename   = "findings.json"
)

// Store da acceso al directorio de una corrida de auditoría.
type Store struct {
	dir string
}

// OpenStore resuelve el directorio de la corrida. No lo crea hasta escribir.
func OpenStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("auditoría: falta el directorio de la corrida")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: abs}, nil
}

// Dir es la raíz de la corrida.
func (s *Store) Dir() string { return s.dir }

// LedgerPath es la ruta del ledger.
func (s *Store) LedgerPath() string { return filepath.Join(s.dir, LedgerFilename) }

// CandidatesPath es la ruta del estado de verificación.
func (s *Store) CandidatesPath() string { return filepath.Join(s.dir, CandidatesFilename) }

// FindingsPath es la ruta del documento de hallazgos.
func (s *Store) FindingsPath() string { return filepath.Join(s.dir, FindingsFilename) }

// ArtifactPath devuelve la ruta de un artefacto derivado (REPORT.md, etc.).
func (s *Store) ArtifactPath(name string) string { return filepath.Join(s.dir, name) }

// Exists informa si hay un ledger guardado.
func (s *Store) Exists() bool {
	info, err := os.Stat(s.LedgerPath())
	return err == nil && info.Mode().IsRegular()
}

// SaveLedger escribe el ledger de forma atómica y privada.
func (s *Store) SaveLedger(l *Ledger) error {
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

// LoadLedger lee y valida el ledger.
func (s *Store) LoadLedger() (*Ledger, error) {
	data, err := platform.ReadFileBounded(s.LedgerPath(), 16<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoAudit
		}
		return nil, fmt.Errorf("auditoría: leer ledger: %w", err)
	}
	l, err := DecodeLedger(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		return nil, err
	}
	return l, nil
}

// SaveCandidates valida el estado de verificación contra el ledger y lo
// escribe de forma atómica y privada. Nada se persiste si no cumple el
// contrato.
func (s *Store) SaveCandidates(l *Ledger, c *Candidates) error {
	if l == nil {
		return errors.New("auditoría: el ledger es obligatorio para validar el estado de verificación")
	}
	if c == nil {
		return errors.New("auditoría: candidatos nulos")
	}
	c.Normalize()
	if err := ValidateCandidates(c, l); err != nil {
		return fmt.Errorf("auditoría: el estado de verificación no cumple el contrato: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return platform.WritePrivateFile(s.CandidatesPath(), data)
}

// LoadCandidates lee el estado de verificación y lo valida contra el ledger.
// Una carga fallida no modifica ningún archivo.
func (s *Store) LoadCandidates(l *Ledger) (*Candidates, error) {
	data, err := platform.ReadFileBounded(s.CandidatesPath(), 16<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoCandidates
		}
		return nil, fmt.Errorf("auditoría: leer candidatos: %w", err)
	}
	c, err := DecodeCandidates(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateCandidates(c, l); err != nil {
		return nil, err
	}
	return c, nil
}

// SaveFindings valida y escribe el documento de hallazgos.
func (s *Store) SaveFindings(f *Findings) error {
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

// LoadFindings lee y valida el documento de hallazgos.
func (s *Store) LoadFindings() (*Findings, error) {
	data, err := platform.ReadFileBounded(s.FindingsPath(), 32<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoAudit
		}
		return nil, fmt.Errorf("auditoría: leer hallazgos: %w", err)
	}
	f, err := DecodeFindings(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateFindingsSemantics(f); err != nil {
		return nil, err
	}
	return f, nil
}

// WriteArtifact escribe un artefacto derivado con permisos privados.
func (s *Store) WriteArtifact(name string, data []byte) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("auditoría: nombre de artefacto vacío")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("auditoría: nombre de artefacto inválido: %q", name)
	}
	return platform.WritePrivateFile(s.ArtifactPath(name), data)
}
