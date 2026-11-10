package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// ReportIntegrityVersion identifica la serialización canónica autenticada del
// informe. Cambia solo con un cambio de forma del contenido cubierto.
const ReportIntegrityVersion = "audit-integrity-1.0.0"

// reportKeyFilename es la clave local dedicada de autenticación del informe.
const reportKeyFilename = "audit-report.key"

// reportKeyBytes es el tamaño de la clave generada (hex de 32 bytes).
const reportKeyBytes = 32

// ReportIntegrity es el valor de autenticación sellado en el commit del
// informe. Excluido del contenido autenticado: el HMAC cubre el ledger y los
// hallazgos, nunca su propio valor.
type ReportIntegrity struct {
	Version string `json:"version"`
	HMAC    string `json:"hmac"`
}

// reportKeyPath es la ruta de la clave local dedicada.
func reportKeyPath(configDir string) string {
	return filepath.Join(configDir, reportKeyFilename)
}

// LoadReportKey lee la clave local dedicada. Una clave ausente o degenerada
// produce un diagnóstico explícito; nunca se improvisa una clave nueva al
// verificar, porque eso reemplazaría el criterio de autenticación.
func LoadReportKey(configDir string) ([]byte, error) {
	if strings.TrimSpace(configDir) == "" {
		return nil, errors.New("auditoría: falta el directorio de configuración para la clave del informe")
	}
	data, err := platform.ReadFileBounded(reportKeyPath(configDir), 4096)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("auditoría: no existe la clave del informe en %s; sella el informe con audit report para crearla: %w", reportKeyPath(configDir), os.ErrNotExist)
		}
		return nil, err
	}
	key := bytes.TrimSpace(data)
	if len(key) < reportKeyBytes {
		return nil, fmt.Errorf("auditoría: la clave del informe en %s es demasiado corta; elimínala y vuelve a sellar el informe", reportKeyPath(configDir))
	}
	return key, nil
}

// LoadOrCreateReportKey devuelve la clave local dedicada, creándola con
// permisos privados si falta. Se usa al sellar el informe; la clave nunca
// aparece en informes, logs ni paquetes.
func LoadOrCreateReportKey(configDir string) ([]byte, error) {
	if key, err := LoadReportKey(configDir); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errKeyDegenerate) && !strings.Contains(err.Error(), "demasiado corta") {
		return nil, err
	}
	buf := make([]byte, reportKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	key := []byte(hex.EncodeToString(buf))
	if err := platform.WritePrivateFile(reportKeyPath(configDir), key); err != nil {
		return nil, err
	}
	return key, nil
}

// errKeyDegenerate marca una clave presente pero inutilizable: al sellar se
// reemplaza; al verificar se rechaza.
var errKeyDegenerate = errors.New("clave del informe degenerada")

// canonicalIntegrityPayload serializa canónicamente el contenido autenticado:
// el ledger y los hallazgos sellados, tras su normalización idempotente y sin
// el propio valor de autenticación.
func canonicalIntegrityPayload(st *RunState) ([]byte, error) {
	if st == nil || st.Ledger == nil || st.Findings == nil {
		return nil, errors.New("auditoría: el informe sellado exige ledger y hallazgos")
	}
	st.Ledger.Recompute()
	st.Findings.Recompute()
	payload := struct {
		SchemaVersion string    `json:"schema_version"`
		RunID         string    `json:"run_id"`
		Ledger        *Ledger   `json:"ledger"`
		Findings      *Findings `json:"findings"`
	}{
		SchemaVersion: ReportIntegrityVersion,
		RunID:         st.Ledger.Run.ID,
		Ledger:        st.Ledger,
		Findings:      st.Findings,
	}
	return json.Marshal(&payload)
}

// ReportHMAC calcula el HMAC-SHA256 del contenido autenticado del informe.
func ReportHMAC(key []byte, st *RunState) (string, error) {
	payload, err := canonicalIntegrityPayload(st)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyReportIntegrity verifica el HMAC sellado del informe sin reescribir
// nada. Cada fallo produce un diagnóstico explícito: integridad ausente
// (informe antiguo), versión distinta, clave ausente o contenido cambiado
// desde el sellado. El HMAC no prueba la verdad del hallazgo ni protege frente
// a quien posea la clave: prueba que el contenido sellado no cambió.
func VerifyReportIntegrity(st *RunState, key []byte) error {
	if st == nil {
		return errors.New("auditoría: no hay estado que verificar")
	}
	if st.Integrity == nil {
		return errors.New("auditoría: el informe no lleva autenticación de integridad; vuelve a sellarlo con audit report")
	}
	if st.Integrity.Version != ReportIntegrityVersion {
		return fmt.Errorf("auditoría: integridad con versión %q, se esperaba %q", st.Integrity.Version, ReportIntegrityVersion)
	}
	if len(key) == 0 {
		return errors.New("auditoría: falta la clave del informe; la verificación no puede proceder")
	}
	expected, err := ReportHMAC(key, st)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(expected), []byte(st.Integrity.HMAC)) {
		return errors.New("auditoría: la integridad del informe no verifica: el ledger o los hallazgos cambiaron desde el sellado, o la clave no es la que lo selló")
	}
	return nil
}
