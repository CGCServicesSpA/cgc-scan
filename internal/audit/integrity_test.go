package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportIntegrityRoundTrip(t *testing.T) {
	st := sealedState(t)
	key := []byte(strings.Repeat("k", 32))
	mac, err := ReportHMAC(key, st)
	if err != nil {
		t.Fatalf("hmac: %v", err)
	}
	st.Integrity = &ReportIntegrity{Version: ReportIntegrityVersion, HMAC: mac}
	if err := VerifyReportIntegrity(st, key); err != nil {
		t.Fatalf("la verificación debe pasar sin cambios: %v", err)
	}

	// Modificar el ledger invalida la verificación.
	tampered := *st
	unit := *tampered.Ledger.UnitByID(tampered.Ledger.Units[0].CoverageID)
	unit.State = StateBlocked
	tampered.Ledger.Units[0] = unit
	if err := VerifyReportIntegrity(&tampered, key); err == nil ||
		!strings.Contains(err.Error(), "no verifica") {
		t.Fatalf("err = %v, want verificación fallida", err)
	}

	// Modificar los registros invalida la verificación.
	tampered2 := *st
	record := tampered2.Findings.Findings[0]
	record.Title = "título alterado"
	tampered2.Findings.Findings[0] = record
	if err := VerifyReportIntegrity(&tampered2, key); err == nil {
		t.Fatalf("modificar registros debe invalidar la verificación")
	}
}

func TestReportIntegrityDiagnostics(t *testing.T) {
	st := sealedState(t)
	key := []byte(strings.Repeat("k", 32))

	// Informe antiguo sin integridad.
	if err := VerifyReportIntegrity(st, key); err == nil || !strings.Contains(err.Error(), "autenticación de integridad") {
		t.Fatalf("err = %v, want informe sin integridad", err)
	}

	// Clave ausente (con informe sellado): la verificación no procede.
	mac, err := ReportHMAC(key, st)
	if err != nil {
		t.Fatal(err)
	}
	sealedSt := *st
	sealedSt.Integrity = &ReportIntegrity{Version: ReportIntegrityVersion, HMAC: mac}
	if err := VerifyReportIntegrity(&sealedSt, nil); err == nil || !strings.Contains(err.Error(), "falta la clave") {
		t.Fatalf("err = %v, want clave ausente", err)
	}

	// Clave incorrecta o reemplazada.
	st.Integrity = &ReportIntegrity{Version: ReportIntegrityVersion, HMAC: mac}
	other := []byte(strings.Repeat("x", 32))
	if err := VerifyReportIntegrity(st, other); err == nil || !strings.Contains(err.Error(), "no verifica") {
		t.Fatalf("err = %v, want verificación fallida con otra clave", err)
	}
}

func TestLoadReportKeyDiagnostics(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadReportKey(dir); err == nil || !strings.Contains(err.Error(), "no existe la clave") {
		t.Fatalf("err = %v, want clave ausente explícita", err)
	}
	if _, err := LoadOrCreateReportKey(dir); err != nil {
		t.Fatalf("crear clave: %v", err)
	}
	if _, err := LoadReportKey(dir); err != nil {
		t.Fatalf("la clave creada debe cargar: %v", err)
	}
	// La clave se crea con permisos privados.
	info, err := os.Stat(filepath.Join(dir, "audit-report.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o, want 600", info.Mode().Perm())
	}
}

func TestReportKeyNeverLeaksIntoArtifacts(t *testing.T) {
	dir := t.TempDir()
	st := sealedState(t)
	key, err := LoadOrCreateReportKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := ReportHMAC(key, st)
	if err != nil {
		t.Fatal(err)
	}
	st.Integrity = &ReportIntegrity{Version: ReportIntegrityVersion, HMAC: mac}
	stateJSON, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateJSON), string(key)) {
		t.Fatal("la clave no puede aparecer en el estado persistido")
	}
	if strings.Contains(string(stateJSON), "audit-report.key") {
		t.Fatal("la ruta de la clave no puede aparecer en el estado")
	}
}

func TestCanonicalIntegrityIsStable(t *testing.T) {
	st := sealedState(t)
	first, err := canonicalIntegrityPayload(st)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalIntegrityPayload(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("la serialización canónica no es estable")
	}
	// Recargar el estado desde JSON produce el mismo payload autenticado.
	st.SchemaVersion = StateSchemaVersion
	stateJSON, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := DecodeRunState(stateJSON)
	if err != nil {
		t.Fatal(err)
	}
	third, err := canonicalIntegrityPayload(reloaded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatal("recargar el estado cambió el contenido autenticado")
	}
}
