package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
)

// catalogOverwriteFor firma el catálogo embebido con la versión pedida y
// escribe el sobre a un archivo local, registrando la pública en el anillo
// de la configuración del app de pruebas.
func catalogOverwriteFor(t *testing.T, app *App, version, keyID string) string {
	t.Helper()
	cat, err := audit.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cat.SchemaVersion = version
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := audit.SignCatalog(cat, keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	ring := filepath.Join(app.Paths.ConfigDir, "catalog-keys")
	if err := os.MkdirAll(ring, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ring, keyID+".pub"), []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "catalogo-firmado.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuditCatalogStatusWithoutActivation(t *testing.T) {
	app, _, _ := newTestApp(t)
	code, out, errOut := auditRun(t, app, "audit", "catalog", "status")
	if code != 0 || !strings.Contains(out, "ninguno") {
		t.Fatalf("status = %d: %s %s", code, out, errOut)
	}
}

func TestAuditCatalogActivateVerifiesAndActivates(t *testing.T) {
	app, _, _ := newTestApp(t)
	overwrite := catalogOverwriteFor(t, app, "audit-catalog-1.2.0", "cli-key")
	code, out, errOut := auditRun(t, app, "audit", "catalog", "activate", "--file", overwrite)
	if code != 0 {
		t.Fatalf("activate = %d: %s %s", code, out, errOut)
	}
	code, out, _ = auditRun(t, app, "audit", "catalog", "status")
	if code != 0 || !strings.Contains(out, "audit-catalog-1.2.0") {
		t.Fatalf("status tras activar = %d: %s", code, out)
	}
}

func TestAuditCatalogActivateRejectsAndPreserves(t *testing.T) {
	app, _, _ := newTestApp(t)
	// Activación válida inicial.
	good := catalogOverwriteFor(t, app, "audit-catalog-1.2.0", "cli-key")
	if code, out, errOut := auditRun(t, app, "audit", "catalog", "activate", "--file", good); code != 0 {
		t.Fatalf("activate válido = %d: %s %s", code, out, errOut)
	}

	// Sobre firmado con una clave fuera del anillo: rechazo explícito y el
	// catálogo activo se conserva.
	cat, err := audit.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := audit.SignCatalog(cat, "otra-clave", priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "otra-clave.json")
	if err := os.WriteFile(bad, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := auditRun(t, app, "audit", "catalog", "activate", "--file", bad)
	if code != 3 || !strings.Contains(errOut, "no es de confianza") {
		t.Fatalf("activate ajena = %d: %s; se esperaba rechazo explícito", code, errOut)
	}
	code, out, _ := auditRun(t, app, "audit", "catalog", "status")
	if code != 0 || !strings.Contains(out, "audit-catalog-1.2.0") {
		t.Fatalf("el catálogo activo debió conservarse: %d %s", code, out)
	}
}

func TestAuditCatalogActivateRejectsIncompatible(t *testing.T) {
	app, _, _ := newTestApp(t)
	overwrite := catalogOverwriteFor(t, app, "audit-catalog-9.9.9", "cli-key")
	code, _, errOut := auditRun(t, app, "audit", "catalog", "activate", "--file", overwrite)
	if code != 3 || !strings.Contains(errOut, "incompatible") {
		t.Fatalf("activate incompatible = %d: %s; se esperaba rechazo", code, errOut)
	}
}
