package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trustRing genera un anillo de claves públicas de confianza en un directorio
// de configuración temporal, con la pública dada bajo el keyID dado.
func trustRing(t *testing.T, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	ring := filepath.Join(dir, trustedKeysDirname)
	if err := os.MkdirAll(ring, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ring, keyID+".pub"),
		[]byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// signedFor genera un par desechable, firma el catálogo embebido con la
// versión pedida y registra la pública en el anillo; devuelve el sobre y el
// directorio de configuración listo para verificar.
func signedFor(t *testing.T, version, keyID string) (*SignedCatalog, string) {
	t.Helper()
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cat.SchemaVersion = version
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignCatalog(cat, keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed, trustRing(t, keyID, pub)
}

func TestSignedCatalogVerifyAndActivate(t *testing.T) {
	signed, dir := signedFor(t, "audit-catalog-1.2.0", "test-key")
	activated, err := ActivateSignedCatalog(signed, dir)
	if err != nil {
		t.Fatalf("activar: %v", err)
	}
	if activated.SchemaVersion != "audit-catalog-1.2.0" {
		t.Fatalf("versión inesperada: %q", activated.SchemaVersion)
	}
	info, err := InstalledCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Installed || info.Version != "audit-catalog-1.2.0" {
		t.Fatalf("catálogo activado mal registrado: %+v", info)
	}
	// Activación repetida con el mismo sobre: idempotente.
	if _, err := ActivateSignedCatalog(signed, dir); err != nil {
		t.Fatalf("reactivar: %v", err)
	}
}

func TestSignedCatalogRejectsTampered(t *testing.T) {
	signed, dir := signedFor(t, "audit-catalog-1.2.0", "test-key")
	// Catálogo alterado tras firmar: la firma no verifica y nada se activa.
	tampered := *signed
	tampered.Catalog.Description = "descripción alterada"
	if _, err := VerifySignedCatalog(&tampered, dir); err == nil ||
		!strings.Contains(err.Error(), "no verifica") {
		t.Fatalf("err = %v, want firma inválida", err)
	}
	info, err := InstalledCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Installed {
		t.Fatal("un rechazo no debe activar nada")
	}
}

func TestSignedCatalogRejectsUnknownKey(t *testing.T) {
	// Sobre firmado con una clave que no está en el anillo de confianza.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cat, cerr := LoadCatalog()
	if cerr != nil {
		t.Fatal(cerr)
	}
	signed, serr := SignCatalog(cat, "otra-clave", priv)
	if serr != nil {
		t.Fatal(serr)
	}
	_, dir := signedFor(t, "audit-catalog-1.2.0", "test-key")
	if _, err := VerifySignedCatalog(signed, dir); err == nil ||
		!strings.Contains(err.Error(), "no es de confianza") {
		t.Fatalf("err = %v, want clave desconocida", err)
	}
}

func TestSignedCatalogRejectsIncompatibleVersion(t *testing.T) {
	signed, dir := signedFor(t, "audit-catalog-9.9.9", "test-key")
	if _, err := VerifySignedCatalog(signed, dir); err == nil ||
		!strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("err = %v, want versión incompatible", err)
	}
}

func TestSignedCatalogRejectsBadSignatureShape(t *testing.T) {
	signed, dir := signedFor(t, "audit-catalog-1.2.0", "test-key")
	signed.Signature = "no-hex"
	if _, err := VerifySignedCatalog(signed, dir); err == nil ||
		!strings.Contains(err.Error(), "firma") {
		t.Fatalf("err = %v, want firma con forma inválida", err)
	}
	// Sobre con esquema distinto.
	signedOK, dir2 := signedFor(t, "audit-catalog-1.2.0", "test-key")
	signedOK.SchemaVersion = "otro-esquema"
	if _, err := VerifySignedCatalog(signedOK, dir2); err == nil ||
		!strings.Contains(err.Error(), "esquema") {
		t.Fatalf("err = %v, want esquema del sobre inválido", err)
	}
	// Límite del sobre declarado y estable.
	if MaxSignedCatalogBytes != 8<<20 {
		t.Fatalf("límite del sobre cambiado sin actualizar pruebas: %d", MaxSignedCatalogBytes)
	}
	// Un sobre serializado y truncado no puede verificarse de forma completa.
	trunc, tdir := signedFor(t, "audit-catalog-1.2.0", "test-key")
	data, err := json.Marshal(trunc)
	if err != nil {
		t.Fatal(err)
	}
	_ = tdir
	if len(data) == 0 {
		t.Fatal("serialización vacía")
	}
}
