package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// Catálogo firmado y actualización local (P2-5d/P2-5e).
//
// Confianza: el catálogo embebido es la raíz de confianza y no se reemplaza;
// el catálogo activable desde archivo solo se activa si una clave pública de
// confianza verificó su firma y su versión es compatible. Las claves públicas
// de confianza viven separadas de la clave privada de firma: ninguna clave
// privada viaja en el repositorio, los informes ni el paquete, y las pruebas
// usan claves desechables.

// CatalogTrustVersion identifica el formato del catálogo firmado.
const CatalogTrustVersion = "audit-catalog-signed-1.0.0"

// limits del formato.
const (
	// MaxSignedCatalogBytes limita el catálogo firmado leído de archivo.
	MaxSignedCatalogBytes = 8 << 20
	// trustedKeysFilename es el directorio de claves públicas de confianza,
	// bajo el directorio de configuración.
	trustedKeysDirname = "catalog-keys"
)

// SignedCatalog es el sobre del catálogo firmado: el catálogo y su firma
// ed25519 sobre los bytes canónicos de ese catálogo.
type SignedCatalog struct {
	SchemaVersion string `json:"schema_version"`
	// Catalog es el catálogo completo; su forma serializada canónica es el
	// contenido autenticado.
	Catalog *Catalog `json:"catalog"`
	// KeyID identifica la clave pública que debe verificar la firma.
	KeyID string `json:"key_id"`
	// Algorithm declara el algoritmo de firma; solo ed25519 en esta versión.
	Algorithm string `json:"algorithm"`
	// Signature es la firma ed25519 (hex) del contenido canónico.
	Signature string `json:"signature"`
}

// ErrUnknownKey indica que la clave que firmó el catálogo no es de confianza.
var ErrUnknownKey = errors.New("auditoría: la clave del catálogo firmado no es de confianza")

// ErrIncompatibleCatalog indica una versión de catálogo no aceptada por esta
// versión del motor.
var ErrIncompatibleCatalog = errors.New("auditoría: versión del catálogo incompatible")

// canonicalCatalogPayload serializa canónicamente el contenido autenticado:
// el catálogo re-serializado desde su forma decodificada, de modo que los
// espacios y el orden de claves del archivo original no participan.
func canonicalCatalogPayload(cat *Catalog) ([]byte, error) {
	if cat == nil {
		return nil, errors.New("auditoría: catálogo nulo")
	}
	return json.Marshal(cat)
}

// SignCatalog firma un catálogo con una clave privada ed25519 desechable o de
// distribución. Solo para herramientas de actualización y pruebas: el motor
// nunca firma.
func SignCatalog(cat *Catalog, keyID string, private ed25519.PrivateKey) (*SignedCatalog, error) {
	payload, err := canonicalCatalogPayload(cat)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(private, payload)
	return &SignedCatalog{
		SchemaVersion: CatalogTrustVersion,
		Catalog:       cat,
		KeyID:         keyID,
		Algorithm:     "ed25519",
		Signature:     hex.EncodeToString(sig),
	}, nil
}

// trustedKeyPath es la ruta de una clave pública de confianza.
func trustedKeyPath(configDir, keyID string) string {
	return filepath.Join(configDir, trustedKeysDirname, keyID+".pub")
}

// VerifySignedCatalog verifica la firma del sobre contra la clave pública de
// confianza declarada y la compatibilidad de versión. Un fallo conserva el
// catálogo activo: nada se activa.
func VerifySignedCatalog(signed *SignedCatalog, configDir string) (*Catalog, error) {
	if signed == nil {
		return nil, errors.New("auditoría: sobre del catálogo nulo")
	}
	if signed.SchemaVersion != CatalogTrustVersion {
		return nil, fmt.Errorf("auditoría: sobre con esquema %q, se esperaba %q", signed.SchemaVersion, CatalogTrustVersion)
	}
	if signed.Algorithm != "ed25519" {
		return nil, fmt.Errorf("auditoría: algoritmo de firma no soportado: %q", signed.Algorithm)
	}
	if strings.TrimSpace(signed.KeyID) == "" {
		return nil, errors.New("auditoría: el sobre no declara key_id")
	}
	// Compatibilidad antes del contrato completo: una versión de catálogo no
	// aceptada por esta versión del motor se rechaza con el diagnóstico de
	// incompatibilidad, aunque el contenido tampoco cumpla el contrato.
	switch signed.Catalog.SchemaVersion {
	case "audit-catalog-1.1.0", "audit-catalog-1.2.0":
	default:
		return nil, fmt.Errorf("%w: %q", ErrIncompatibleCatalog, signed.Catalog.SchemaVersion)
	}
	if err := signed.Catalog.Validate(); err != nil {
		return nil, fmt.Errorf("auditoría: el catálogo firmado no cumple el contrato: %w", err)
	}
	pub, err := platform.ReadFileBounded(trustedKeyPath(configDir, signed.KeyID), 4096)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q no está en el anillo de confianza", ErrUnknownKey, signed.KeyID)
		}
		return nil, err
	}
	keyBytes, derr := hex.DecodeString(strings.TrimSpace(string(pub)))
	if derr != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auditoría: la clave pública %q es inválida", signed.KeyID)
	}
	sig, serr := hex.DecodeString(signed.Signature)
	if serr != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("auditoría: la firma del catálogo es inválida")
	}
	payload, perr := canonicalCatalogPayload(signed.Catalog)
	if perr != nil {
		return nil, perr
	}
	if !ed25519.Verify(ed25519.PublicKey(keyBytes), payload, sig) {
		return nil, errors.New("auditoría: la firma del catálogo no verifica")
	}
	return signed.Catalog, nil
}

// ActivateSignedCatalog activa un catálogo firmado verificado sustituyendo el
// catálogo instalado de forma atómica. Ante interrupción queda el anterior o
// el nuevo, nunca un punto intermedio; repetir la activación con el mismo
// sobre es idempotente.
func ActivateSignedCatalog(signed *SignedCatalog, configDir string) (*Catalog, error) {
	verified, err := VerifySignedCatalog(signed, configDir)
	if err != nil {
		return nil, err
	}
	// El catálogo instalado vive en el directorio de datos de la
	// configuración; WriteFileAtomic es atómico y fsync completo.
	data, err := json.MarshalIndent(verified, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := platform.WritePrivateFile(activeCatalogPath(configDir), append(data, '\n')); err != nil {
		return nil, err
	}
	return verified, nil
}

// activeCatalogPath es la ruta del catálogo activado por actualización.
func activeCatalogPath(configDir string) string {
	return filepath.Join(configDir, "audit-catalog.active.json")
}

// InstalledCatalogInfo declara qué catálogo está activado, si lo hay.
type InstalledCatalogInfo struct {
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	ActivatedAt string `json:"activated_at,omitempty"`
}

// InstalledCatalog lee la información del catálogo activado, sin activarlo.
func InstalledCatalog(configDir string) (*InstalledCatalogInfo, error) {
	data, err := platform.ReadFileBounded(activeCatalogPath(configDir), MaxSignedCatalogBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &InstalledCatalogInfo{Installed: false}, nil
		}
		return nil, err
	}
	var cat Catalog
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cat); err != nil {
		return nil, fmt.Errorf("auditoría: catálogo activado inválido: %w", err)
	}
	sum := sha256.Sum256(data)
	return &InstalledCatalogInfo{
		Installed:   true,
		Version:     cat.SchemaVersion,
		SHA256:      hex.EncodeToString(sum[:]),
		ActivatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
