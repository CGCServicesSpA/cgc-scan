// Package masking enmascara secretos y sanea texto no confiable antes de que
// llegue a un reporte, a un log o a un prompt.
//
// Reglas:
//   - Un secreto nunca se emite completo: se reemplaza por una huella HMAC
//     truncada con una sal por instalación.
//   - El texto saneado no contiene secuencias ANSI, caracteres de control
//     (salvo \n y \t) ni controles de dirección Unicode. Los caracteres de
//     ancho cero se reemplazan por U+FFFD para que su presencia sea visible.
package masking

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// replacement es el marcador para runas invisibles o inválidas.
const replacement = '\uFFFD'

// Sanitize elimina lo que no debe llegar a un consumidor y marca lo invisible.
func Sanitize(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b { // ESC: secuencia ANSI/OSC
			i = skipEscape(s, i)
			continue
		}
		if c == '\n' || c == '\t' {
			b.WriteByte(c)
			i++
			continue
		}
		if c < 0x20 || c == 0x7f {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(replacement)
			i++
			continue
		}
		switch {
		case r >= 0x80 && r <= 0x9f: // controles C1
			// se eliminan
		case r == 0x2028 || r == 0x2029: // separadores de línea Unicode
			b.WriteByte('\n')
		case isBidiControl(r):
			// se eliminan
		case isZeroWidth(r):
			b.WriteRune(replacement)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// SanitizeBytes aplica Sanitize a un []byte.
func SanitizeBytes(b []byte) []byte { return []byte(Sanitize(string(b))) }

// skipEscape devuelve el índice posterior a una secuencia ESC.
func skipEscape(s string, i int) int {
	j := i + 1
	if j >= len(s) {
		return j
	}
	switch s[j] {
	case '[': // CSI: parámetros hasta un byte final 0x40-0x7e
		j++
		for j < len(s) {
			c := s[j]
			j++
			if c >= 0x40 && c <= 0x7e {
				return j
			}
		}
		return j
	case ']': // OSC: hasta BEL o ST (ESC \)
		j++
		for j < len(s) {
			if s[j] == 0x07 {
				return j + 1
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j + 2
			}
			j++
		}
		return j
	default: // secuencia de dos bytes
		return i + 2
	}
}

func isBidiControl(r rune) bool {
	switch {
	case r >= 0x202a && r <= 0x202e,
		r >= 0x2066 && r <= 0x2069,
		r == 0x200e, r == 0x200f, r == 0x061c:
		return true
	}
	return false
}

func isZeroWidth(r rune) bool {
	switch r {
	case 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff:
		return true
	}
	return false
}

// ErrEmptySalt indica una sal ausente.
var ErrEmptySalt = errors.New("la sal no puede estar vacía")

// Masker produce huellas y reemplazos de secretos con una sal por instalación.
// La sal no se escribe en el reporte; sin ella no se puede adivinar el valor
// a partir de la huella (ADR-08).
type Masker struct {
	salt []byte
}

// NewMasker construye un Masker. La sal debe tener al menos 16 bytes.
func NewMasker(salt []byte) (*Masker, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("%w: %d bytes, se requieren al menos 16", ErrEmptySalt, len(salt))
	}
	cp := make([]byte, len(salt))
	copy(cp, salt)
	return &Masker{salt: cp}, nil
}

// Fingerprint devuelve una huella estable del valor: HMAC-SHA256 truncado a
// 16 bytes en hexadecimal, con prefijo de algoritmo.
func (m *Masker) Fingerprint(value string) string {
	mac := hmac.New(sha256.New, m.salt)
	mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)[:16])
}

// Mask reemplaza un secreto por un marcador que conserva su huella para poder
// correlacionarlo sin exponerlo. Un valor vacío queda vacío.
func (m *Masker) Mask(value string) string {
	if value == "" {
		return ""
	}
	return "<secret:" + m.Fingerprint(value) + ">"
}

// Redact reemplaza cada secreto conocido dentro del texto por su máscara y
// sanea el resultado. Los secretos más largos se reemplazan primero para que
// uno corto no rompa a otro que lo contiene.
func (m *Masker) Redact(text string, secrets []string) string {
	clean := Sanitize(text)
	secrets = uniqueNonEmpty(secrets)
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, s := range secrets {
		clean = strings.ReplaceAll(clean, s, m.Mask(s))
	}
	return clean
}

// RedactBytes aplica Redact a un []byte.
func (m *Masker) RedactBytes(text []byte, secrets []string) []byte {
	return []byte(m.Redact(string(text), secrets))
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// NewSalt genera 32 bytes aleatorios.
func NewSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generar sal: %w", err)
	}
	return salt, nil
}

// EncodeSalt serializa una sal como hexadecimal.
func EncodeSalt(salt []byte) string { return hex.EncodeToString(salt) }

// DecodeSalt interpreta una sal hexadecimal.
func DecodeSalt(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("sal inválida: %w", err)
	}
	if len(b) < 16 {
		return nil, ErrEmptySalt
	}
	return b, nil
}

// LoadOrCreateSalt lee la sal del archivo o la crea con permisos 0600 y
// escritura atómica. La sal es por instalación y por usuario.
func LoadOrCreateSalt(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return DecodeSalt(string(data))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("leer sal: %w", err)
	}
	salt, err := NewSalt()
	if err != nil {
		return nil, err
	}
	if err := platform.WritePrivateFile(path, []byte(EncodeSalt(salt))); err != nil {
		return nil, fmt.Errorf("guardar sal: %w", err)
	}
	return salt, nil
}
