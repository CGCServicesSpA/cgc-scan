package masking

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"texto normal", "hola mundo", "hola mundo"},
		{"conserva salto y tabulación", "a\tb\nc", "a\tb\nc"},
		{"elimina NUL y otros C0", "a\x00b\x01c\x1fd", "abcd"},
		{"elimina DEL y C1", "a\x7fb\u0085c", "abc"},
		{"elimina ANSI CSI color", "\x1b[31mrojo\x1b[0m", "rojo"},
		{"elimina ANSI con parámetros largos", "\x1b[1;2;3;4mtexto", "texto"},
		{"elimina OSC con BEL", "\x1b]0;título\x07texto", "texto"},
		{"elimina OSC con ST", "\x1b]8;;http://x\x1b\\texto", "texto"},
		{"ESC truncado", "abc\x1b", "abc"},
		{"elimina bidi", "a\u202eb\u2066c\u200e", "abc"},
		{"marca ancho cero", "a\u200bb\ufeffc", "a\uFFFDb\uFFFDc"},
		{"separador de línea", "a\u2028b", "a\nb"},
		{"UTF-8 inválido", string([]byte{0xff, 'a'}), "\uFFFDa"},
		{"emoji intacto", "ok 🚀", "ok 🚀"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.in)
			if got != tt.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := Sanitize(got); again != got {
				t.Fatalf("Sanitize no es idempotente: %q -> %q", got, again)
			}
		})
	}
}

func TestSanitizeRemovesAllForbiddenRunes(t *testing.T) {
	// Barrido de todos los controles y de los rangos bidi conocidos.
	var b strings.Builder
	for r := rune(0); r < 0x20; r++ {
		b.WriteRune(r)
	}
	for r := rune(0x80); r <= 0x9f; r++ {
		b.WriteRune(r)
	}
	for r := rune(0x202a); r <= 0x202e; r++ {
		b.WriteRune(r)
	}
	for r := rune(0x2066); r <= 0x2069; r++ {
		b.WriteRune(r)
	}
	clean := Sanitize(b.String())
	for _, r := range clean {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) {
			t.Fatalf("quedó una runa prohibida: U+%04X", r)
		}
	}
}

func TestMasker(t *testing.T) {
	m, err := NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	secret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	masked := m.Mask(secret)
	if strings.Contains(masked, secret) {
		t.Fatalf("la máscara contiene el secreto: %q", masked)
	}
	if !strings.HasPrefix(masked, "<secret:hmac-sha256:") {
		t.Fatalf("máscara inesperada: %q", masked)
	}
	if m.Mask(secret) != masked {
		t.Fatal("la máscara no es determinista")
	}
	other, _ := NewMasker([]byte("ffffffffffffffffffffffffffffffff"))
	if other.Mask(secret) == masked {
		t.Fatal("dos sales distintas produjeron la misma máscara")
	}
	if m.Mask("") != "" {
		t.Fatal("un valor vacío no debe enmascararse")
	}
}

func TestNewMaskerRejectsShortSalt(t *testing.T) {
	if _, err := NewMasker([]byte("corta")); err == nil {
		t.Fatal("se aceptó una sal corta")
	}
}

func TestRedact(t *testing.T) {
	m, _ := NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	text := "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 y password=hunter2-super-secret\x1b[0m"
	clean := m.Redact(text, []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789", "hunter2-super-secret"})
	if strings.Contains(clean, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") || strings.Contains(clean, "hunter2-super-secret") {
		t.Fatalf("quedó un secreto: %q", clean)
	}
	if strings.Contains(clean, "\x1b") {
		t.Fatalf("quedó ANSI: %q", clean)
	}
	if strings.Count(clean, "<secret:") != 2 {
		t.Fatalf("se esperaban dos máscaras: %q", clean)
	}
}

func TestRedactLongestFirst(t *testing.T) {
	m, _ := NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	short := "abc123"
	long := "abc123def456"
	clean := m.Redact("valor "+long, []string{short, long})
	if strings.Contains(clean, long) || strings.Contains(clean, short) {
		t.Fatalf("quedó un secreto: %q", clean)
	}
}

func TestSaltRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.salt")
	salt, err := LoadOrCreateSalt(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	if len(salt) != 32 {
		t.Fatalf("sal de %d bytes", len(salt))
	}
	again, err := LoadOrCreateSalt(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(salt) != string(again) {
		t.Fatal("la sal cambió entre lecturas")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permisos = %o, want 600", perm)
	}
}

func FuzzSanitize(f *testing.F) {
	seeds := []string{
		"hola",
		"\x1b[31mrojo\x1b[0m",
		"a\u202eb",
		"a\x00b",
		"🚀",
		"",
		string([]byte{0xff, 0xfe}),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Sanitize(s)
		if !utf8.ValidString(out) {
			t.Fatalf("salida UTF-8 inválida para %q: %q", s, out)
		}
		for _, r := range out {
			if r == 0x1b || r == 0x7f || (r < 0x20 && r != '\n' && r != '\t') || isBidiControl(r) {
				t.Fatalf("runa prohibida U+%04X en %q", r, out)
			}
		}
		if again := Sanitize(out); again != out {
			t.Fatalf("no idempotente: %q -> %q", out, again)
		}
	})
}

func FuzzRedact(f *testing.F) {
	m, _ := NewMasker([]byte("0123456789abcdef0123456789abcdef"))
	f.Add("token", "prefix token suffix")
	f.Add("", "sin secreto")
	f.Add("a", "aaa")
	f.Fuzz(func(t *testing.T, secret, text string) {
		if secret == "" {
			return
		}
		out := m.Redact(text, []string{secret})
		// Un secreto de uno o dos caracteres aparece por azar en el
		// hexadecimal de la propia máscara; la garantía se evalúa con
		// valores reales (>= 8 caracteres).
		if len(secret) >= 8 && strings.Contains(out, secret) {
			t.Fatalf("el secreto %q sobrevivió en %q", secret, out)
		}
		if len(secret) >= 8 {
			if again := m.Redact(out, []string{secret}); again != out {
				t.Fatalf("Redact no es idempotente para %q", secret)
			}
		}
	})
}
