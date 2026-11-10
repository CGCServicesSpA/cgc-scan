package audit

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// padTo rellena un documento válido con espacios hasta el tamaño pedido: el
// espacio residual es JSON legal, así que el relleno no altera el contrato.
func padTo(t *testing.T, valid []byte, size int) []byte {
	t.Helper()
	if len(valid) > size {
		t.Fatalf("la semilla válida (%d bytes) supera el límite (%d)", len(valid), size)
	}
	out := append([]byte{}, valid...)
	out = append(out, bytes.Repeat([]byte{' '}, size-len(valid))...)
	return out
}

func TestDecodersAcceptExactLimitAndRejectOneByteOver(t *testing.T) {
	cases := []struct {
		name   string
		limit  int
		seed   []byte
		decode func([]byte) (any, error)
	}{
		{"entrega", MaxSubmissionBytes, seedSubmission(), func(d []byte) (any, error) { return DecodeSubmission(d) }},
		{"ledger", MaxLedgerBytes, seedLedger(), func(d []byte) (any, error) { return DecodeLedger(d) }},
		{"candidatos", MaxCandidatesBytes, seedCandidates(), func(d []byte) (any, error) { return DecodeCandidates(d) }},
		{"hallazgos", MaxFindingsBytes, seedFindings(), func(d []byte) (any, error) { return DecodeFindings(d) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exact := padTo(t, tc.seed, tc.limit)
			if len(exact) != tc.limit {
				t.Fatalf("tamaño = %d, want %d", len(exact), tc.limit)
			}
			if _, err := tc.decode(exact); err != nil {
				t.Fatalf("exactamente el límite debe aceptarse: %v", err)
			}
			over := append(exact, ' ')
			if _, err := tc.decode(over); err == nil || !strings.Contains(err.Error(), "límite") {
				t.Fatalf("err = %v, want rechazo por límite", err)
			}
		})
	}
}

func TestCheckJSONDepthAcceptsLimitAndRejectsOneOver(t *testing.T) {
	nested := func(depth int) []byte {
		var b bytes.Buffer
		for i := 0; i < depth; i++ {
			b.WriteString(`{"a":`)
		}
		b.WriteString(`1`)
		for i := 0; i < depth; i++ {
			b.WriteString(`}`)
		}
		return b.Bytes()
	}
	if err := checkJSONDepth(nested(MaxJSONDepth), MaxJSONDepth); err != nil {
		t.Fatalf("el límite exacto debe aceptarse: %v", err)
	}
	if err := checkJSONDepth(nested(MaxJSONDepth+1), MaxJSONDepth); err == nil ||
		!strings.Contains(err.Error(), "anidamiento") {
		t.Fatalf("err = %v, want rechazo de anidamiento", err)
	}
	// Un delimitador dentro de una cadena no cuenta como anidamiento.
	if err := checkJSONDepth([]byte(`{"a":"{[[{\"b\":["}`), MaxJSONDepth); err != nil {
		t.Fatalf("err = %v, want aceptado", err)
	}
}

func TestStoreRejectsOverLimitCandidatesFile(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ledger := plannerLedger("sql-injection")
	if err := store.SaveLedger(ledger); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{' '}, candidatesReadLimit+1)
	if err := os.WriteFile(store.CandidatesPath(), oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadCandidates(ledger); err == nil || !strings.Contains(err.Error(), "límite") {
		t.Fatalf("err = %v, want rechazo por límite", err)
	}
	// El archivo sobredimensionado queda intacto: la carga no modifica nada.
	info, err := os.Stat(store.CandidatesPath())
	if err != nil || info.Size() != int64(len(oversized)) {
		t.Fatalf("la carga fallida tocó el archivo: %v %v", info, err)
	}
}

func TestValidSeedsStillDecode(t *testing.T) {
	if _, err := DecodeLedger(seedLedger()); err != nil {
		t.Fatalf("semilla de ledger: %v", err)
	}
	if _, err := DecodeFindings(seedFindings()); err != nil {
		t.Fatalf("semilla de hallazgos: %v", err)
	}
	if _, err := DecodeSubmission(seedSubmission()); err != nil {
		t.Fatalf("semilla de entrega: %v", err)
	}
	if _, err := DecodeCandidates(seedCandidates()); err != nil {
		t.Fatalf("semilla de candidatos: %v", err)
	}
	// El relleno de espacios tras el objeto se acepta.
	padded := seedCandidates()
	if _, err := DecodeCandidates(append(append([]byte{}, padded...), ' ', '\t', '\n')); err != nil {
		t.Fatalf("espacio residual: %v", err)
	}
}
