package audit

import "fmt"

// Límites de tamaño y de anidamiento de los documentos. Se aplican en las API
// públicas de decodificación y en la lectura del store, de modo que ninguna
// entrada pueda agotar memoria o pila antes de ser rechazada.
const (
	// MaxSubmissionBytes es el límite de una entrega del agente.
	MaxSubmissionBytes = 8 << 20
	// MaxLedgerBytes es el límite del documento de cobertura.
	MaxLedgerBytes = 16 << 20
	// MaxCandidatesBytes es el límite del estado de verificación.
	MaxCandidatesBytes = 16 << 20
	// MaxFindingsBytes es el límite del documento de hallazgos.
	MaxFindingsBytes = 32 << 20
	// MaxRunStateBytes es el límite del estado autoritativo: la suma de los
	// documentos que contiene.
	MaxRunStateBytes = 64 << 20
	// MaxJSONDepth es el límite de anidamiento aceptado por los
	// decodificadores: un objeto o arreglo más profundo no es un contrato
	// válido y puede agotar la pila del decodificador.
	MaxJSONDepth = 64
)

// checkSize rechaza un documento que supera su límite.
func checkSize(data []byte, limit int, what string) error {
	if len(data) > limit {
		return fmt.Errorf("%s supera el límite de %d bytes (%d recibidos)", what, limit, len(data))
	}
	return nil
}

// checkJSONDepth rechaza un documento cuyo anidamiento supera el límite.
func checkJSONDepth(data []byte, max int) error {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, b := range data {
		switch {
		case escaped:
			escaped = false
		case inString:
			switch b {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case b == '"':
			inString = true
		case b == '{' || b == '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case b == '}' || b == ']':
			depth--
		}
	}
	if deepest > max {
		return fmt.Errorf("el anidamiento supera el límite de %d niveles (%d observados)", max, deepest)
	}
	return nil
}
