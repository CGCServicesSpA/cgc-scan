package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

// seedLedger genera un ledger válido que alimenta el fuzz target.
func seedLedger() []byte {
	l := plannerLedger("sql-injection", "command-injection")
	l.Units[0].State = StateCandidate
	l.Units[0].Owner = "hunter-a"
	l.Units[0].ReviewedPaths = []string{"main.go"}
	l.Units[0].Checks = []Check{huntCheck("hunter-a")}
	l.Units[0].Candidates = []string{"fp-1"}
	l.Recompute()
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// seedFindings genera un documento de hallazgos válido.
func seedFindings() []byte {
	data, err := json.MarshalIndent(validFindings(), "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// seedSubmission genera una entrega de caza válida.
func seedSubmission() []byte {
	sub := stampingSubmission("hunter-a", "root/code/sql-injection", "fp-1")
	data, err := json.MarshalIndent(sub, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// seedCandidates genera un estado de verificación válido.
func seedCandidates() []byte {
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: "run-1", Items: []Candidate{{
		Fingerprint: "fp-1", Unit: "root/code/sql-injection", HunterAgent: "hunter-a",
		Proposed: recordFor("fp-1", VerdictNeedsValidation), State: CandidatePending,
		Attempts: []VerificationAttempt{},
	}}}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// fuzzSeeds devuelve las semillas comunes: documento válido, truncado,
// sobredimensionado, anidado y basura con forma de contrato.
func fuzzSeeds(valid []byte) [][]byte {
	return [][]byte{
		valid,
		valid[:len(valid)/2],
		bytes.Repeat(valid, 1+MaxSubmissionBytes/len(valid)),
		append(append([]byte("{\"x\":"), bytes.Repeat([]byte{'['}, MaxJSONDepth+64)...), bytes.Repeat([]byte{']'}, MaxJSONDepth+64)...),
		[]byte("{\"schema_version\":" + string(valid[:20]) + "}"),
	}
}

func FuzzDecodeLedger(f *testing.F) {
	for _, seed := range fuzzSeeds(seedLedger()) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := DecodeLedger(data)
		if err != nil {
			return
		}
		if _, jerr := l.JSON(); jerr != nil {
			t.Fatalf("un ledger decodificado debe serializar: %v", jerr)
		}
	})
}

func FuzzDecodeFindings(f *testing.F) {
	for _, seed := range fuzzSeeds(seedFindings()) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fnd, err := DecodeFindings(data)
		if err != nil {
			return
		}
		if _, jerr := json.Marshal(fnd); jerr != nil {
			t.Fatalf("hallazgos decodificados deben serializar: %v", jerr)
		}
	})
}

func FuzzDecodeSubmission(f *testing.F) {
	for _, seed := range fuzzSeeds(seedSubmission()) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		sub, err := DecodeSubmission(data)
		if err != nil {
			return
		}
		if _, jerr := json.Marshal(sub); jerr != nil {
			t.Fatalf("una entrega decodificada debe serializar: %v", jerr)
		}
	})
}

func FuzzDecodeCandidates(f *testing.F) {
	for _, seed := range fuzzSeeds(seedCandidates()) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeCandidates(data)
		if err != nil {
			return
		}
		if _, jerr := json.Marshal(c); jerr != nil {
			t.Fatalf("el estado decodificado debe serializar: %v", jerr)
		}
	})
}

func FuzzDecodeRunState(f *testing.F) {
	// Semilla válida: un estado mínimo pero completo, construido en línea
	// para no depender de helpers de pruebas unitarias.
	l := plannerLedger("sql-injection")
	st := &RunState{
		SchemaVersion:  StateSchemaVersion,
		Source:         &SourceInfo{Mode: SourceModeWorktree},
		CatalogVersion: CatalogSchemaVersion,
		Ledger:         l,
		Candidates:     &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}},
	}
	valid, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		f.Fatal(err)
	}
	valid = append(valid, '\n')
	for _, seed := range fuzzSeeds(valid) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rst, err := DecodeRunState(data)
		if err != nil {
			return
		}
		if _, jerr := json.Marshal(rst); jerr != nil {
			t.Fatalf("el estado decodificado debe serializar: %v", jerr)
		}
	})
}

func FuzzDecodeSignedCatalog(f *testing.F) {
	// Semillas: sobre válido, truncado, sobredimensionado y anidado.
	cat, err := LoadCatalog()
	if err != nil {
		f.Fatal(err)
	}
	signed := SignedCatalog{
		SchemaVersion: CatalogTrustVersion,
		Catalog:       cat,
		KeyID:         "seed",
		Algorithm:     "ed25519",
		Signature:     "0000",
	}
	valid, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		f.Fatal(err)
	}
	valid = append(valid, '\n')
	for _, seed := range fuzzSeeds(valid) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Solo forma: la verificación necesita un anillo de confianza, que
		// aquí no existe; ningún fallo debe entrar en pánico.
		var signed SignedCatalog
		if err := json.Unmarshal(data, &signed); err != nil {
			return
		}
		if _, jerr := json.Marshal(&signed); jerr != nil {
			t.Fatalf("el sobre decodificado debe serializar: %v", jerr)
		}
	})
}
