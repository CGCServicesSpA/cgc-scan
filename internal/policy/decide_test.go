package policy

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name string
		run  RunOutcome
		pol  PolicyOutcome
		want int
	}{
		{"completo sin hallazgos", RunOutcome{Complete: true}, PolicyOutcome{}, ExitOK},
		{"completo bajo el umbral", RunOutcome{Complete: true}, PolicyOutcome{Violated: false}, ExitOK},
		{"completo con incumplimiento", RunOutcome{Complete: true}, PolicyOutcome{Violated: true}, ExitViolation},
		{"argumentos inválidos", RunOutcome{InvalidArgs: true, Complete: false}, PolicyOutcome{Violated: true}, ExitUsage},
		{"argumentos inválidos con cancelación", RunOutcome{Canceled: true, InvalidArgs: true}, PolicyOutcome{}, ExitCanceled},
		{"ejecución incompleta", RunOutcome{Complete: false}, PolicyOutcome{}, ExitIncomplete},
		{"incompleta e incumplida: gana 3", RunOutcome{Complete: false}, PolicyOutcome{Violated: true}, ExitIncomplete},
		{"cancelación gana a todo", RunOutcome{Canceled: true, Complete: false}, PolicyOutcome{Violated: true}, ExitCanceled},
		{"cancelación con ejecución completa", RunOutcome{Canceled: true, Complete: true}, PolicyOutcome{Violated: true}, ExitCanceled},
		{"cero explícito", RunOutcome{Complete: true}, PolicyOutcome{Violated: false}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.run, tt.pol); got != tt.want {
				t.Fatalf("Decide(%+v, %+v) = %d, want %d", tt.run, tt.pol, got, tt.want)
			}
		})
	}
}

func TestExitCodesAreStable(t *testing.T) {
	// Los códigos son contrato público; este test falla si alguien los cambia.
	if ExitOK != 0 || ExitViolation != 1 || ExitUsage != 2 || ExitIncomplete != 3 || ExitCanceled != 130 {
		t.Fatal("los códigos de salida cambiaron respecto del PRD §8.1")
	}
}
