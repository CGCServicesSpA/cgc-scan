package policy

import "testing"

func auditSummary() AuditFindingsSummary {
	return AuditFindingsSummary{
		ConfirmedBySeverity: map[string]int{
			"informational": 1, "low": 2, "medium": 1,
			"high": 0, "critical": 0,
		},
		NeedsValidation: 3,
	}
}

func TestAuditThresholdMatrix(t *testing.T) {
	cases := []struct {
		failOn   string
		violated bool
	}{
		// confirmed: cualquier confirmado cuenta.
		{AuditFailOnConfirmed, true},
		// severidades: >= umbral cuenta.
		{"informational", true},
		{"low", true},
		{"medium", true},
		{"high", false},
		{"critical", false},
		// needs_validation: solo los pendientes de validación.
		{AuditFailOnNeedsValidation, true},
	}
	for _, tc := range cases {
		got, err := AuditThresholdViolated(tc.failOn, auditSummary())
		if err != nil {
			t.Fatalf("%s: %v", tc.failOn, err)
		}
		if got != tc.violated {
			t.Fatalf("%s: violated = %v, want %v", tc.failOn, got, tc.violated)
		}
	}
}

func TestAuditThresholdUnknownFailsUsefully(t *testing.T) {
	if _, err := AuditThresholdViolated("no-existe", auditSummary()); err == nil {
		t.Fatal("se esperaba diagnóstico de umbral desconocido")
	}
}

func TestAuditFailOnValid(t *testing.T) {
	for _, ok := range []string{AuditFailOnConfirmed, AuditFailOnNeedsValidation, "medium", "critical", "informational"} {
		if !AuditFailOnValid(ok) {
			t.Fatalf("%q debió validar", ok)
		}
	}
	for _, bad := range []string{"", "no-existe", "confirmed_or_higher"} {
		if AuditFailOnValid(bad) {
			t.Fatalf("%q debió rechazarse", bad)
		}
	}
}

func TestAuditThresholdZeroFindingsIsClean(t *testing.T) {
	clean := AuditFindingsSummary{ConfirmedBySeverity: map[string]int{}, NeedsValidation: 0}
	for _, failOn := range []string{AuditFailOnConfirmed, AuditFailOnNeedsValidation, "critical", "medium"} {
		got, err := AuditThresholdViolated(failOn, clean)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Fatalf("%s: sin hallazgos no debe incumplir", failOn)
		}
	}
}
