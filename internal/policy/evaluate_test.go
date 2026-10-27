package policy

import (
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

func finding(fp string, sev normalize.Severity) normalize.Finding {
	return normalize.Finding{
		Fingerprint: fp,
		Kind:        normalize.KindCode,
		Title:       "x",
		Severity:    normalize.SeverityInfo{Original: string(sev), Normalized: sev, Source: "eslint"},
		Sources:     []normalize.SourceRef{{Engine: "eslint"}},
	}
}

func TestEvaluateThreshold(t *testing.T) {
	findings := []normalize.Finding{
		finding("a", normalize.SeverityCritical),
		finding("b", normalize.SeverityMedium),
	}
	ev := Evaluate(findings, normalize.SeverityHigh, true, nil)
	if !ev.Violated {
		t.Fatal("critical debería violar fail-on high")
	}
	if len(ev.Active) != 2 {
		t.Fatalf("activos = %d", len(ev.Active))
	}
}

func TestEvaluateInfoNeverBlocks(t *testing.T) {
	findings := []normalize.Finding{
		finding("a", normalize.SeverityInformational),
		finding("b", normalize.SeverityInformational),
	}
	for _, threshold := range []normalize.Severity{normalize.SeverityInformational, normalize.SeverityLow, normalize.SeverityHigh} {
		if ev := Evaluate(findings, threshold, true, nil); ev.Violated {
			t.Fatalf("info bloqueó con umbral %s", threshold)
		}
	}
}

func TestEvaluateUnknownOnlyWhenPolicySays(t *testing.T) {
	findings := []normalize.Finding{finding("a", normalize.SeverityUnknown)}
	if ev := Evaluate(findings, normalize.SeverityHigh, false, nil); ev.Violated {
		t.Fatal("unknown bloqueó con unknown_counts=false")
	}
	if ev := Evaluate(findings, normalize.SeverityHigh, true, nil); !ev.Violated {
		t.Fatal("unknown no bloqueó con unknown_counts=true")
	}
}

func TestEvaluateExpiredExceptionDoesNotSuppress(t *testing.T) {
	findings := []normalize.Finding{finding("a", normalize.SeverityHigh)}
	ex := []Exception{{
		Fingerprint: "a", Reason: "no alcanzable", Owner: "seguridad",
		Expires: "2026-01-01", Effective: false,
	}}
	ev := Evaluate(findings, normalize.SeverityHigh, true, ex)
	if ev.Violated != true || ev.SuppressedCount != 0 {
		t.Fatalf("una excepción vencida suprimió: %+v", ev)
	}
	if findings[0].Policy.Status != "active" {
		t.Fatalf("estado = %q", findings[0].Policy.Status)
	}
}

func TestEvaluateActiveExceptionKeepsFindingVisible(t *testing.T) {
	findings := []normalize.Finding{finding("a", normalize.SeverityHigh)}
	ex := []Exception{{
		Fingerprint: "a", Reason: "riesgo aceptado", Owner: "seguridad",
		Expires: "2999-01-01", Effective: true,
	}}
	ev := Evaluate(findings, normalize.SeverityHigh, true, ex)
	if ev.Violated {
		t.Fatal("una excepción efectiva no debe violar")
	}
	if ev.SuppressedCount != 1 || len(ev.Active) != 0 {
		t.Fatalf("evaluación = %+v", ev)
	}
	if findings[0].Policy.Status != "suppressed" || findings[0].Policy.SuppressedReason != "riesgo aceptado" {
		t.Fatalf("el hallazgo suprimido no conserva motivo: %+v", findings[0].Policy)
	}
}

func TestEvaluateInvalidThresholdFallsBackToHigh(t *testing.T) {
	findings := []normalize.Finding{finding("a", normalize.SeverityMedium)}
	if ev := Evaluate(findings, normalize.Severity("raro"), true, nil); ev.Violated {
		t.Fatal("medium no debería violar el fallback high")
	}
	findings[0].Severity.Normalized = normalize.SeverityHigh
	if ev := Evaluate(findings, normalize.Severity("raro"), true, nil); !ev.Violated {
		t.Fatal("high debería violar el fallback high")
	}
}
