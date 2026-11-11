package audit

import (
	"testing"
)

// Proyecto con capa de mensajería reconocible (colas, consumers, brokers).
func messagingProject() map[string]string {
	return map[string]string{
		"go.mod":                        "module example.test/mq\n\ngo 1.27.3\n",
		"internal/queue/producer.go":    "package queue\n\nfunc Produce() {}\n",
		"internal/queue/consumer.go":    "package queue\n\nfunc Consume() {}\n",
		"internal/queue/broker.go":      "package queue\n\nfunc Broker() {}\n",
		"internal/pubsub/subscriber.go": "package pubsub\n\nfunc Subscribe() {}\n",
	}
}

// Proyecto con interfaz IPC local reconocible (daemon, socket, deep links).
func ipcProject() map[string]string {
	return map[string]string{
		"go.mod":                     "module example.test/daemon\n\ngo 1.27.3\n",
		"internal/daemon/daemon.go":  "package daemon\n\nfunc Serve() {}\n",
		"internal/daemon/ipc.go":     "package daemon\n\nfunc Handle() {}\n",
		"internal/links/deeplink.go": "package links\n\nfunc Route() {}\n",
	}
}

func hasClass(ledger *Ledger, id string) bool {
	for _, u := range ledger.Units {
		if u.AttackClass == id {
			return true
		}
	}
	return false
}

func TestMessagingClassesActivateOnMessagingSignal(t *testing.T) {
	ledger := buildForTestProfile(t, writeProject(t, messagingProject()), nil, ProfileStandard)
	for _, class := range []string{"message-boundary-canonicalization", "topic-subscription-scope", "duplicate-delivery-idempotency"} {
		if !hasClass(ledger, class) {
			t.Fatalf("la clase %s debió activarse con la señal de mensajería", class)
		}
	}
	if err := ValidateLedgerSemantics(ledger); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestMessagingClassesDoNotActivateWithoutSignal(t *testing.T) {
	// El árbol CLI puro no tiene mensajería: las clases del dominio no
	// aparecen y la ausencia de señales no se declara como cobertura.
	ledger := buildForTestProfile(t, writeProject(t, cliOnlyProject()), nil, ProfileStandard)
	for _, class := range []string{"message-boundary-canonicalization", "topic-subscription-scope"} {
		if hasClass(ledger, class) {
			t.Fatalf("la clase %s no debió activarse sin señal", class)
		}
	}
}

func TestIPCClassesActivateOnIPCSignal(t *testing.T) {
	ledger := buildForTestProfile(t, writeProject(t, ipcProject()), nil, ProfileStandard)
	for _, class := range []string{"local-ipc-untrusted-peer", "deeplink-navigation-confusion"} {
		if !hasClass(ledger, class) {
			t.Fatalf("la clase %s debió activarse con la señal ipc_signal", class)
		}
	}
	if err := ValidateLedgerSemantics(ledger); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestIPCClassesDoNotActivateWithoutSignal(t *testing.T) {
	ledger := buildForTestProfile(t, writeProject(t, cliOnlyProject()), nil, ProfileStandard)
	for _, class := range []string{"local-ipc-untrusted-peer", "deeplink-navigation-confusion"} {
		if hasClass(ledger, class) {
			t.Fatalf("la clase %s no debió activarse sin señal", class)
		}
	}
}

func TestClientClassesActivateOnJSProject(t *testing.T) {
	files := map[string]string{
		"package.json":          "{\"name\":\"app\",\"version\":\"1.0.0\"}",
		"src/app/store.ts":      "export const store = {};",
		"src/app/mergeUtil.ts":  "export function deepMerge(a: object, b: object) { return a; }",
		"src/app/messageBus.ts": "export function onMessage(cb: (m: unknown) => void) { return cb; }",
		"src/app/persist.ts":    "export function save(k: string, v: string) { localStorage.setItem(k, v); }",
	}
	ledger := buildForTestProfile(t, writeProject(t, files), nil, ProfileStandard)
	for _, class := range []string{"prototype-pollution-gadget", "postmessage-origin-confusion", "client-storage-stale-authz"} {
		if !hasClass(ledger, class) {
			t.Fatalf("la clase %s debió activarse en un proyecto JS/TS con fuente", class)
		}
	}
}

func TestAgentBoundaryClassesActivateWithSource(t *testing.T) {
	// Las clases de frontera de agente requieren solo la señal source: son
	// estructurales en cualquier proyecto con código.
	ledger := buildForTestProfile(t, writeProject(t, cliOnlyProject()), nil, ProfileStandard)
	for _, class := range []string{"tool-argument-injection", "indirect-injection-retrieved-content"} {
		if !hasClass(ledger, class) {
			t.Fatalf("la clase %s debió activarse con source", class)
		}
	}
}

func TestExpandedCatalogIsDeterministicAcrossProfiles(t *testing.T) {
	for _, files := range []map[string]string{messagingProject(), ipcProject()} {
		root := writeProject(t, files)
		for _, profile := range []string{ProfileQuick, ProfileStandard, ProfileDeep} {
			first := buildForTestProfile(t, root, nil, profile)
			second := buildForTestProfile(t, root, nil, profile)
			a, err := first.JSON()
			if err != nil {
				t.Fatal(err)
			}
			b, err := second.JSON()
			if err != nil {
				t.Fatal(err)
			}
			if string(a) != string(b) {
				t.Fatalf("%s: reparto no determinista", profile)
			}
		}
	}
}

func TestExpandedCatalogClassesTraceToCompanions(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"prototype-pollution-gadget", "postmessage-origin-confusion",
		"client-storage-stale-authz", "message-boundary-canonicalization",
		"topic-subscription-scope", "duplicate-delivery-idempotency",
		"tenant-isolation-missing", "derived-copy-acl-drift",
		"softdelete-tombstone-bypass", "integer-overflow-unchecked",
		"binary-plugin-search-order", "tool-argument-injection",
		"indirect-injection-retrieved-content", "local-ipc-untrusted-peer",
		"deeplink-navigation-confusion",
	} {
		class := cat.ClassByID(id)
		if class == nil {
			t.Fatalf("falta la clase %s en el catálogo", id)
		}
		if class.Source == "" || !stringContains(class.Source, "companions/") {
			t.Fatalf("la clase %s debe trazarse a su companion: %q", id, class.Source)
		}
	}
}

func stringContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
