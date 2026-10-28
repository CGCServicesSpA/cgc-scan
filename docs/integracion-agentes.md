# Integración con agentes y CI

Este documento es para quien consume CGC Scan desde un agente, un editor o un
pipeline. El contrato es el JSON; el prompt es una representación para
remediación.

## Invocación

```bash
cgc-scan scan "$PROYECTO" --format json --report-out "$REPORTE" --fail-on high
```

- Sin interacción: `scan` nunca espera entrada.
- stdout: solo el documento (JSON, texto o prompt).
- stderr: logs y progreso; `--log-format json` los hace estructurados.
- Códigos: 0 sin incumplimiento, 1 política, 2 argumentos/configuración, 3
  ejecución incompleta, 130 cancelación.

## Leer el resultado

```json
{
  "schema_version": "1.0.0",
  "coverage": { "partial": false, "not_analyzed": [], "units": [] },
  "findings": [
    {
      "fingerprint": "0123456789abcdef0123456789abcdef",
      "kind": "vulnerability",
      "severity": { "original": "HIGH", "normalized": "high", "source": "trivy" },
      "package": { "ecosystem": "Go", "name": "golang.org/x/text", "version": "v0.3.0", "fixed_version": "v0.41.0" },
      "descriptions": [ { "text": "The Nickname profile can panic...", "source": "trivy" } ],
      "locations": [ { "path": "go.mod" } ],
      "references": [ "https://pkg.go.dev/vuln/GO-2026-6629" ],
      "remediation": [ { "description": "Actualizar a v0.41.0 o superior", "source": "advisory" } ],
      "verification": {
        "unit": "root",
        "status": "ready",
        "recipes": [
          { "unit": "root", "kind": "test", "command": "go test ./...", "workdir": ".", "origin": "user" },
          { "unit": "root", "kind": "build", "command": "go build ./...", "workdir": ".", "origin": "user" }
        ],
        "missing": [],
        "rescan": "cgc-scan scan . --format json"
      },
      "sources": [ { "engine": "trivy", "version": "0.76.1" } ]
    }
  ],
  "policy": { "fail_on": "high", "violated": true }
}
```

Reglas para el consumidor:

1. Comprueba `coverage.partial` y `errors` antes de afirmar que algo está resuelto.
2. Usa `fingerprint` como identidad estable entre ejecuciones.
3. No inventes campos ausentes: `priority`, `confidence`, `fixed_version` pueden
   ser nulos si la fuente no los entregó.
4. Los `sources` y `severity_others` muestran diferencias entre motores; no las
   descartes.
5. Cada hallazgo trae `verification`: la receta de tests/build de su unidad, el
   comando de reescaneo y si la validación está `ready` o `blocked`. Si está
   bloqueada, faltan recetas confirmadas por el usuario; no inventes comandos.

## Flujo por parche con el prompt

```bash
cgc-scan scan "$PROYECTO" --format prompt --report-out "$REPORTE" > "$PROMPT"
```

El prompt:

- versiona plantilla y esquema;
- delimita la evidencia no confiable con un nonce;
- exige tests sin modificar, build y reescaneo por parche;
- declara las recetas confirmadas y las unidades con validación bloqueada;
- se divide en lotes si supera el umbral, con referencia al reporte completo;
- no llama a ningún modelo ni ejecuta comandos.

Un agente debe aplicar un parche acotado, ejecutar los tests de la receta sin
tocarlos, ejecutar el build y volver a escanear el ámbito afectado. Si un test
falla, corrige el código o informa el bloqueo; no lo omitas. Si un cambio major
requiere adaptar tests, detente y pide autorización expresa.

## Comparar tras corregir

```bash
cgc-scan compare "$REPORTE_ANTERIOR" "$REPORTE_NUEVO" --format json
```

- `new`, `persistent`, `resolved`, `not_evaluated`.
- Si el reporte marca `verification.status=blocked`, confirma una vez las recetas
  detectadas con `cgc-scan scan . --confirm-recipes` o con `cgc-scan recipes --set`.
- Un hallazgo ausente en un escaneo parcial o con errores es `not_evaluated`.
- Para declarar `resolved` hace falta cobertura comparable y el mismo ámbito.

## CI

```yaml
- run: cgc-scan doctor --format json
- run: cgc-scan scan . --offline --format json --fail-on high
```

Recomendaciones:

- Guarda el JSON como artefacto y usa `--report-out`.
- En modo `--offline`, prepara antes las bases con `cgc-scan update-db`.
- No uses `--require-isolation enforced` si el proyecto necesita adaptadores de
  host; el escaneo fallará antes de analizar, por diseño.
- Fija la versión de CGC Scan y las versiones de motores del manifiesto.

## Ejemplo mínimo en Go

```go
cmd := exec.CommandContext(ctx, "cgc-scan", "scan", project, "--format", "json", "--offline")
cmd.Env = append(os.Environ(), "NO_COLOR=1")
out, err := cmd.Output()
if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
    // Política incumplida: el JSON sigue siendo válido.
}
var doc Report
_ = json.Unmarshal(out, &doc)
```

No interpretes el código 1 como fallo de ejecución: el documento sigue siendo
válido y contiene `policy.violated=true`.
