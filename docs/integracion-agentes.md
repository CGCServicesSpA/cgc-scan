# Integración con agentes y CI

Este documento es para quien consume CGC Scan desde un agente, un editor o un
pipeline. El contrato es el JSON; el prompt es una representación para
remediación.

## Flujo recomendado: una pasada y después iterar barato

```bash
cgc-scan agent "$PROYECTO"               # one-shot: grupos, prioridad, delta, acciones
cgc-scan explain <grupo|huella> "$PROYECTO"
# aplicar el parche y ejecutar las recetas confirmadas
cgc-scan verify <grupo> "$PROYECTO"      # solo unidad y motores afectados
cgc-scan status "$PROYECTO"              # resumen sin escanear
```

- `agent` emite `agent-1.0.0` y guarda el canónico en `report_path`.
- `explain` devuelve descripción, referencias y evidencia de una huella o grupo.
- `verify` devuelve `resolved|persistent|partial` por huella y el delta.
- `plan` reconstruye grupos y acciones desde `latest.json`; `compare --baseline`
  compara `latest.json` con `baseline.json` sin rutas.
- La primera ejecución de `agent` crea la línea base; `baseline set|clear` la
  controla explícitamente.
- `status`, `plan`, `explain` y `compare --baseline` no escanean.

## Campos nuevos de `report-1.1.0`

- `remediation_groups`: una acción por componente con `package.from/to`,
  `breaking_risk`, `direct`, `commands.apply` (sugerencia, no se ejecuta),
  `verification` y `fixes`.
- `next_actions`: orden determinista; incluye `confirm_recipes`,
  `apply_group`, `revoke_secret`, `fix_code`, `fix_config`, `install_toolchain`
  y `update_db`. Con Docker, `install_toolchain` suele significar que la imagen
  del lenguaje no se pudo preparar, no que falte instalar Go/Node/PHP/Rust/
  Python en el equipo: revisa `tools.engines[].preparation[]` antes de actuar.
- `priority.score/rank/factors`: prioridad explicable; bajar la prioridad de
  `test/`, `fixtures/` y `examples/` no oculta el hallazgo.
- `--min-severity` es solo un filtro de vista para texto/agent; el JSON canónico
  conserva todo y la política no cambia.
- `package.direct/relationship/via`: directa o transitiva y el padre directo.
- `delta`: `new`, `persistent`, `resolved`, `not_evaluated` frente a la línea base.
- `tools.engines[].cache`: `hit|miss|mixed|disabled` por unidad y motor.

Los consumidores de `1.0.0` siguen funcionando: los campos son aditivos.

## Skill global para agentes

Instala o actualiza la skill una vez; queda disponible en todos los proyectos.
`install.sh` la actualiza junto con el binario, así que normalmente no hace
falta ejecutar el instalador de la skill por separado:

```bash
./install.sh                               # binario + skill (destino auto)
./install.sh --no-skill                    # solo el binario
./install.sh --skill-target all            # binario + skill en todos los harness
./scripts/install-skill.sh                 # auto: DevPass/OpenCode + Claude
./scripts/install-skill.sh --target all
./scripts/install-skill.sh --status
./scripts/install-skill.sh --check
./scripts/install-skill.sh --uninstall
```

Destinos:

- fuente canónica: `~/.agents/skills/cgc-scan`
- DevPass: `~/.config/devpass-code/skills/cgc-scan` (y compatibilidad OpenCode)
- OpenCode: `~/.config/opencode/skills/cgc-scan`
- Claude: `~/.claude/skills/cgc-scan`
- Codex: `~/.codex/skills/cgc-scan`
- Kiro: `~/.kiro/skills/cgc-scan`
- mcode/MiniMax: `~/.minimax/skills/cgc-scan`
- Pi: `~/.pi/agent/skills/cgc-scan`

`--target agents` instala solo la copia canónica; `--target opencode|devpass|
claude|codex|kiro|mcode|pi` instalan la canónica y el enlace correspondiente.
`--target all` enlaza todos. `--target DIR` instala en `DIR/cgc-scan` sin
enlaces. `SKILLS_DIR` fuerza un único destino directo. La actualización es
atómica y conserva `cgc-scan.bak`; `--check` sale con 1 si la versión instalada
no coincide con la fuente.

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

Antes de interpretar hallazgos, mira cómo se ejecutó cada motor:

- `tools.engines[].status`: `completed`, `skipped`, `failed` o `not_requested`.
- `tools.engines[].mode`: `docker` para Trivy y para los adaptadores en imagen de
  toolchain, `global`/`library` para el host.
- `tools.engines[].image`: etiqueta de la imagen derivada
  (`cgc-scan/toolchain:...`) cuando todas las unidades comparten una; en un
  monorepo con versiones distintas queda vacía y `preparation[]` lista cada
  imagen.
- `tools.engines[].preparation[]`: acciones `toolchain:<motor>` con la base y su
  digest resuelto, `db:*` y `adapter:*`.
- `coverage.limitations[]`: incluye la red del contenedor de toolchain y los
  fallos de preparación. Una limitación no implica `partial` por sí sola; revisa
  también `coverage.partial` y `errors`.

Un adaptador en contenedor declara `isolation: configured`, nunca `enforced`.
`--require-isolation enforced` falla antes de analizar si algún adaptador del
proyecto solo ofrece `configured`, incluido el modo contenedor.

```json
{
  "schema_version": "1.1.0",
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
- En modo `--offline`, prepara antes las bases con `cgc-scan update-db` y deja
  construidas las imágenes de toolchain (`scan` una vez con red o
  `docker pull`/`docker build` en el runner). `--offline` no descarga ni
  construye imágenes.
- Si el pipeline no tiene Docker, instala los toolchains en la imagen del runner
  o usa `CGC_SCAN_TOOLCHAIN=host` explícitamente.
- No uses `--require-isolation enforced` si el proyecto necesita adaptadores de
  host o de toolchain; el escaneo fallará antes de analizar, por diseño.
- Fija la versión de CGC Scan y las versiones de motores del manifiesto. La
  imagen base del lenguaje se fija por el digest que el reporte registra; si
  necesitas reproducibilidad estricta, conserva el JSON de preparación.

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
