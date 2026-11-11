# Uso

## Comandos

```bash
cgc-scan setup [--trivy-mode docker|global] [--semgrep enable|disable] [--non-interactive]
cgc-scan doctor [--format text|json]
cgc-scan agent [ruta] [flags]
cgc-scan scan [ruta] [flags]
cgc-scan status [ruta] [--format text|json]
cgc-scan plan [ruta] [--format text|json]
cgc-scan explain <huella|grupo> [ruta] [--format text|json]
cgc-scan verify <huella|grupo> [ruta] [--format json|text]
cgc-scan compare <anterior.json> <actual.json> [--format json|text]
cgc-scan compare --baseline [ruta]
cgc-scan baseline <set|show|clear> [ruta]
cgc-scan update-db
cgc-scan recipes [--format text|json]
cgc-scan recipes --set <archivo.toml>
cgc-scan recipes --clear
cgc-scan --version
cgc-scan help [comando]
```

Omitir la ruta analiza el directorio actual. Se analizan los archivos tal como
están en disco, incluidos cambios sin commit y archivos nuevos. No se hace
`clone`, `fetch` ni ninguna operación remota, salvo la preparación de bases,
motores e imágenes de toolchain cuando no se usa `--offline`.

## Auditoría asistida

```bash
cgc-scan audit init [ruta] [--profile quick|standard|deep] [--budget N]
                   [--include PATRÓN ...] [--exclude PATRÓN ...] [--prior DIR]
                   [--out DIR] [--format text|json]
cgc-scan audit next [ruta] --agent <id> [--max-units N]
                    [--format json|text|prompt] [--out DIR]
cgc-scan audit submit [ruta] --file <entrega.json> [--format text|json] [--out DIR]
cgc-scan audit status [ruta] [--format text|json] [--out DIR]
cgc-scan audit explain [ruta] --coverage-id <id>|--fingerprint <huella>
                       [--format text|json] [--out DIR]
cgc-scan audit reset-unit [ruta] --coverage-id <id> --reason "..." [--out DIR]
cgc-scan audit report [ruta] [--format text|json] [--fail-on <umbral>]
                      [--verify] [--out DIR]
cgc-scan audit compare <corrida-anterior> <corrida-actual> [--format text|json]
cgc-scan audit import [ruta] --file <reporte.json> [--format text|json] [--out DIR]
cgc-scan audit catalog status
cgc-scan audit catalog activate --file <catalogo-firmado.json>
```

Flujo típico (quick, una pasada de verificación):

```bash
cgc-scan audit init . --profile quick --budget 12
cgc-scan audit next . --agent hunter-a --format json      # asignación de caza
# el agente caza y guarda su entrega en entrega.json
cgc-scan audit submit . --file entrega.json
cgc-scan audit next . --agent verifier-a --format json    # verificación independiente
cgc-scan audit submit . --file verificacion.json
cgc-scan audit report .                                   # sella y deriva los reportes
cgc-scan audit report . --verify                          # integridad sin reescritura
```

Notas de uso:

- El directorio de la corrida vive por defecto en el estado del proyecto, nunca
  dentro del árbol analizado; `--out DIR` exige un destino externo o ignorado
  por Git.
- Los perfiles cambian la granularidad y las fases, nunca el listón de
  evidencia: `quick` colapsa por subsistema × dominio con una pasada;
  `standard` por frontera × clase con dos pasadas y crítica; `deep` por ciclo
  de vida y además revalida lo que la corrida `--prior` dejó con la fuente
  cambiada.
- `--budget N` cuenta invocaciones de agente en todas las fases y reserva las
  obligatorias antes de repartir caza; el agotamiento difiere y sella la
  corrida como incompleta (código 3).
- `--fail-on` (solo `audit report`): `confirmed`, `needs_validation` o una
  severidad auditada (`informational|low|medium|high|critical`); una corrida
  incompleta siempre devuelve 3 antes de evaluar el umbral.
- Si un agente abandona una unidad, `audit reset-unit` la devuelve a `planned`
  archivando el intento como `blocked`.
- `audit import --file reporte.json` convierte hallazgos de un escaneo en
  leads pendientes de caza; nunca aparecen como confirmados.
- El catálogo de clases embebido se puede actualizar solo con un sobre firmado
  local (`audit catalog activate`); no hay descarga remota.

## Toolchains por contenedor

Con Docker local disponible, `scan`, `agent` y `verify` ejecutan govulncheck,
ESLint, Psalm, cargo-audit y Bandit dentro de una imagen derivada de la imagen
oficial del lenguaje, en la versión que declara el proyecto (`go.mod`,
`package.json`/`.nvmrc`, `composer.json`, `Cargo.toml`, `pyproject.toml`). El
proyecto se monta en solo lectura y la red del contenedor se habilita para
resolver dependencias, así que el reporte declara `isolation: configured`.

- La primera ejecución descarga la imagen base y construye la imagen derivada
  con la herramienta fijada en el manifiesto. Las siguientes reutilizan la
  imagen (`cgc-scan/toolchain:<lenguaje>-<versión>-<motor>-<versión>`).
- La base se fija por el digest resuelto al construir y el reporte lo registra
  en `preparation`; no está fijada en `manifest/trust.json`.
- `--offline` y `--no-auto-install` nunca descargan ni construyen imágenes.
- `CGC_SCAN_TOOLCHAIN=host` fuerza el uso de los toolchains del equipo.
- Sin Docker, o si una imagen no se puede preparar, la unidad cae al toolchain
  del host y, si tampoco está, queda omitida con cobertura parcial.

En el reporte, un adaptador en contenedor se reconoce por `mode: docker`, la
etiqueta en `tools.engines[].image` y una preparación como esta:

```json
{
  "id": "govulncheck",
  "mode": "docker",
  "status": "completed",
  "image": "cgc-scan/toolchain:go-1.22.3-govulncheck-1.9.0",
  "preparation": [
    { "action": "db:go-vulndb", "status": "ok" },
    { "action": "toolchain:govulncheck", "status": "ok",
      "detail": "cgc-scan/toolchain:go-1.22.3-govulncheck-1.9.0 con base golang:1.22.3@sha256:... (no fijada en el manifiesto)" }
  ]
}
```

Si la preparación falla, `preparation` trae `status: failed` con el motivo y
`coverage.limitations` lo repite. El adaptador cae al host; si el toolchain
tampoco está, la unidad queda `requirement_missing` y el código de salida es 3.
Para diagnosticar un problema de imagen, ejecuta con `CGC_SCAN_TOOLCHAIN=host`:
si el adaptador funciona, el problema está en Docker o en la versión detectada,
no en el proyecto.

La resolución de dependencias dentro del contenedor revela nombres y versiones
de paquetes al registro público del ecosistema, nunca el código. Usa
`--offline` o `CGC_SCAN_TOOLCHAIN=host` si el equipo no lo permite.

## Flujo para agentes

```bash
cgc-scan agent .                     # una vez: escaneo + grupos + delta + acciones
cgc-scan explain <grupo|huella>      # detalle solo si hace falta
cgc-scan verify <grupo>              # tras el parche, solo lo afectado
cgc-scan status                      # resumen sin escanear
```

`agent` emite `agent-1.0.0`, guarda `latest.json` e `index.json` en la caché del
proyecto y crea la línea base en la primera ejecución. `scan` mantiene el JSON
canónico completo `report-1.1.0`.

## Flags de `scan` y `agent`

| Flag | Efecto |
| --- | --- |
| `--format json\|text\|prompt\|agent` | Representación; `agent` solo en `scan` |
| `--fail-on critical\|high\|medium\|low\|info\|unknown` | Umbral; por defecto `high` |
| `--report-out <archivo>` | Guarda además el JSON canónico, de forma atómica y 0600 |
| `--trivy-mode docker\|global` | Fuerza la modalidad solo para esta ejecución |
| `--no-auto-install` | No descarga motores, imágenes ni construye toolchains; si faltan, código 3 |
| `--offline` | Sin descargas, builds ni consultas; usa solo imágenes y bases locales |
| `--require-isolation configured\|enforced` | Nivel mínimo de aislamiento; los adaptadores en contenedor de toolchain siempre ofrecen `configured` |
| `--include <patrón>` / `--exclude <patrón>` | Repetibles; delimitan rutas |
| `--only deps,secrets,code,config` | Escaneo parcial por categoría |
| `--engines <lista>` | Solo los motores indicados |
| `--changed` | Solo unidades con cambios desde la línea base (Git local) |
| `--no-cache` | Ignora la caché incremental por unidad y motor |
| `--max-groups <n>` | Limita grupos en `agent`; el resumen declara el truncamiento |
| `--min-severity <sev>` | Filtro de vista para texto/agent; no altera la política ni el JSON canónico |
| `--timeout <duración>` | Tiempo máximo por invocación |
| `--concurrency <n>` | Invocaciones concurrentes (0 = automático) |
| `--confirm-recipes` | Detecta y confirma recetas de test/build; solo añade las que faltan |
| `--quiet` / `--verbose` | Progreso mínimo o detallado |
| `--log-format text\|json` | Formato de logs en stderr |

No existen `--ai`, `analyze` ni parámetros de inferencia. Un parámetro no
soportado devuelve código 2; no se ignora.

## Códigos de salida

| Código | Significado |
| --- | --- |
| 0 | Plan completado sin incumplir el umbral |
| 1 | Plan completado e incumplimiento de política |
| 2 | Argumentos o configuración inválidos antes de preparar |
| 3 | Ejecución incompleta o fallida (incluye preparación y aislamiento) |
| 130 | Cancelación por SIGINT/SIGTERM |

La prioridad es 130 → 2 → 3 → 1 → 0. El JSON conserva el resultado de política y
el de ejecución aunque el proceso devuelva un solo código.

## Formatos

- **JSON**: un único documento por stdout, validado contra
  [`schemas/report.schema.json`](../schemas/report.schema.json) (`report-1.1.0`).
  Los campos volátiles están en `run`. Incluye `remediation_groups`,
  `next_actions` y, si hay línea base, `delta`.
- **texto**: resumen legible con cobertura, motores y política; por hallazgo
  incluye paquete y versión corregida, identificadores, ubicación, motores,
  severidad original, prioridad, descripción, remediación y referencias. Sin
  color si no hay TTY o si `NO_COLOR` está definida.
- **prompt**: plantilla versionada para un agente de remediación. No ejecuta
  tests, build ni parches, y no llama a ningún modelo.
- **agent**: documento compacto `agent-1.0.0` contra
  [`schemas/agent.schema.json`](../schemas/agent.schema.json). Solo resumen,
  grupos, acciones, delta, bloqueos y `report_path`; las descripciones y
  referencias se piden con `explain`. El truncamiento por `--max-groups` se
  declara en `summary.truncated` y `summary.groups_total`.

Los logs y el progreso van siempre a stderr. `--log-format json` produce logs
estructurados.

## Estado local por proyecto

El estado vive fuera del proyecto, en la caché:

```text
<cache>/cgc-scan/projects/<local_id>/
  latest.json      último reporte canónico
  baseline.json    línea base
  index.json       huella -> grupo/unidad/motor
  units/           resultados por unidad y motor
  cache/units/     caché incremental con su clave
```

Los archivos se escriben de forma atómica con permisos 0600 y los directorios
0700. `status`, `plan`, `explain`, `verify` y `compare --baseline` funcionan
sobre este estado sin repetir el escaneo completo. `cgc-scan baseline set|show|clear`
permite fijar, inspeccionar o borrar la línea base; `agent` la crea en su primera
ejecución.

## Caché incremental y bases

- La clave combina versión del motor, versión/fecha de la base, configuración
  efectiva y el hash de manifiestos/lockfiles o del árbol fuente de la unidad.
- Los motores de dependencias se invalidan sobre todo con lockfiles; los de
  código con el árbol fuente; Trivy con ambos y la base.
- `tools.engines[].cache` y las entradas por unidad declaran `hit|miss|mixed|disabled`.
- `--no-cache` fuerza la ejecución completa.
- `db.refresh_after` (12 h por defecto) reutiliza la base dentro del plazo sin
  consultar la red y el reporte muestra su antigüedad. `update-db` siempre
  actualiza.

## Selección de rutas

```bash
cgc-scan scan . --include 'services/**' --exclude '**/fixtures/**'
```

- Los patrones admiten `**`.
- Las exclusiones prevalecen sobre las inclusiones.
- Las exclusiones intrínsecas (`node_modules`, `vendor`, `target`, `.git`, etc.)
  no se pueden desactivar.
- `--exclude` **reemplaza** las exclusiones del proyecto y de la configuración
  del usuario; las intrínsecas se conservan.
- Todo recorte elegido marca `coverage.partial` y enumera lo no analizado en
  `coverage.not_analyzed`.

## Política del proyecto

`cgc-scan.toml` en la raíz detectada del proyecto. Es dato no confiable: solo
puede agregar exclusiones y excepciones, y endurecer el umbral.

```toml
fail_on = "critical"
exclude = ["docs/examples/**"]

[[exception]]
fingerprint = "3fa19c0e5b7d4a21c8d6e0f19a2b4c77"
reason = "No alcanzable: la función afectada no se invoca"
owner = "equipo-seguridad"
expires = 2027-01-31
```

Las claves prohibidas se ignoran y se registran en `errors`. Una excepción sin
`expires` se rechaza; las vencidas dejan de suprimir y siguen visibles en el
reporte.

## Recetas de validación

La única fuente de recetas de confianza es la configuración de usuario,
confirmada explícitamente:

```bash
cgc-scan recipes                     # candidatos detectados y recetas confirmadas
cgc-scan recipes --set ./recetas.toml
cgc-scan recipes --clear
```

Para no preparar el archivo a mano, la primera vez puedes confirmar los
candidatos en el mismo escaneo:

```bash
cgc-scan scan backoffice --trivy-mode global --confirm-recipes
```

`--confirm-recipes` solo añade las recetas que faltan (no sobrescribe comandos
ya confirmados), las guarda en la configuración de usuario y las usa en ese
mismo escaneo. Los escaneos posteriores ya no necesitan el flag.

Formato de `--set`:

```toml
[[recipes]]
unit = "svc/api"
[recipes.test]
command = "npm test"
workdir = "svc/api"
[recipes.build]
command = "npm run build"
workdir = "svc/api"
```

`project` se completa con la raíz actual. `--set` actualiza solo las unidades
declaradas en el archivo: confirmar una unidad no borra las recetas de las demás.
Sin receta confirmada, el prompt y el
reporte declaran la validación de esa unidad como bloqueada; nunca inventan un
comando. Cada hallazgo incluye `verification` con las recetas confirmadas
aplicables a su unidad, los candidatos detectados como `suggested` (no son de
confianza hasta confirmarlos), las recetas faltantes y el comando de reescaneo.

## Configuración de usuario

`<config>/cgc-scan/config.toml` (0600) guarda `trivy_mode`, `semgrep_enabled`,
las recetas confirmadas y la política de bases:

```toml
trivy_mode = "global"
semgrep_enabled = false

[db]
warn_after = "72h"
block_after_offline = "168h"
refresh_after = "12h"
```

Dentro de `refresh_after` las bases se reutilizan sin consultar la red; el
reporte muestra su antigüedad. `cgc-scan update-db` siempre fuerza la
actualización.

## Comparación

```bash
cgc-scan compare anterior.json actual.json --format json
cgc-scan compare --baseline . --format json
```

Clasifica `new`, `persistent`, `resolved` y `not_evaluated`. Si el escaneo actual
es parcial o tiene errores, un hallazgo ausente queda como `not_evaluated`, nunca
como resuelto. `--baseline` usa `latest.json` y `baseline.json` del proyecto, sin
rutas ni escaneo.

## Verificación focalizada

```bash
cgc-scan verify rg-go-golang.org/x/text .
cgc-scan verify 0123456789abcdef0123456789abcdef .
```

`verify` resuelve la unidad y los motores desde el índice, reescanea solo ese
alcance, fusiona el resultado en `latest.json` y devuelve `resolved`,
`persistent` o `partial` por huella. No ejecuta recetas ni comandos de
aplicación. Su código de salida es el del escaneo focalizado: otros hallazgos del
mismo alcance pueden devolver 1.

## `doctor` y `update-db`

`doctor` es solo diagnóstico: no descarga, no crea directorios ni toma bloqueos.
`update-db` actualiza Trivy (base, Java, checks) y las bases de Go y RustSec sin
montar ningún proyecto.
