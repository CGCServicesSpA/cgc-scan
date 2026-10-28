# Uso

## Comandos

```bash
cgc-scan setup [--trivy-mode docker|global] [--semgrep enable|disable] [--non-interactive]
cgc-scan doctor [--format text|json]
cgc-scan scan [ruta] [flags]
cgc-scan compare <anterior.json> <actual.json> [--format json|text]
cgc-scan update-db
cgc-scan recipes [--format text|json]
cgc-scan recipes --set <archivo.toml>
cgc-scan recipes --clear
cgc-scan --version
cgc-scan help [comando]
```

Omitir la ruta en `scan` analiza el directorio actual. Se analizan los archivos
tal como están en disco, incluidos cambios sin commit y archivos nuevos. No se
hace `clone`, `fetch` ni ninguna operación remota.

## Flags de `scan`

| Flag | Efecto |
| --- | --- |
| `--format json\|text\|prompt` | Representación de salida; el escaneo es el mismo |
| `--fail-on critical\|high\|medium\|low\|info\|unknown` | Umbral; por defecto `high` |
| `--report-out <archivo>` | Guarda además el JSON canónico, de forma atómica y 0600 |
| `--trivy-mode docker\|global` | Fuerza la modalidad solo para esta ejecución |
| `--no-auto-install` | No descarga motores ni imágenes; si faltan, código 3 |
| `--offline` | Sin descargas ni consultas; valida antigüedad de bases |
| `--require-isolation configured\|enforced` | Nivel mínimo de aislamiento |
| `--include <patrón>` / `--exclude <patrón>` | Repetibles; delimitan rutas |
| `--timeout <duración>` | Tiempo máximo por invocación |
| `--concurrency <n>` | Invocaciones concurrentes (0 = automático) |
| `--confirm-recipes` | Detecta y confirma las recetas de test/build de las unidades del escaneo; solo añade las que faltan y las guarda en la configuración de usuario |
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
  [`schemas/report.schema.json`](../schemas/report.schema.json). Los campos
  volátiles están en `run`.
- **texto**: resumen legible con cobertura, motores y política; por hallazgo
  incluye paquete y versión corregida, identificadores, ubicación, motores,
  severidad original, prioridad, descripción, remediación y referencias. Sin
  color si no hay TTY o si `NO_COLOR` está definida.
- **prompt**: plantilla versionada para un agente de remediación. No ejecuta
  tests, build ni parches, y no llama a ningún modelo.

Los logs y el progreso van siempre a stderr. `--log-format json` produce logs
estructurados.

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

## Comparación

```bash
cgc-scan compare anterior.json actual.json --format json
```

Clasifica `new`, `persistent`, `resolved` y `not_evaluated`. Si el escaneo actual
es parcial o tiene errores, un hallazgo ausente queda como `not_evaluated`, nunca
como resuelto.

## `doctor` y `update-db`

`doctor` es solo diagnóstico: no descarga, no crea directorios ni toma bloqueos.
`update-db` actualiza Trivy (base, Java, checks) y las bases de Go y RustSec sin
montar ningún proyecto.
