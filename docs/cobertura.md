# Cobertura

CGC Scan nunca presenta un resultado limpio si la cobertura fue incompleta. La
sección `coverage` del reporte es el contrato que lo hace verificable.

## Modelo

| Campo | Significado |
| --- | --- |
| `partial` | `true` si y solo si hay una exclusión **elegida** o una restricción por `--include` |
| `exclusions[]` | Patrón y `origin`: `intrinsic`, `user`, `policy` o `cli` |
| `not_analyzed[]` | Unidades no analizadas y patrones aplicados |
| `units[]` | Estado por unidad: `requested`, `completed`, `skipped`, `failed` |
| `limitations[]` | Limitaciones que no caben en los estados |

Las exclusiones **intrínsecas** son contenido no analizable por definición
(`node_modules`, `vendor`, `.venv`, `target`, `dist`, `build`, `.next`,
`coverage`, `.git`, la salida de `--report-out`). No marcan el escaneo como
parcial.

Las exclusiones **elegidas** son las que provienen del usuario, de la política
del proyecto o de `--exclude`. Sí marcan parcialidad. `--include` también.

## Qué cubre cada motor

| Motor | Qué analiza | Estado si falta |
| --- | --- | --- |
| Trivy | Dependencias, secretos y configuraciones del árbol objetivo | `failed` y código 3 |
| govulncheck | Módulos Go, funciones alcanzables y avisos del toolchain | `requirement_missing` |
| ESLint | Reglas de seguridad en JavaScript y TypeScript | `requirement_missing` |
| Psalm | Taint en PHP (requiere `vendor/autoload.php`) | `requirement_missing` |
| cargo-audit | Advisories de `Cargo.lock` con RustSec local | `requirement_missing` |
| Bandit | Patrones inseguros en Python | `requirement_missing` |
| Semgrep CE | Reglas propias o del usuario; opcional | `disabled` si no se habilitó |

Un motor puede ejecutarse en el host o dentro de una imagen de toolchain. El
estado (`completed`, `skipped`, `failed`) significa lo mismo en ambos casos; para
distinguirlos usa `tools.engines[].mode` (`docker` para el contenedor),
`tools.engines[].image` y las acciones `toolchain:<motor>` de
`tools.engines[].preparation[]`. Un fallo de preparación de la imagen no se
convierte en un resultado limpio: la unidad cae al host o queda
`requirement_missing`.

Un motor `skipped` o `failed` se suma a `coverage` y marca la ejecución como
incompleta (código 3). Semgrep `disabled` es la excepción: no marca
incompletitud ni cambia el código de salida.

## Toolchains por lenguaje

Si el daemon local de Docker responde, cada adaptador se ejecuta dentro de una
imagen derivada de la imagen oficial del lenguaje, en la versión que declara el
proyecto:

| Lenguaje | Fuente de la versión | Imagen base |
| --- | --- | --- |
| Go | `go.mod` (`go` y `toolchain`) | `golang:<versión>` |
| Node/TypeScript | `.nvmrc`, `.node-version`, `engines.node` o `volta.node` | `node:<versión>` |
| PHP | `config.platform.php`, `require.php` o `.php-version` | `php:<versión>-cli` |
| Rust | `rust-version`, `rust-toolchain.toml` o `edition` | `rust:<versión>-slim` |
| Python | `requires-python`, `.python-version`, `runtime.txt` o `Pipfile` | `python:<versión>-slim` |

Cada imagen se construye una vez por combinación lenguaje/versión/herramienta,
se etiqueta de forma determinista (`cgc-scan/toolchain:...`) y se reutiliza. La
imagen base se fija en el momento de la construcción por su digest y el reporte
lo registra; como no está en `manifest/trust.json`, se declara como limitación.

El proyecto se monta en `/src` en solo lectura y la red del contenedor queda
habilitada para resolver dependencias del proyecto. Por eso el motor declara
`isolation: configured`, nunca `enforced`. Las bases locales (Go, RustSec) y la
configuración de Psalm se montan desde un directorio temporal compartido con el
daemon; los cachés de cada lenguaje viven en volúmenes `cgc-scan-toolchain-*`
propios del usuario.

Sin Docker se mantiene el comportamiento anterior: se usan los toolchains del
host y, si falta alguno, la unidad queda sin analizar con
`requirement_missing`. `--offline` y `--no-auto-install` reutilizan imágenes ya
construidas y nunca descargan ni construyen otras. La variable
`CGC_SCAN_TOOLCHAIN=host` fuerza el uso de los toolchains del equipo para una
operación de emergencia.

## Requisitos de Composer

Psalm sigue exigiendo `vendor/autoload.php` en la unidad. El contenedor monta el
proyecto en solo lectura, así que `composer install` sigue siendo un paso
previo del usuario: la CLI nunca escribe en el proyecto.

## Exclusiones y motores

El conjunto efectivo de exclusiones viaja en el plan. Trivy recibe
`--skip-dirs/--skip-files`, ESLint `--ignore-pattern`, Psalm `ignoreFiles`,
Bandit y Semgrep sus opciones de exclusión. Un adaptador que no puede expresar
una exclusión debe declararlo en `Requirements()` para no escanear contenido que
la CLI declaró excluido.

## Verificación por hallazgo

Cada hallazgo incluye `verification`:

- `recipes`: recetas de test/build **confirmadas** para su unidad.
- `suggested`: candidatos detectados en los manifiestos, marcados como no
  confiables hasta que el usuario los confirme.
- `missing`: recetas que faltan; si hay alguna, `status` es `blocked`.
- `rescan`: comando para volver a analizar el ámbito de la unidad con la misma
  modalidad y modo offline.
- `note`: explica el bloqueo o, para secretos, que hace falta revocar y rotar.

Un secreto nunca se declara `ready`: el reescaneo por sí solo no valida la
rotación.

## Cómo leer un reporte parcial

1. Revisa `coverage.partial` y `coverage.not_analyzed`.
2. Comprueba qué motores quedaron `skipped`/`failed`.
3. No interpretes `resolved` en `compare` si el escaneo actual es parcial.
4. Un hallazgo ausente en un escaneo parcial es `not_evaluated`, no resuelto.

## Reproducibilidad

Dos ejecuciones con las mismas entradas, versiones y bases producen el mismo
documento salvo `run` (ID, fechas, duración) y los campos derivados del tiempo
(`tools.engines[].duration_ms`, `db.age_seconds`). Los hallazgos se ordenan por
severidad normalizada, priorización y fingerprint.
