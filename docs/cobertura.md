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

Un motor `skipped` o `failed` se suma a `coverage` y marca la ejecución como
incompleta (código 3). Semgrep `disabled` es la excepción: no marca
incompletitud ni cambia el código de salida.

## Requisitos que no se instalan

Los toolchains de los proyectos no se instalan: Go, Node, PHP/Composer,
Rust/Cargo y Python deben estar presentes. Si falta uno, la unidad queda sin
analizar y el reporte lo dice. Esto incluye el caso de PHP con `composer.json`
pero sin `composer install`: Psalm se omite con `requirement_missing`.

## Exclusiones y motores

El conjunto efectivo de exclusiones viaja en el plan. Trivy recibe
`--skip-dirs/--skip-files`, ESLint `--ignore-pattern`, Psalm `ignoreFiles`,
Bandit y Semgrep sus opciones de exclusión. Un adaptador que no puede expresar
una exclusión debe declararlo en `Requirements()` para no escanear contenido que
la CLI declaró excluido.

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
