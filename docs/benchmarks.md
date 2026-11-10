# Benchmarks y valores por defecto

> Medición del 27-10-2026 en macOS 27, Apple Silicon (arm64), Docker 29.9.2,
> Trivy 0.76.1, base de vulnerabilidades caliente y caché de motores preparada.
> Dos ejecuciones por caso, `--offline --format json`, modalidad Docker. Las
> mediciones se tomaron con Go 1.26.10; tras actualizar a **Go 1.27.3** se repitió
> el caso global en caliente: 0,78–0,81 s por ejecución.
>
> **Nota (v1.2):** estas cifras corresponden al modo host de los adaptadores
> (toolchains instalados en el equipo). Con imágenes de toolchain, el arranque
> incluye el contenedor del lenguaje; la primera ejecución además descarga la
> imagen base y construye la derivada. Ver la sección siguiente.

| Caso | Contenido | Media | Rango |
| --- | --- | --- | --- |
| Pequeño | Fixture Go con 1 módulo y 5 CVEs | 4,46 s | 4,15–4,76 s |
| Mediano | Monorepo de 3 unidades (Go, JS, Python) | 8,33 s | 7,62–9,05 s |
| Grande | Repositorio de la propia CLI (varios módulos y fixtures) | 43,6 s | 41,6–45,7 s (ejecución incompleta por govulncheck) |
| Global (mismo fixture pequeño) | Runner global, caché caliente | 1,08 s | 0,96–1,27 s |

El caso grande quedó incompleto: `govulncheck` no pudo cargar el módulo raíz en
modo offline por la resolución del toolchain. Es el comportamiento correcto
(código 3 y cobertura declarada), no un resultado limpio. No se usa para fijar
metas de rendimiento.

## Toolchain por contenedor (v1.2)

Medición del 30-10-2026 en el mismo equipo, con las imágenes de toolchain ya
construidas y los volúmenes de caché calientes. No es una matriz: es una
referencia para dimensionar el coste fijo del contenedor del lenguaje.

| Escenario | Tiempo pared | Nota |
| --- | --- | --- |
| `scan . --engines govulncheck` sobre el repositorio de la CLI, `--no-cache` | ~23 s | imagen `go-1.27.3` caliente; el motor recorre todo el árbol |
| `scan <fixture Go> --engines govulncheck`, `--no-cache` | ~17 s | incluye el arranque del contenedor y la carga del módulo |
| Segunda ejecución del mismo fixture con caché de unidad | ~1–2 s | `cache: hit`; la imagen y el volumen ya existen |
| Primera ejecución en frío | 2–4 min | descarga de la base del lenguaje, build de la imagen derivada y preparación de bases |

El coste de la primera ejecución depende de la imagen base (Go y Rust pesan más
que Python slim) y de la red. En CI conviene construir las imágenes una vez y
usar `--offline` en las ejecuciones posteriores. Las cifras de la tabla anterior
siguen siendo válidas para el modo host (`CGC_SCAN_TOOLCHAIN=host`).

## Lectura

- El coste dominante es el arranque de contenedores y el análisis de dependencias,
  no el parseo del reporte.
- La primera preparación incluye la descarga de la base de Trivy (~1,6 GB) y no
  se parece a estas cifras; el volumen/caché la reutiliza en las siguientes.
- Semgrep añade un contenedor fijo por escaneo desde v1.1 (antes uno por unidad),
  así que en monorepos el coste fijo ya no crece con el número de módulos.
- El runner global es ~4× más rápido que Docker en el caso pequeño por el coste
  fijo del contenedor. En proyectos muy grandes el montaje de solo lectura de
  Docker Desktop puede invertir la relación.
- No se midieron proyectos de más de 50 000 archivos ni una matriz completa de
  Linux/amd64 con adaptadores. Queda pendiente ampliar la matriz (H7-01).
- Prueba de máquina limpia Linux/amd64 con el RC: `setup` global y `update-db`
  (Trivy, Java, checks, Go, RustSec) completaron; el escaneo offline produjo
  reporte y devolvió 3 porque el contenedor no tenía toolchain Go.

## Estado local y caché incremental (v1.1)

Medición local del 30-10-2026, macOS arm64, Trivy 0.76.1 global, fixture Go con
`golang.org/x/text v0.3.0`, Dockerfile y `.env`; base y espejo de Go ya
preparados y `--offline`:

| Escenario | Tiempo pared | Resultado |
| --- | --- | --- |
| `agent` primera ejecución (sin caché de proyecto) | 2,4 s | 8 hallazgos, 4 grupos, línea base creada |
| `agent` repetición sin cambios | 0,20 s | caché `hit` en Trivy y govulncheck |
| `verify rg-go-golang.org/x/text` con hallazgos presentes | ~0,8-2,1 s | `persistent`, reescaneo de Trivy + govulncheck |
| `verify` tras actualizar a `v0.41.0` y `go mod tidy` | 0,2 s | `resolved`, delta `resolved: 5` |
| `status` / `plan` / `explain` | < 0,1 s | leen estado, no escanean |

La repetición con caché evita el arranque de Trivy y el análisis de paquetes; el
coste restante es preparación y lectura de estado. Las cifras no sustituyen la
matriz de referencia multi-máquina (H7-01).

## Valores por defecto

| Parámetro | Valor | Razón |
| --- | --- | --- |
| Concurrencia | `min(GOMAXPROCS, 4)`; flag `--concurrency` | Evita saturar I/O y Docker sin serializar |
| Timeout por invocación | 10 min | Cubre monorepos medianos; configurable con `--timeout` |
| Timeout de preparación de base | 20 min | La base inicial pesa ~1,6 GB |
| Tope de salida por motor | 64 MiB | Un reporte Trivy grande cabe; el exceso falla, no se trunca |
| Tope de stderr | 1 MiB | Diagnóstico suficiente sin crecer sin control |
| Aviso de antigüedad de base | 72 h | Dato operativo razonable |
| Reutilización de base (`db.refresh_after`) | 12 h | Evita red en iteraciones del mismo día |
| Bloqueo offline | 168 h | Evita bases rancias sin impedir trabajo diario |

Los valores se revisan cuando existan medidas de Linux/amd64 y proyectos grandes.
