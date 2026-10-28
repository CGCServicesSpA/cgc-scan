# Benchmarks y valores por defecto

> Medición del 27-10-2026 en macOS 27, Apple Silicon (arm64), Docker 29.9.2,
> Trivy 0.76.1, base de vulnerabilidades caliente y caché de motores preparada.
> Dos ejecuciones por caso, `--offline --format json`, modalidad Docker.

| Caso | Contenido | Media | Rango |
| --- | --- | --- | --- |
| Pequeño | Fixture Go con 1 módulo y 5 CVEs | 4,46 s | 4,15–4,76 s |
| Mediano | Monorepo de 3 unidades (Go, JS, Python) | 8,33 s | 7,62–9,05 s |
| Grande | Repositorio de la propia CLI (varios módulos y fixtures) | 43,6 s | 41,6–45,7 s (ejecución incompleta por govulncheck) |

El caso grande quedó incompleto: `govulncheck` no pudo cargar el módulo raíz en
modo offline por la resolución del toolchain. Es el comportamiento correcto
(código 3 y cobertura declarada), no un resultado limpio. No se usa para fijar
metas de rendimiento.

## Lectura

- El coste dominante es el arranque de contenedores y el análisis de dependencias,
  no el parseo del reporte.
- La primera preparación incluye la descarga de la base de Trivy (~1,6 GB) y no
  se parece a estas cifras; el volumen/caché la reutiliza en las siguientes.
- Semgrep añade un contenedor por unidad; en proyectos pequeños el coste fijo es
  visible.
- No se midieron Linux, amd64, el runner global ni proyectos de más de 50 000
  archivos. Queda pendiente ampliar la matriz (H7-01).

## Valores por defecto

| Parámetro | Valor | Razón |
| --- | --- | --- |
| Concurrencia | `min(GOMAXPROCS, 4)`; flag `--concurrency` | Evita saturar I/O y Docker sin serializar |
| Timeout por invocación | 10 min | Cubre monorepos medianos; configurable con `--timeout` |
| Timeout de preparación de base | 20 min | La base inicial pesa ~1,6 GB |
| Tope de salida por motor | 64 MiB | Un reporte Trivy grande cabe; el exceso falla, no se trunca |
| Tope de stderr | 1 MiB | Diagnóstico suficiente sin crecer sin control |
| Aviso de antigüedad de base | 72 h | Dato operativo razonable |
| Bloqueo offline | 168 h | Evita bases rancias sin impedir trabajo diario |

Los valores se revisan cuando existan medidas de Linux/amd64 y proyectos grandes.
