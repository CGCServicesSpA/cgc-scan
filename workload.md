# CGC Scan — Workload v1.0

> **Versión:** 1.1 (borrador para revisión) · **Fecha:** 27 de octubre de 2026
> **Complementa:** `requisitos-cli-seguridad.md` v0.10 (**PRD**) y `design.md` v1.1 (**Design Doc**)
> **Alcance:** todas las tareas para completar CGC Scan v1 de principio a fin, desde las decisiones previas hasta la publicación de v1.0.0, más el backlog posterior.

Este documento responde a "¿qué hay que hacer y en qué orden?". No redefine requisitos ni diseño: cada tarea referencia el requisito (RF), el criterio de aceptación (CA), la decisión (ADR u O-) o el riesgo que la origina.

---

## 1. Convenciones

| Elemento | Definición |
| --- | --- |
| ID de tarea | `P-nn` (preparación) o `Hn-nn` (hito de ingeniería). Los IDs no se reutilizan |
| Tipo | Decisión, Spike (código descartable para validar), Dev, Test, Doc, Ops, Legal, Release |
| Esfuerzo | Días-persona de un único desarrollador, **incluyendo sus pruebas y documentación mínima**. Estimación *Propuesta*, sin benchmarks, con incertidumbre de ±30 % |
| Depende de | Tareas que deben estar terminadas antes de empezar. Sin dependencias circulares (verificado al generar este documento) |
| Refs | Origen de la tarea: RF y CA del PRD, secciones, ADR, riesgos T- y R-, o preguntas abiertas O- |
| Estado | `[ ]` pendiente · `[~]` en curso · `[x]` terminada |
| P2 | Tarea opcional, fuera de los totales de v1 |

**Definición de terminado (aplica a toda tarea de tipo Dev, Test y Release):**

1. El código y las pruebas están en la rama principal con la CI en verde (build, `-race`, linters, `govulncheck`).
2. Los criterios de aceptación citados en la tarea pasan, o la tarea de pruebas del hito los cubre.
3. No se escribe en stdout fuera de `report`, y los datos no confiables pasan por `masking`.
4. Si cambia un contrato (JSON, flags, códigos de salida), se actualizan el esquema y el PRD en el mismo cambio.
5. Si la tarea modifica una decisión técnica, se actualiza el registro de decisiones del Design Doc.

---

## 2. Resumen y calendario

| Hito | Nombre | Tareas | Días-persona | Gate (criterio de salida) |
| --- | --- | --- | --- | --- |
| P | Preparación: decisiones y spikes | 12 | 15 | Decisiones registradas en PRD y design.md; spikes documentados; ningún bloqueo abierto para H1. |
| H0 | Fundaciones: repositorio, CI y esqueleto | 12 | 14 | CI verde en la matriz; `cgc-scan --version` y códigos de salida probados; esquema validado; linters activos. |
| H1 | Rebanada vertical: scan de Go con Trivy global | 12 | 22 | `cgc-scan scan` sobre un fixture Go produce JSON válido contra el esquema, determinista y con cobertura declarada. |
| H2 | Runner Docker, caché y bases | 11 | 18 | El mismo escaneo funciona con Docker y con `--offline`; la matriz de runner y los bloqueos están probados. |
| H3 | Setup, configuración y política del proyecto | 10 | 17.5 | `setup` funciona en máquinas limpias de macOS y Linux, interactivo y no interactivo; `doctor` y política del proyecto operativos. |
| H4 | Adaptadores por lenguaje y monorepos | 15 | 42 | Los seis lenguajes y un monorepo mixto reportan cobertura honesta; una herramienta faltante nunca produce un resultado limpio. |
| H5 | Política, comparación y formato prompt | 11 | 22.5 | Los tres formatos entregan el mismo escaneo; el prompt es consumible por un agente; códigos de salida completos. |
| H6 | Semgrep opcional, aislamiento y release | 10 | 20 (+3 P2) | Semgrep opcional funciona solo tras `setup`; las pruebas de aislamiento pasan; artefactos firmados con SBOM y procedencia. |
| H7 | Endurecimiento, documentación y lanzamiento | 12 | 26.5 | Matriz de aceptación completa registrada, documentación publicada y v1.0.0 disponible. |
| **Total** | | **105** | **197.5** (+3 P2) | |

**Contingencia sugerida (Propuesto):** +15 % (29.6 días) para cambios que surjan de los spikes y de la primera integración con cada motor. Total con contingencia: **227.1 días-persona**.

### 2.1 Duración según dedicación

| Días productivos por semana | Sin contingencia | Con contingencia |
| --- | --- | --- |
| 5 | 40 semanas (≈ 9.2 meses) | 45 semanas (≈ 10.4 meses) |
| 4 | 49 semanas (≈ 11.3 meses) | 57 semanas (≈ 13.1 meses) |
| 3 | 66 semanas (≈ 15.2 meses) | 76 semanas (≈ 17.5 meses) |
| 2 | 99 semanas (≈ 22.8 meses) | 114 semanas (≈ 26.2 meses) |

Con un único desarrollador las tareas se ejecutan en serie; la tabla supone que no hay otro trabajo en paralelo. Si la dedicación es compartida con otros productos, usa la fila que corresponda a los días reales por semana.

### 2.2 Ruta crítica

Con recursos ilimitados, la cadena más larga de dependencias suma **32 días**; con una sola persona manda el total de la tabla anterior. La cadena es:

`P-06 → H0-01 → H0-02 → H1-01 → H1-02 → H4-02 → H4-03 → H4-15 → H5-03 → H5-10 → H7-01 → H7-04 → H7-11 → H7-12`

Lectura práctica: esa cadena solo importaría con varias personas trabajando en paralelo. Con un único desarrollador la duración real es la suma de todas las tareas (tabla 2.1); lo útil de la ruta crítica es saber qué no se puede reordenar: decidir licencias y nombre antes de crear el repositorio, y fijar el contrato JSON antes de los formatos de salida.

La cadena pasa ahora por la infraestructura de aprovisionamiento de los adaptadores (H4-02) porque la selección de rutas (H4-15) necesita traducir las exclusiones a los mecanismos de cada motor (H4-03). Reordenar H4 para ejecutar la selección antes que el resto de los adaptadores es posible, pero entonces `compare` (H5-03) quedaría esperando a una infraestructura de motores que no se necesita para comparar.

### 2.3 Reglas de ejecución

1. **Orden de hitos:** P → H0 → H1 → H2 → H3 → H4 → H5 → H6 → H7. Dentro de un hito se respeta `Depende de`.
2. **Una tarea en curso a la vez** (límite de trabajo en curso = 1), salvo tareas de espera de CI o de descargas.
3. **No se abre un hito hasta cumplir el gate del anterior**, salvo que la tarea dependa solo de tareas ya terminadas. Ejemplo: los spikes P-07 a P-11 se hacen mientras se esperan las respuestas de P-03 (nombre) y P-06 (licencias), que sí deben cerrarse antes de crear el repositorio (H0-01).
4. **Re-estimar** al cerrar H1 y al cerrar H4: con datos reales se corrige el resto del calendario.
5. **Versiones de motores fijadas al empezar H1.** Se actualizan solo con una tarea explícita que repita P-07, P-09 y la prueba de aislamiento (H6-05).
6. **Orden recomendado dentro de H4:** Go, JavaScript y TypeScript, Python, Rust y por último PHP, por dificultad creciente de la herramienta (Psalm exige PHP, Composer y dependencias instaladas). El alcance de seis lenguajes en v1 no cambia (PRD §4.1).

---

## 3. Hitos y tareas

### Hito P — Preparación: decisiones y spikes

**Objetivo:** Cerrar las decisiones abiertas y validar con código descartable lo que más puede cambiar el diseño.

**Gate:** Decisiones registradas en PRD y design.md; spikes documentados; ningún bloqueo abierto para H1.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| P-01 | Decidir cómo se obtienen las herramientas de los adaptadores (ESLint, Psalm, Bandit, cargo-audit, govulncheck): aprovisionamiento verificado, sin scripts de instalación | Decisión | — | 0.5 | design O-1, §8.1; T-04 | [ ] |
| P-02 | Decidir repositorio público o privado y plataforma de CI (define firmas sin clave y SLSA) | Decisión | — | 0.5 | design O-5 | [ ] |
| P-03 | Verificar disponibilidad del nombre `cgc-scan`: paquetes, dominio y marca en INAPI; fijar el nombre definitivo | Decisión | — | 1 | PRD §15 | [ ] |
| P-04 | Cerrar defaults pendientes: umbral `--fail-on`, antigüedad de bases, trato de archivos ignorados por Git (`.env`), prioridad 3 sobre 1, lotes del prompt y nombre del archivo de política del proyecto | Decisión | — | 1 | PRD §15; design O-4 | [ ] |
| P-05 | Decidir runner de Semgrep (¿sigue a Trivy?) y quién mantiene las reglas propias de CGC con qué licencia | Decisión | — | 0.5 | PRD §5.2, §15 | [ ] |
| P-06 | Revisión de licencias: Trivy, adaptadores, reglas, dependencias Go y licencia de la propia CLI | Legal | — | 1.5 | PRD R3, §12 | [ ] |
| P-07 | Spike Trivy: validar flags reales (fs, offline, descarga de bases, base Java, checks, desactivar comprobación de versión) contra la versión candidata | Spike | — | 2 | design T-01, §6.1 | [ ] |
| P-08 | Spike Docker: propiedad de archivos del volumen de caché (root y no root) en Linux y Docker Desktop macOS | Spike | — | 1.5 | design T-02, O-3 | [ ] |
| P-09 | Spike aislamiento `configured`: comprobar con `strace` que Trivy no abre conexiones con las opciones previstas | Spike | P-07 | 1.5 | PRD R1; design §6.2 | [ ] |
| P-10 | Spike govulncheck: base local y evaluar uso como biblioteca (`golang.org/x/vuln/scan`) | Spike | — | 1 | design O-2 | [ ] |
| P-11 | Spike adaptadores: invocación y formato de salida de ESLint (JS y TSX), Psalm (taint), cargo-audit (base local) y Bandit sobre fixtures mínimos | Spike | P-01 | 3 | PRD §5; design §8 | [ ] |
| P-12 | Actualizar PRD y design.md con las decisiones y hallazgos de la fase; registrar cambios | Doc | P-01, P-02, P-03, P-04, P-05, P-06, P-07, P-08, P-09, P-10, P-11 | 1 | — | [ ] |
| | **Subtotal P** | | | **15** | | |

### Hito H0 — Fundaciones: repositorio, CI y esqueleto

**Objetivo:** Base de ingeniería: repositorio, CI, linters, rutas, escritura atómica, esquema del reporte y esqueleto de comandos.

**Gate:** CI verde en la matriz; `cgc-scan --version` y códigos de salida probados; esquema validado; linters activos.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H0-01 | Crear repositorio, licencia, README, SECURITY.md y CONTRIBUTING | Ops | P-02, P-03, P-06 | 0.5 | PRD §6.7 | [ ] |
| H0-02 | `go mod init`, fijar versión de Go y `toolchain`, crear estructura de paquetes | Dev | H0-01 | 0.5 | design §3 | [ ] |
| H0-03 | CI: build y pruebas en matriz linux/macOS × amd64/arm64 con `-race` | Ops | H0-02 | 1.5 | design §15 | [ ] |
| H0-04 | Linters y seguridad de la propia CLI: golangci-lint (gosec, errcheck, forbidigo para stdout), staticcheck, vet, `go mod verify`, govulncheck | Ops | H0-03 | 1 | design §15.3; CA-08 | [ ] |
| H0-05 | `main`: `signal.NotifyContext`, `slog` hacia stderr, tipo `ExitError`, `os.Exit` único | Dev | H0-02 | 1 | design §11 | [ ] |
| H0-06 | `policy.Decide` con pruebas de tabla de los códigos 0, 1, 2, 3 y 130 | Dev | H0-05 | 0.5 | PRD §8.1; design §5.4 | [ ] |
| H0-07 | `platform/paths`: ubicaciones por plataforma, variables `CGC_SCAN_*_DIR` | Dev | H0-02 | 1 | design §4.1 | [ ] |
| H0-08 | Escritura atómica (temporal, `fsync`, `os.Rename`) y helpers de permisos 0600/0700 | Dev | H0-07 | 0.5 | RF-35; design §4.3 · CA-55 | [ ] |
| H0-09 | Esquema JSON del reporte v1.0.0, embebido, con validación en pruebas; declarar desde el inicio `coverage.partial`, `coverage.not_analyzed`, el origen de cada exclusión y la sección `validation` | Dev | H0-02 | 3 | PRD §9; ADR-06; RF-14, RF-37 | [ ] |
| H0-10 | Esqueleto de `testdata/fixtures`, convención de archivos de referencia y helper que ignora campos volátiles | Test | H0-09 | 1 | design §15.1 | [ ] |
| H0-11 | `masking`: enmascarado de secretos y saneado de texto (control, ANSI, bidi), con fuzzing | Dev | H0-02 | 1.5 | design §10.3, §13 | [ ] |
| H0-12 | Cobra: comandos `setup`, `doctor`, `scan`, `compare`, `update-db`, `recipes`, `--version`, ayuda, completado, `NO_COLOR`, TTY; parámetro desconocido devuelve código 2 | Dev | H0-05 | 2 | RF-32; PRD §8.2 · CA-05 | [ ] |
| | **Subtotal H0** | | | **14** | | |

### Hito H1 — Rebanada vertical: scan de Go con Trivy global

**Objetivo:** Un escaneo completo de punta a punta, con la menor cantidad posible de funciones, para validar el contrato.

**Gate:** `cgc-scan scan` sobre un fixture Go produce JSON válido contra el esquema, determinista y con cobertura declarada.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H1-01 | Manifiesto de confianza embebido y `tools/update-manifest` (descarga, verificación de firma y checksums, escritura de hashes) | Dev | H0-02, P-07 | 2 | ADR-07; design §7.1 | [ ] |
| H1-02 | Instalación del binario de Trivy: descarga con tope, SHA-256, extracción segura, instalación atómica, comprobación de versión | Dev | H1-01, H0-08 | 2.5 | RF-20, RF-21; design §7.2 · CA-29 | [ ] |
| H1-03 | Bloqueos de archivo con `flock` para instalación y caché | Dev | H0-07 | 1 | design §7.4 | [ ] |
| H1-04 | Runner global: entorno por lista permitida, HOME aislado, proxy inválido, grupos de procesos, timeouts, tope de salida | Dev | H0-08, P-09 | 3 | design §6.2, §6.4; RF-07 | [ ] |
| H1-05 | Constructor `trivyArgs` encapsulado y pruebas de referencia de los argumentos | Dev | P-07 | 1.5 | design T-01 | [ ] |
| H1-06 | Parser de Trivy (vulnerabilidades, secretos, configuraciones) hacia `Finding`, `Redact` y tolerancia a salida truncada; fuzzing | Dev | H1-05, H0-11 | 3 | design §5.2, §8 · CA-13 | [ ] |
| H1-07 | Modelo `Finding`, fingerprint v1 y pruebas de estabilidad | Dev | H0-09 | 1.5 | design §5.3, §9.1 | [ ] |
| H1-08 | Descubrimiento mínimo (Go) con `os.Root` y exclusiones por defecto; inventario de exclusiones en `coverage` | Dev | H0-02 | 2 | PRD §4.3, §4.4; ADR-10 | [ ] |
| H1-09 | Plan de cobertura y estado por unidad (completado, omitido, fallido) | Dev | H1-08 | 1 | RF-02 | [ ] |
| H1-10 | Orquestador: `errgroup`, cancelación, resultados parciales | Dev | H1-04, H1-09 | 1.5 | RF-08; design §12 | [ ] |
| H1-11 | Renderizador JSON determinista (orden estable, campos volátiles agrupados en `run`) | Dev | H0-09, H1-07 | 1.5 | design §10.1 | [ ] |
| H1-12 | `scan` de extremo a extremo sobre un fixture Go con `testscript`; JSON válido contra el esquema | Test | H1-02, H1-06, H1-10, H1-11 | 1.5 | Gate H1 | [ ] |
| | **Subtotal H1** | | | **22** | | |

### Hito H2 — Runner Docker, caché y bases

**Objetivo:** Segunda modalidad de Trivy, volumen persistente, actualización de bases con bloqueos y modo offline.

**Gate:** El mismo escaneo funciona con Docker y con `--offline`; la matriz de runner y los bloqueos están probados.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H2-01 | Detección de Docker: daemon, contexto local, arquitectura soportada | Dev | H1-04 | 1 | PRD §6.3; design §6.1 | [ ] |
| H2-02 | Runner Docker: red deshabilitada, solo lectura, capacidades eliminadas, límites, salida por stdout | Dev | H2-01, P-08 | 2.5 | design §6.1; ADR-09 | [ ] |
| H2-03 | Resolución de runner: precedencia y matriz de comportamiento (`--trivy-mode`, `--no-auto-install`, `--offline`) con pruebas de tabla | Dev | H2-02, H1-02 | 2 | RF-19, RF-22; PRD §6.2 | [ ] |
| H2-04 | Preparación de la imagen por digest y del volumen de caché nombrado | Dev | H2-02 | 1.5 | RF-26; PRD §6.4 | [ ] |
| H2-05 | Contenedor actualizador con red y volumen, sin el proyecto montado | Dev | H2-04 | 1.5 | RF-27; PRD §6.4 | [ ] |
| H2-06 | Interfaz `DBSource` y fuentes de Trivy (base, base Java, checks) | Dev | H2-05, H1-03 | 2 | design §7.4 | [ ] |
| H2-07 | Protocolo de bloqueo exclusivo y compartido; leer metadatos de la base tras tomar el compartido | Dev | H2-06 | 1.5 | RF-27; design §7.4 | [ ] |
| H2-08 | Comando `update-db` | Dev | H2-06 | 0.5 | PRD §8 | [ ] |
| H2-09 | Modo `--offline`: validación de antigüedad, errores estructurados y código 3 | Dev | H2-07 | 1.5 | RF-22, RF-28 | [ ] |
| H2-10 | Fallos de actualización: no declarar bases vigentes, mensajes accionables | Dev | H2-06 | 1 | PRD §6.4, §6.5 | [ ] |
| H2-11 | Pruebas de runner, bases y concurrencia | Test | H2-03, H2-07, H2-09, H2-10 | 3 | Gate H2 · CA-24, CA-25, CA-26, CA-27, CA-28, CA-30, CA-38, CA-39, CA-40, CA-41 | [ ] |
| | **Subtotal H2** | | | **18** | | |

### Hito H3 — Setup, configuración y política del proyecto

**Objetivo:** Instalación guiada, estado local, `doctor` y política declarativa segura.

**Gate:** `setup` funciona en máquinas limpias de macOS y Linux, interactivo y no interactivo; `doctor` y política del proyecto operativos.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H3-01 | `config.toml` de usuario: lectura, escritura y validación | Dev | H0-07 | 1 | design §4.2 | [ ] |
| H3-02 | `state.json`: esquema, escritura atómica, registro de instalaciones y ediciones de perfil | Dev | H0-08 | 1 | design §4.3 | [ ] |
| H3-03 | `setup` interactivo: detección de Docker, preguntas de Trivy y Semgrep, cancelación segura | Dev | H3-01, H3-02, H2-01 | 2 | RF-23; PRD §6.2 | [ ] |
| H3-04 | `setup` no interactivo (`--trivy-mode`, `--semgrep`, `--non-interactive`) | Dev | H3-03 | 1 | RF-24 | [ ] |
| H3-05 | Instalación global: enlace en `~/.local/bin`, no pisar instalaciones ajenas, versión incompatible | Dev | H1-02, H3-02 | 1.5 | RF-25; ADR-11 | [ ] |
| H3-06 | Edición idempotente del perfil de shell (zsh, bash, fish) con respaldo y registro | Dev | H3-02 | 2 | RF-25; design §7.3 | [ ] |
| H3-07 | `doctor`: diagnóstico de solo lectura de motores, bases, aislamiento y adaptadores | Dev | H2-03 | 2 | RF-03 | [ ] |
| H3-08 | Política del proyecto `cgc-scan.toml`: lista de claves permitidas, errores de política, solo endurece el umbral, excepciones con vencimiento; registrar `exclude` con origen `policy` y marcar `coverage.partial` cuando aplique | Dev | H0-12, P-04 | 3.5 | RF-33; PRD §6.8; design §9.4, O-4 | [ ] |
| H3-09 | Precedencia de configuración y registro del origen de cada valor | Dev | H3-01, H3-08 | 1 | PRD §6.8 | [ ] |
| H3-10 | Pruebas de `setup`, instalación global, perfil y política | Test | H3-04, H3-05, H3-06, H3-08 | 2.5 | Gate H3 · CA-31, CA-32, CA-33, CA-34, CA-35, CA-36, CA-37, CA-52, CA-53 | [ ] |
| | **Subtotal H3** | | | **17.5** | | |

### Hito H4 — Adaptadores por lenguaje y monorepos

**Objetivo:** Los seis lenguajes con sus herramientas, descubrimiento completo, correlación y severidad.

**Gate:** Los seis lenguajes y un monorepo mixto reportan cobertura honesta; una herramienta faltante nunca produce un resultado limpio.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H4-01 | Descubrimiento completo: seis lenguajes, unidades, monorepos, workspaces y `go.work`; detección de la raíz del proyecto (`go.work`, `composer.json`, workspaces de `package.json`, raíz de Git) | Dev | H1-08 | 3.5 | RF-01; PRD §5; design §9.4 | [ ] |
| H4-02 | Infraestructura común de aprovisionamiento de herramientas de adaptadores (según P-01): manifiesto, verificación, instalación sin scripts | Dev | P-01, H1-02 | 3 | design §8.1 | [ ] |
| H4-03 | Contrato `Requirements()` y estado omitido con `requirement_missing`; contrato de candidatos de receta de validación y candidatos por lenguaje refinados con los scripts del manifiesto del proyecto | Dev | H4-02 | 2.5 | PRD §5, regla común; design §9.5 | [ ] |
| H4-04 | Adaptador Go: govulncheck (modo fuente, base local, flujo JSON, alcanzabilidad) | Dev | H4-03, P-10 | 3.5 | PRD §5; design §8 | [ ] |
| H4-05 | Adaptador JavaScript y TypeScript: ESLint con configuración propia y reglas de seguridad; fixtures JS y TSX | Dev | H4-03, P-11 | 4 | PRD §5; design §8 | [ ] |
| H4-06 | Adaptador PHP: Psalm con análisis de taint | Dev | H4-03, P-11 | 3.5 | PRD §5; design §8 | [ ] |
| H4-07 | Adaptador Rust: cargo-audit con base local sin consultas | Dev | H4-03, P-11 | 2.5 | PRD §5.1 | [ ] |
| H4-08 | Adaptador Python: Bandit | Dev | H4-03, P-11 | 2 | PRD §5 | [ ] |
| H4-09 | Fuentes de datos RustSec y vulndb de Go dentro de `update-db` | Dev | H2-06, H4-04, H4-07 | 2 | design §7.4 | [ ] |
| H4-10 | Fixtures vulnerables y corregidos por lenguaje (seis) y un monorepo mixto | Test | H0-10 | 4 | CA-01, CA-02 | [ ] |
| H4-11 | Normalización de severidad por motor y por categoría de riesgo de regla (ESLint y Psalm), con la escala común y sus pruebas | Dev | H1-07 | 1 | PRD §9; design §8.2, §8.3; CA-58 | [ ] |
| H4-12 | Correlación de hallazgos de dependencias y de código, con pruebas | Dev | H4-11 | 3 | RF-06; design §9.2 | [ ] |
| H4-13 | `Redact` por adaptador y persistencia de salidas originales enmascaradas | Dev | H1-06 | 1.5 | design §5.2 | [ ] |
| H4-15 | Selección de rutas: `--include` y `--exclude` repetibles, coincidencia con `**`, matriz de precedencia contra la política del proyecto, `coverage.partial` y `coverage.not_analyzed`, y propagación de las exclusiones a cada motor | Dev | H3-08, H4-01, H4-03 | 3 | RF-14; PRD §4.4, §6.8; design §9.4 | [ ] |
| H4-14 | Pruebas de cobertura por lenguaje, monorepo, herramienta faltante, timeouts, no modificación y proyecto hostil | Test | H4-04, H4-05, H4-06, H4-07, H4-08, H4-10, H4-12, H4-15 | 3 | Gate H4 · CA-01, CA-02, CA-06, CA-07, CA-10, CA-11, CA-14, CA-46 | [ ] |
| | **Subtotal H4** | | | **42** | | |

### Hito H5 — Política, comparación y formato prompt

**Objetivo:** Umbrales, excepciones, `compare`, formatos texto y prompt, `--report-out`, priorización y recetas de validación.

**Gate:** Los tres formatos entregan el mismo escaneo; el prompt es consumible por un agente; códigos de salida completos.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H5-01 | Evaluación de política: umbral, severidad `unknown`, excepciones vencidas, hallazgos suprimidos visibles | Dev | H3-08, H4-11 | 2 | RF-09; design §9.3 | [ ] |
| H5-02 | Integrar los códigos de salida con el orquestador, incluida la cancelación (130) | Dev | H5-01, H0-06 | 1 | PRD §8.1 | [ ] |
| H5-03 | `compare`: nuevo, persistente, resuelto y no evaluado con cobertura comparable; un hallazgo fuera del ámbito de un escaneo parcial es no evaluado, nunca resuelto | Dev | H1-07, H5-01, H4-15 | 3 | RF-10; CA-09; design §9.4 | [ ] |
| H5-04 | Formato texto con resumen de cobertura y aviso de ejecución incompleta | Dev | H1-11 | 1.5 | RF-13; design §10.4 | [ ] |
| H5-05 | Formato prompt: plantilla versionada, bloques con nonce, saneado y secciones | Dev | H0-11, H1-11 | 3 | RF-15; design §10.3 | [ ] |
| H5-13 | Comando `recipes`: candidatos detectados, confirmación explícita y persistencia en la configuración de usuario por proyecto (`--set`, `--clear`) | Dev | H4-03, H3-01 | 2 | RF-37; PRD §8, §10.1; design §9.5 | [ ] |
| H5-06 | Prompt: flujo por parche, protección de tests, adaptación de secretos y recetas de validación tomadas de `validation`, con las unidades sin receta declaradas como bloqueadas | Dev | H5-05, H5-13 | 2.5 | RF-16, RF-17, RF-18, RF-37; PRD §10 | [ ] |
| H5-07 | Prompt por lotes con índice y referencia al reporte completo | Dev | H5-06, P-04 | 1.5 | PRD §15 | [ ] |
| H5-08 | `--report-out` atómico, excluido del escaneo y con permisos restringidos | Dev | H1-11, H0-08 | 1 | PRD §8 | [ ] |
| H5-09 | Priorización y campos CVSS, EPSS, KEV cuando existan; orden estable de hallazgos | Dev | H4-12 | 1.5 | RF-36 | [ ] |
| H5-10 | Pruebas de formatos, política, comparación, prompt, entrada local y reproducibilidad | Test | H5-02, H5-03, H5-04, H5-07, H5-08, H5-09 | 3.5 | Gate H5 · CA-04, CA-08, CA-09, CA-12, CA-15, CA-16, CA-17, CA-18, CA-19, CA-20, CA-21, CA-22, CA-23, CA-42, CA-43, CA-44, CA-45, CA-46, CA-51, CA-56 | [ ] |
| | **Subtotal H5** | | | **22.5** | | |

### Hito H6 — Semgrep opcional, aislamiento y release

**Objetivo:** Tercer nivel opcional, aislamiento verificable por versión y cadena de suministro de la CLI.

**Gate:** Semgrep opcional funciona solo tras `setup`; las pruebas de aislamiento pasan; artefactos firmados con SBOM y procedencia.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H6-01 | Aprovisionamiento de Semgrep según la decisión P-05 (verificado, sin elevación) | Dev | P-05, H1-02 | 2.5 | PRD §5.2 | [ ] |
| H6-02 | Adaptador Semgrep: reglas locales, métricas y comprobación de versión desactivadas, estado `disabled` | Dev | H6-01, H4-03 | 2.5 | RF-30 | [ ] |
| H6-03 | Conjunto mínimo de reglas propias de CGC con licencia permisiva y versionado | Dev | P-05, P-06 | 4 | PRD R3; PRD §15 | [ ] |
| H6-04 | Declarar el nivel de aislamiento en el reporte y soportar `--require-isolation` | Dev | H1-04, H2-02 | 1.5 | RF-31 | [ ] |
| H6-05 | Prueba de aislamiento por versión de motor en CI (`strace` y Docker sin red) | Test | H6-04, P-09 | 2.5 | design §15.2 | [ ] |
| H6-06 | (P2) `enforced` en el runner global de Linux con espacio de red y sondeo en tiempo de ejecución | Dev | H6-05 | 3 | design §6.3 | [ ] |
| H6-07 | GoReleaser: matriz de plataformas, `-trimpath`, checksums | Release | H0-03 | 1.5 | design §15.5 | [ ] |
| H6-08 | Firma con cosign, SBOM CycloneDX y atestación de procedencia SLSA | Release | H6-07, P-02 | 2.5 | RF-34; PRD §6.7 | [ ] |
| H6-09 | Documentar y probar la verificación de artefactos con un release real | Release | H6-08 | 1 | RF-34 · CA-54 | [ ] |
| H6-10 | Pruebas de Semgrep opcional y de aislamiento | Test | H6-02, H6-05, H6-09 | 2 | Gate H6 · CA-03, CA-47, CA-48, CA-49, CA-50 | [ ] |
| | **Subtotal H6** | | | **20 (+3 P2)** | | |

### Hito H7 — Endurecimiento, documentación y lanzamiento

**Objetivo:** Calidad final, documentación, revisión legal y publicación de v1.0.0.

**Gate:** Matriz de aceptación completa registrada, documentación publicada y v1.0.0 disponible.

| ID | Tarea | Tipo | Depende de | Días | Refs | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| H7-01 | Benchmarks por tamaño de proyecto y plataforma; fijar timeouts y concurrencia por defecto | Test | H5-10, H6-10 | 3 | design §15.4, §12 | [ ] |
| H7-02 | Fuzzing sostenido de parsers, saneado y política | Test | H5-10 | 1.5 | design §15.1 | [ ] |
| H7-03 | Revisión de seguridad propia contra el modelo de amenazas y corrección de hallazgos | Dev | H6-10 | 3 | design §13 | [ ] |
| H7-04 | Ejecutar y registrar la matriz completa de criterios de aceptación CA-01 a CA-56 | Test | H7-01, H7-02, H7-03 | 3 | PRD §13 | [ ] |
| H7-05 | Prueba con un agente consumidor real: JSON y prompt, ciclo parche, tests, build y reescaneo | Test | H5-10 | 3 | PRD §16 paso 5 | [ ] |
| H7-06 | Revisión legal final: licencias empaquetadas y Ley 21.719 | Legal | P-06, H6-10 | 1.5 | design §14 | [ ] |
| H7-07 | Documentación de usuario: instalación, `setup`, flags, cobertura, privacidad y preguntas frecuentes | Doc | H6-10 | 3 | PRD §2 | [ ] |
| H7-08 | Guía de integración para agentes con ejemplos de JSON y prompt | Doc | H5-10 | 1.5 | PRD §2 | [ ] |
| H7-09 | Canal de distribución: releases con checksums y fórmula de instalación (por ejemplo Homebrew) | Release | H6-08 | 2 | PRD §6.7 | [ ] |
| H7-10 | Proceso de soporte y de divulgación de vulnerabilidades (contacto, plazos, triage) | Ops | H0-01 | 1 | PRD §6.7 | [ ] |
| H7-11 | Release candidate: pruebas en máquinas limpias macOS y Linux (amd64 y arm64) y corrección de bloqueantes | Test | H7-04, H7-05, H7-06, H7-07, H7-09 | 3 | Gate H7 | [ ] |
| H7-12 | Publicar v1.0.0 y comunicarlo | Release | H7-11 | 1 | — | [ ] |
| | **Subtotal H7** | | | **26.5** | | |

---

## 4. Cobertura de criterios de aceptación

Cada criterio del PRD tiene al menos una tarea que lo cubre. La verificación final de la matriz completa es H7-04.

| CA | Tarea(s) |
| --- | --- |
| CA-01 | H4-10, H4-14 |
| CA-02 | H4-10, H4-14 |
| CA-03 | H6-10 |
| CA-04 | H5-10 |
| CA-05 | H0-12 |
| CA-06 | H4-14 |
| CA-07 | H4-14 |
| CA-08 | H0-04, H5-10 |
| CA-09 | H5-10 |
| CA-10 | H4-14 |
| CA-11 | H4-14 |
| CA-12 | H5-10 |
| CA-13 | H1-06 |
| CA-14 | H4-14 |
| CA-15 | H5-10 |
| CA-16 | H5-10 |
| CA-17 | H5-10 |
| CA-18 | H5-10 |
| CA-19 | H5-10 |
| CA-20 | H5-10 |
| CA-21 | H5-10 |
| CA-22 | H5-10 |
| CA-23 | H5-10 |
| CA-24 | H2-11 |
| CA-25 | H2-11 |
| CA-26 | H2-11 |
| CA-27 | H2-11 |
| CA-28 | H2-11 |
| CA-29 | H1-02 |
| CA-30 | H2-11 |
| CA-31 | H3-10 |
| CA-32 | H3-10 |
| CA-33 | H3-10 |
| CA-34 | H3-10 |
| CA-35 | H3-10 |
| CA-36 | H3-10 |
| CA-37 | H3-10 |
| CA-38 | H2-11 |
| CA-39 | H2-11 |
| CA-40 | H2-11 |
| CA-41 | H2-11 |
| CA-42 | H5-10 |
| CA-43 | H5-10 |
| CA-44 | H5-10 |
| CA-45 | H5-10 |
| CA-46 | H4-15, H5-10 |
| CA-47 | H6-10 |
| CA-48 | H6-10 |
| CA-49 | H6-10 |
| CA-50 | H6-10 |
| CA-51 | H5-10 |
| CA-52 | H3-10 |
| CA-53 | H3-10 |
| CA-54 | H6-09 |
| CA-55 | H0-08, H4-13, H5-08 |
| CA-56 | H5-10 |
| CA-57 | H5-13, H5-10 |
| CA-58 | H4-11, H5-10 |

---

## 5. Backlog posterior a v1 (sin estimar)

| Ítem | Origen | Nota |
| --- | --- | --- |
| Salida SARIF 2.1.0 | PRD §8.2 | Recomendado para v1.1; el esquema interno ya se diseña para mapearse sin pérdida |
| SBOM del proyecto escaneado (CycloneDX) | PRD §8.2 | Ampliación posible |
| Escaneo de imágenes de contenedor | PRD §4.5 | Solo archivos exportados (`docker save`), sin socket Docker |
| `enforced` en el runner global (si H6-06 no se ejecuta) | PRD §15 | Evaluar por plataforma con datos de uso |
| Soporte nativo de Windows | PRD §12 | Hoy WSL2 |
| Segunda iteración con interpretación local opcional | PRD §11 | Requiere decidir runtime, modelo y límites de contexto |
| Revisión de la Ley 21.719 si se agrega telemetría, cuentas o licenciamiento en línea | design §14 | Cambia el rol de CGC frente a los datos |
| Selección de lenguajes y reglas adicionales | PRD §4.1 | Según demanda |

---

## 6. Riesgos de planificación

Los riesgos de producto están en PRD §14 y los técnicos en design §16; aquí solo los que afectan al calendario.

| ID | Riesgo | Impacto | Mitigación |
| --- | --- | --- | --- |
| W-01 | Alcance grande para un solo desarrollador: seis lenguajes, dos runners y varias herramientas externas | Alto | Gates por hito, orden de adaptadores de la regla 6, re-estimación tras H1 y H4. Cualquier recorte de alcance requiere una decisión explícita sobre el PRD §4.1 |
| W-02 | Estimaciones sin benchmarks | Medio | Contingencia de 15 %; los spikes P-07 a P-11 se hacen antes de comprometer fechas |
| W-03 | Los spikes cambian el diseño (flags de motores, distribución de adaptadores) | Alto | P-12 actualiza documentos antes de H0; no empezar H1 con decisiones sin cerrar |
| W-04 | Cambios de versión de un motor a mitad del proyecto | Medio | Regla 5: versiones fijadas desde H1 y actualización solo como tarea |
| W-05 | Resultado legal desfavorable sobre reglas o licencias (P-06) | Medio | Semgrep es opcional; H6-03 usa reglas propias; el hallazgo se conoce antes de H0 |
| W-06 | Dedicación inferior a la supuesta | Alto | Usar la tabla 2.1 con los días reales por semana y revisar mensualmente |

---

## 7. Seguimiento

- Marca el estado en la columna *Estado* de cada tabla (`[ ]`, `[~]`, `[x]`).
- Al terminar un hito, anota la fecha real y los días reales junto al subtotal; esa diferencia alimenta la re-estimación de la regla 4.
- Las tareas nuevas que surjan reciben el siguiente número libre de su hito y se agregan con su dependencia y su referencia de origen.
