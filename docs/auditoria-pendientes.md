# Trabajo pendiente — auditoría asistida

> **Estado de partida:** commit `d7b3b93`, 31 paquetes de pruebas verdes,
> cobertura de `internal/audit` 78,3 % (`go test -count=1 -cover ./internal/audit/`).
> El árbol de trabajo no está limpio en el momento de la verificación porque
> este documento y el índice local `.codegraph/` están sin seguimiento.
> **Alcance:** backlog del protocolo `cgc-scan audit` y de su integración con el
> resto del producto. No incluye el runtime de IA ni el sandbox de ejecución:
> esos son cambios de PRD, no tareas de este backlog.

## Cómo leerlo

| Prioridad | Criterio |
| --- | --- |
| **P0** | Puede producir un resultado incorrecto, una afirmación de cobertura falsa o corromper el estado de la corrida |
| **P1** | Completa la fidelidad al protocolo o hace operable el flujo en proyectos reales |
| **P2** | Integración, experiencia de uso, mantenimiento y release |

---

## P0 — Correctitud y seguridad del protocolo

### P0-1. Persistencia transaccional de `ledger.json` + `candidates.json`

**Hoy.** `audit init`, `audit next` y `audit submit` escriben dos archivos con
dos `os.Rename` independientes: el ledger se guarda antes que el estado de
verificación, sin transacción que los ate. Si el proceso muere entre ambos, el
ledger y el estado de verificación quedan desalineados (unidad `candidate` sin
candidato, o candidato sin unidad). `audit report` repite el patrón con
`findings.json` y `ledger.json`, que también se sellan por separado.

**Qué hacer.** Un solo archivo de estado (`state.json`) con ambos documentos, o
un journal de dos fases con recuperación al abrir. Mantener `ledger.json` y
`candidates.json` como vistas derivadas si se quieren conservar.

**Archivos.** `internal/audit/store.go`, `internal/cli/audit.go`.

**Hecho cuando.** Una prueba que hace fallar la segunda escritura deja el
directorio recuperable; `audit status` informa el estado consistente; no existe
la combinación «unidad candidate sin candidato».

**Esfuerzo.** 3 d.

---

### P0-2. Bloqueo de la corrida

**Hoy.** No hay `flock`. Dos procesos `audit next` pueden asignar la misma
unidad; dos `audit submit` pueden perder una actualización (last write wins).

**Qué hacer.** Bloqueo exclusivo sobre el directorio de la corrida, reutilizando
`gofrs/flock` y el patrón de `internal/platform/lock.go`. Bloqueo exclusivo durante toda la operación de lectura-modificación-escritura
de `init`/`next`/`submit`/`report`; lectura compartida para `status`.
`report` también sella el ledger y escribe artefactos, por lo que no es lector.

**Archivos.** `internal/audit/store.go`, `internal/cli/audit.go`.

**Hecho cuando.** N goroutines concurrentes de `next`/`submit` serializan sin
dueños duplicados, sin `wave` repetida y sin pérdida de entregas; el bloqueo se
libera al cancelar.

**Esfuerzo.** 2 d.

---

### P0-3. Verificar que la traza citada existe en la fuente declarada

**Hoy.** El validador comprueba sintaxis y rutas relativas. Un registro puede
citar un archivo inexistente, una línea fuera de rango o un archivo que no está
en `source_ref`.

**Qué hacer.** En `submit`/`report`:

1. comprobar que `trace[].file` y `evidence[].file` existen en la raíz;
2. comprobar `line <= número de líneas`;
3. si `source_ref` es una revisión de Git y el árbol estaba limpio, verificar
   `git cat-file -e <rev>:<path>` y leer el blob para el conteo de líneas
   (todo local, sin red);
4. distinguir la validez histórica del snapshot de su vigencia en el árbol
   actual; si se exige vigencia actual, declarar el cambio y exigir revalidación.
   No convertir automáticamente un cambio de archivo en `needs_validation`: ese
   veredicto exige una hipótesis y un bloqueo que satisfagan su contrato.

**Archivos.** `internal/audit/validate.go`, `internal/audit/broker.go`,
`internal/cli/audit.go`.

**Hecho cuando.** Una traza fabricada se rechaza en `submit`; un archivo
cambiado entre la cita y la verificación no puede confirmarse como vigente
sin revalidación; la prueba usa un
repositorio Git real y dos revisiones.

**Esfuerzo.** 3 d.

---

### P0-4. Recuperación de asignaciones abandonadas

**Hoy.** `Unit.Attempts` existe en el contrato pero nunca se escribe. Si un
agente abandona una unidad `in_progress`, no hay forma de devolverla a
`planned`; solo iniciar otra corrida.

**Qué hacer.** `cgc-scan audit reset-unit --coverage-id ID --reason "..."`:

- cierra explícitamente el intento abandonado como `blocked` con razón de
  abandono y archiva dueño, ola y checks realmente disponibles; el contrato
  actual no admite archivar `in_progress`;
- incrementa `wave`;
- deja la unidad `planned` con evidencia vacía;
- registra la razón y conserva el historial.

**Archivos.** `internal/audit/broker.go`, `internal/cli/audit.go`,
`schemas/audit-ledger.schema.json` (sin cambios de forma si se archiva como `blocked`).

**Hecho cuando.** El reset archiva el intento, otro agente recibe la unidad y el
ledger sigue validando; el intento archivado no se copia al estado vigente.

**Esfuerzo.** 2 d.

---

### P0-5. Validar `candidates.json` al cargarlo

**Hoy.** Al cargar `candidates.json` se limita la lectura a 16 MiB y se
decodifica un objeto sin campos desconocidos, comprobando `schema_version`.
No se exige EOF después del objeto, por lo que puede aceptar contenido adicional. Un archivo
editado a mano puede saltarse la independencia (verificador = cazador) o dejar un
`Final` con la rama equivocada.

**Qué hacer.** Validación semántica al cargar: `hunter_agent` canónico, cada
intento con agente distinto, fingerprint y rama de veredicto de `final` coherentes, estados válidos,
`run_id` y referencias consistentes con el ledger, y rechazo de contenido
posterior al objeto. `escalated` es obligatorio en `escalation`, pero puede
conservarse como historial en `decided`: así lo hace hoy el broker.

**Archivos.** `internal/audit/store.go`, `internal/audit/broker.go` (exportar
`ValidateCandidates`).

**Hecho cuando.** Un `candidates.json` con verificador igual al cazador se
rechaza al abrir; una prueba de mesa cubre los cinco estados corruptos.

**Esfuerzo.** 1 d.

---

### P0-6. Fuzzing de los decodificadores públicos

**Hoy.** No hay fuzz para `DecodeLedger`, `DecodeFindings` ni
`DecodeSubmission`. El repo ya tiene campañas cortas de fuzzing en CI.

**Qué hacer.** Semillas válidas + mutaciones; límites de tamaño y
de anidamiento explícitos; garantizar que ningún decodificador entra en pánico ni consume
memoria desmedida.

La CLI ya limita las entregas a 8 MiB, aunque para archivos usa `os.ReadFile`
antes de comprobar el tamaño; el store limita ledger/candidatos/hallazgos a
16/16/32 MiB. Los decodificadores públicos no imponen esos límites por sí solos.

**Archivos.** `internal/audit/*_fuzz_test.go`, `.github/workflows/ci.yml`,
`internal/cli/audit.go`, `internal/audit/schema.go`.

**Hecho cuando.** `go test -fuzz` corre 20 s por decodificador en CI sin fallos y
las semillas válidas siguen pasando.

**Esfuerzo.** 2 d.

---

## P1 — Fidelidad al protocolo

### P1-1. Perfiles con semántica real (`quick` / `standard` / `deep`)

**Hoy.** El perfil se registra pero no cambia el reparto.

**Qué hacer.**

| Perfil | Unidades | Olas | Verificación |
| --- | --- | --- | --- |
| `quick` | por subsistema × dominio | una | una pasada |
| `standard` | por subsistema × frontera × clase | crítico por ola + crítico final | dos pasadas |
| `deep` | por subsistema × ciclo de vida | olas hasta crítico limpio | dos pasadas + segunda pasada de unidades previas |

**Archivos.** `internal/audit/build.go`, `internal/audit/broker.go`,
`catalog.json` (metadatos por perfil).

**Hecho cuando.** Dos perfiles producen ledgers con distinta granularidad y el
informe declara el perfil y la cobertura que implica.

**Esfuerzo.** 4 d.

---

### P1-2. Olas de crítica de cobertura

**Hoy.** `audit next` emite `hunt`, `verify` y `escalation_check`. No existe el
rol de crítico. Los cazadores ya pueden devolver `uncovered`, que `submitHunt`
convierte en unidades planificadas; falta la fase de crítica independiente.

**Qué hacer.** Tercer tipo de tarea `critique`; ingesta de `missing_units`,
`reassign_ids`, `resolved_prior_leads` y `stop`; creación de unidades
planificadas; archivo de intentos en la reasignación; crítico final limpio antes
de `complete`.

**Archivos.** `internal/audit/broker.go`, `internal/audit/report.go`,
`internal/cli/audit.go`.

**Hecho cuando.** Una corrida con una superficie no mapeada recibe una unidad
del crítico, la caza y cierra; el informe distingue «crítico limpio» de «sin
crítico».

**Esfuerzo.** 6 d.

---

### P1-3. Verificación en dos pasadas y reemplazo material

**Hoy.** Una sola pasada (semántica `quick`): el verificador valida y cierra.
Existe una segunda firma, pero solo cuando el verificador **promueve** el
veredicto (`needs_validation` → `confirmed`): el candidato pasa a `escalation` y
exige otro verificador, que puede confirmar con `verified` o sustituir el
registro con `replace`. No hay, en cambio, una segunda revisión del registro
final en general, ni una regla de **reemplazo material**: `replace` compara
solo el rango del veredicto (`VerdictRank`), no si el cambio altera causa raíz,
traza, ejecución, impacto o severidad.

**Qué hacer.** Separar «validar candidato» de «verificar registro final» para
`standard`/`deep`; un reemplazo que cambie causa raíz, traza, ejecución,
impacto o severidad exige un verificador que no cazó, no validó y no propuso el
reemplazo.

**Archivos.** `internal/audit/broker.go`, `internal/audit/report.go`.

**Hecho cuando.** Un reemplazo material no se aplica sin la segunda firma; el
presupuesto y la independencia se respetan; `quick` conserva el comportamiento
actual.

**Esfuerzo.** 4 d.

---

### P1-4. Reserva determinista de presupuesto

**Hoy.** El presupuesto cuenta asignaciones nuevas y prioriza verificaciones,
pero no reserva críticos ni verificadores antes de repartir caza. Al agotarse
en la rama de caza difiere unidades y sella `incomplete`; al agotarse en
`issueVerification` solo devuelve `ErrBudgetExhausted`. La CLI anuncia que
difirió y selló también en ese caso, aunque no ocurrió. Corregir esa divergencia
y cubrir ambos caminos forma parte de esta tarea.

**Qué hacer.** Aplicar la regla de reserva de la skill: reservar el crítico
final y una fracción para verificación antes de cada ola; negarse a lanzar
cazadores si la reserva no cabe; razones de incompletitud deterministas.

**Archivos.** `internal/audit/broker.go`.

**Hecho cuando.** Un presupuesto que no cubre crítico + verificación no asigna
cazadores y termina `incomplete` con la razón exacta; una tabla de pruebas cubre
los bordes.

**Esfuerzo.** 3 d.

---

### P1-5. Composición de asignaciones tipo prompt

**Hoy.** `audit next` entrega JSON con la clase por defecto y ya permite
`--format text` mediante `renderAuditTask`. No ofrece `--format prompt`. No aprovecha el saneado ni
los delimitadores con nonce de `report/prompt.go`.

**Qué hacer.** `--format prompt` con plantilla versionada: contexto, invariante,
checks, rutas, contrato de resultado y bloques de datos no confiables
delimitados. Nunca interpolar instrucciones desde el proyecto.

**Archivos.** `internal/audit/prompt.go`, `templates/audit/*.tmpl`
(`internal/report/prompt/v1.tmpl` es la plantilla vigente que hay que seguir;
`templates/prompt/` está vacío y no se usa), `internal/cli/audit.go`.

**Hecho cuando.** Con un nonce fijado para pruebas, el prompt renderiza de forma determinista; un título con
secuencias de control o ANSI no rompe el delimitador; el JSON sigue disponible.

**Esfuerzo.** 3 d.

---

### P1-6. Aditividad real entre corridas

**Hoy.** `--prior` expone contexto, pero no calcula cambios de fuente ni
transporta confirmados previos por la verificación actual.

**Qué hacer.** Hash de contenido por unidad; transportar un `confirmed` previo
solo si su fuente y condiciones no cambiaron, y hacerlo pasar por la
verificación actual; crear unidad de revalidación cuando la fuente cambió; no
suprimir unidades por estar cubiertas antes.

**Archivos.** `internal/audit/build.go`, `internal/audit/broker.go`,
`internal/unitcache` (el hash de árbol ya existe en `cache.go`, pero
`hashTree`/`hashFiles` no están exportados: hay que promover un helper
reutilizable).

**Hecho cuando.** Cambiar un archivo invalida solo su unidad; un confirmado
previo sin cambios se revalida, no se copia; un `rejected` sin cambios evita
repetir la misma afirmación, y uno con cambios vuelve a ser trabajo.

**Esfuerzo.** 6 d.

---

### P1-7. Deduplicación por causa raíz y rationale de orden

**Hoy.** Se deduplica por fingerprint exacto. La skill consolida por fingerprint
y luego por causa raíz, y exige registrar por qué se eligió cada unidad.

**Qué hacer.** Agrupar candidatos con la misma causa raíz y distinta entrada en
un solo registro con la traza más fuerte; registrar el orden de asignación en el
ledger.

**Archivos.** `internal/audit/broker.go`, `internal/audit/ledger.go`.

**Hecho cuando.** Dos variantes del mismo defecto no producen dos registros; el
ledger explica el orden aplicado.

**Esfuerzo.** 2 d.

---

### P1-8. Delta entre corridas de auditoría

**Hoy.** No hay comparación de auditorías. `compare` solo trabaja con
`report-1.1.0`.

**Qué hacer.** `new`, `persistent`, `resolved`, `not_evaluated` por fingerprint,
y `cgc-scan audit compare [anterior actual]`.

**Archivos.** `internal/audit/compare.go`, `internal/cli/audit.go`.

**Hecho cuando.** Dos corridas sobre el mismo fixture producen un delta
determinista; lo no evaluado nunca aparece como resuelto.

**Esfuerzo.** 3 d.

---

### P1-9. Integridad y tamper-evidence del informe

**Hoy.** La procedencia es autodeclarada; cualquiera puede editar
`findings.json` después de `audit report`.

**Qué hacer.** Bloque `integrity` con HMAC-SHA256 con una clave secreta local dedicada, usando como referencia
el almacenamiento privado de `internal/masking`, sobre una serialización
canónica del ledger y los registros, y comando de verificación.
No sustituye la firma de release: detecta modificaciones sin acceso a la clave,
pero quien puede leerla o reemplazarla también puede recalcular el HMAC.

**Archivos.** `internal/audit/integrity.go`, `internal/cli/audit.go`.

**Hecho cuando.** Editar un veredicto invalida el HMAC; `audit report --verify`
lo detecta; el formato sigue siendo determinista.

**Esfuerzo.** 3 d.

---

## P2 — Integración, UX y operación

### P2-1. Puente con `scan` y `agent`

Convertir hallazgos de motores en **leads** de auditoría (nunca `confirmed`),
vincularlos a unidades y evitar trabajo duplicado. Un lead de Trivy entra como
`needs_validation` o como candidato a cazar; jamás hereda severidad.

**Esfuerzo.** 4 d.

### P2-2. `audit explain`, `status` enriquecido y texto de tareas

Explicar un fingerprint o unidad sin reescribir archivos; listar unidades
bloqueadas y diferidas en `status`; mejorar el render de tareas existente (`audit next --format text`).
`status` ya muestra conteos de bloqueadas/diferidas, pero no su listado. **2 d.**

### P2-3. Política de salida para CI (`--fail-on`)

Hoy una corrida completa devuelve 0 aunque tenga confirmados críticos. Decidir
si `--fail-on` aplica a `confirmed` y con qué umbral; documentar la diferencia
con `scan --fail-on`.

**Decisión de producto + 2 d.**

### P2-4. Seguridad de `--out`

Advertir o rechazar un `--out` dentro del repositorio si no está ignorado por
Git. La skill incluida describe la ubicación externa por defecto, pero no
impone esa comprobación para un `--out` explícito. **1 d.**

### P2-5. Catálogo completo de dominios

Hoy hay 4 dominios y 16 clases. La referencia cubre 10 *companions* (web y auth,
cliente, cadena de suministro, cloud, protocolos, aislamiento de datos,
escritorio/móvil, memoria/binario, IA/LLM, agotamiento de recursos). Ampliar como
datos versionados, con señales y pruebas por fixture, y herramienta de
actualización firmada.

**5–10 d incrementales.**

### P2-6. PRD, aceptación y documentación de uso

El PRD (`requisitos-cli-seguridad.md`) no especifica el comando `cgc-scan audit`; `docs/uso.md` no lista los comandos; la matriz de
aceptación no tiene CA. Agregar RF/CA, ejemplos, FAQ y límites declarados.

**3 d.**

### P2-7. Empaquetado

`install.sh --package` copia la skill pero no los esquemas públicos: el
paquete incluye el binario, `install.sh`, la skill y su instalador, además de
VERSION, documentación, licencias e INSTALL.txt, pero no `schemas/`. Faltan `schemas/audit-ledger.schema.json`,
`schemas/findings.schema.json`, `schemas/agent.schema.json` y
`schemas/report.schema.json`. Esto también rompe la comprobación de versión de
esquema del propio instalador: al instalar desde el paquete, `SCRIPT_DIR` no
tiene `schemas/report.schema.json`, así que el `if [ -f "$SCHEMA_FILE" ]`
omite la validación en silencio. Incluirlos y verificar la instalación desde el
paquete.

**1 d.**

### P2-8. CI y benchmarks

Ya hay pruebas de flujo CLI en `internal/cli/audit_test.go`, ejecutadas por
el job general de Go. Añadir un job E2E del protocolo sobre un repo Git real; semillas de fuzz para audit;
benchmark de construcción del ledger en monorepo; evitar el doble recorrido de
las unidades `project` y `root` (en la raíz del repositorio, `discovery` emite
`project` con `path="."` y `root` con `path="."`: las dos recorren el mismo
árbol y `audit init` las vuelve a escanear por separado).

**2 d.**

### P2-9. Release

Convertir «Sin publicar» en versión, notas de release, actualización de la skill
y verificación del paquete. **1 d.**

---

## No objetivos de este backlog

Requieren cambiar el PRD y no se abordan aquí:

- runtime de IA, subagentes o proveedor de modelos (CA-04, CA-05);
- sandbox con ejecución del código del proyecto (§6.6);
- navegadores, emuladores, fuzzers o IPC local;
- parches automáticos o ejecución de recetas;
- atestación de **verdad** de un hallazgo: el motor solo valida estructura,
  consistencia e independencia.

---

## Deuda menor detectada

- `Unit.Attempts` existe en el contrato pero nunca se escribe: nada archiva el
  estado terminal de una unidad reasignada. `wave` sí se incrementa hoy, en cada
  `audit next` que reparte una unidad, y lo usan P0-4/P1-2.
- El `hardening` de nivel superior se copia a todas las unidades de la entrega;
  convendría un campo de asignación.
- El informe no lista fingerprints de candidatos pendientes; el código no
  documenta una decisión de privacidad. Si se necesita trazabilidad, añadir
  una sección con huellas truncadas.
- `VerdictRank` y `severityRank` son escalas distintas con nombres parecidos;
  documentarlo en el paquete.
- `audit init` recorre dos veces el árbol (`project` y `root`); P2-8 lo mide.
- `candidates.json` es interno y sin esquema público; si se quiere auditar por
  terceros, publicarlo.

---

## Orden recomendado

| Sprint | Contenido | Esfuerzo |
| --- | --- | --- |
| 1 | P0-1 atomicidad, P0-2 lock, P0-3 trazas, P0-4 reset, P0-5 candidates, P0-6 fuzz | ~13 d |
| 2 | P1-1 perfiles, P1-2 críticos, P1-4 reserva | ~13 d |
| 3 | P1-3 dos pasadas, P1-5 prompt, P1-8 delta | ~10 d |
| 4 | P1-6 aditividad, P1-7 dedupe, P1-9 integridad | ~11 d |
| 5 | P2-1 puente, P2-6 PRD/aceptación, P2-7 empaquetado, P2-8 CI | ~10 d |

**Total estimado:** ~57 días cubren P0, todo P1 y el bloque mínimo de P2
(puente, PRD, empaquetado y CI). El resto de P2 sin catálogo añade ~6 días, y el
catálogo completo 5–10 días más: ~68–73 días en total.

---

## Verificación de este backlog

> **Fecha:** 10 de noviembre de 2026 · **Base:** commit `d7b3b93`
> **Método:** lectura del código de `internal/audit`, `internal/cli/audit.go`,
> `internal/platform`, `internal/discovery`, `internal/report`, `install.sh` y
> `skills/cgc-scan/SKILL.md`; `go test ./...` (31 paquetes en verde);
> `go test -count=1 -cover ./internal/audit/` (78,3 %); lectura de
> `discovery.Discover` y `BuildLedger` para comprobar el recorrido de unidades.
> En esta revisión se repitió `go test ./...` (31 paquetes pasan; parte desde
> caché) y la cobertura de audit con `-count=1`: 78,3 %.

Se contrastaron los 24 ítems P0/P1/P2 con la implementación y los contratos
locales. Se mantienen como trabajo pendiente, con las precisiones de esta
revisión. Se elimina el anterior recuento «22 de 25 / tres divergencias», que
no concordaba ni con los ítems ni con las seis filas de su tabla. Las
correcciones son documentales; no se implementó el backlog. Las estimaciones
de esfuerzo son propuestas, no mediciones verificadas. Las exigencias atribuidas
a la skill externa deben fijarse a una versión antes de implementarlas; esta
revisión contrasta el repositorio local y su evaluación, no la rama remota actual.

### Correcciones de esta revisión

- P0-2: `report` necesita bloqueo exclusivo porque escribe.
- P0-3: separar validez de una cita en un snapshot y vigencia en el árbol actual.
- P0-4/P0-5: respetar los estados admitidos al archivar y el historial
  `escalated` que el broker conserva después de decidir; exigir EOF al cargar.
- P0-6: precisar los límites de lectura existentes y los que faltan.
- P1-2/P1-4/P1-5: reconocer `uncovered`, el distinto agotamiento de presupuesto
  en verificación y el formato de texto ya implementado.
- P1-9: distinguir clave secreta de sal y limitar la garantía del HMAC.
- P2: corregir CA-01…CA-72, contenido del paquete y pruebas de flujo existentes;
  retirar la atribución no demostrada de una decisión de privacidad.

### Correcciones históricas ya presentes

| # | Afirmación original | Realidad verificada | Corrección |
| --- | --- | --- | --- |
| 1 | Cobertura de `internal/audit` de 78,5 % | 78,3 % (`go test -count=1 -cover`) | Valor corregido y comando de reproducción añadido |
| 2 | `audit next` emite «solo `hunt` y `verify`» | Emite tres tipos: `hunt`, `verify` y `escalation_check` | Enumeración corregida; la conclusión (no hay rol de crítico) se mantiene |
| 3 | Los dos archivos se escriben en `next` y `submit` | `audit init` también escribe ledger y candidatos por separado, y `audit report` sella `findings.json` y `ledger.json` por separado | Alcance de P0-1 ampliado a los cuatro comandos |
| 4 | «`Unit.Attempts` y `wave` … solo se usarán con P0-4/P1-2» | `wave` ya se incrementa en cada reparto (`broker.go`); `Unit.Attempts` es lo que nunca se escribe | Deuda menor reescrita para separar ambos casos |
| 5 | «No hay segunda revisión del registro final ni regla de reemplazo material» | Sí existe segunda firma cuando el verificador **promueve** el veredicto, y `replace` compara solo `VerdictRank` | Descripción ajustada: la ausencia real es la regla de materialidad, no la segunda firma |
| 6 | `internal/projectstate` aporta el hash reutilizable de `unitcache` | El hash vive en `internal/unitcache/cache.go` y `hashTree`/`hashFiles` no están exportados; `projectstate` no hashea | Ruta corregida y necesidad de exportar un helper anotada |

### Evidencias del estado actual (con las precisiones anteriores)

- **P0-1** — dos `os.Rename` independientes: `platform.WriteFileAtomic` renombra
  un temporal por archivo, sin transacción entre archivos.
- **P0-2** — no hay `flock` en el protocolo de auditoría; `platform.Acquire`
  (`gofrs/flock`) existe y está disponible para reutilizar.
- **P0-3** — el validador comprueba sintaxis y rutas relativas (`ValidRepoPath`,
  `line >= 1`); no comprueba existencia del archivo ni rango de la línea.
- **P0-4** — `Unit.Attempts` existe en el contrato y nunca se escribe.
- **P0-5** — al cargar `candidates.json` se decodifica un objeto sin campos desconocidos
  y se valida `schema_version`; no hay validación semántica ni exigencia de EOF.
- **P0-6** — no hay fuzz para `DecodeLedger`, `DecodeFindings` ni
  `DecodeSubmission`; CI solo tiene campañas de `internal/masking`.
- **P1-1** — el perfil se registra en el ledger y no cambia el reparto.
- **P1-4** — el presupuesto cuenta asignaciones nuevas, sin reservas; solo la rama
  de caza difiere y sella al agotarse, no la rama de verificación.
- **P1-5** — `audit next` ofrece JSON y texto, pero no prompts; el saneado y los delimitadores con
  nonce viven en `internal/report/prompt.go` y no se reutilizan.
- **P1-6** — `--prior` expone contexto sin calcular cambios de fuente ni
  transportar confirmados previos a la verificación actual.
- **P1-7** — la deduplicación es por fingerprint exacto (`broker.go` rechaza
  fingerprints duplicados en la entrega); no hay consolidación por causa raíz.
- **P1-8** — no existe comparación de auditorías; `compare` solo opera sobre
  `report-1.1.0`.
- **P1-9** — la procedencia es autodeclarada (`attested_by: caller`,
  `engine_verified: false`); no hay bloque de integridad ni HMAC.
- **P2-1** — no existe puente entre `scan`/`agent` y `audit`: no importa hallazgos de esos motores como leads;
  `Uncovered` sí permite proponer nuevas superficies desde una entrega de caza.
- **P2-2** — no existe `audit explain`; `status` no lista unidades bloqueadas ni
  diferidas.
- **P2-3** — `audit report` sale con 0 en una corrida completa aunque haya
  confirmados críticos; `--fail-on` existe en `scan`, no en `audit`.
- **P2-4** — `--out` no comprueba si cae dentro del repositorio ni si está
  ignorado por Git.
- **P2-5** — el catálogo tiene 4 dominios (`code`, `configuration`,
  `dependencies`, `secrets`) y 16 clases.
- **P2-6** — el PRD no especifica `cgc-scan audit`, `docs/uso.md` no lista sus comandos y la
  matriz de aceptación (`docs/aceptacion.md`, CA-01…CA-72) no tiene ninguna CA
  de auditoría.
- **P2-7** — el paquete de `install.sh` no incluye `schemas/` (confirmado), y
  esto desactiva en silencio la comprobación de versión de esquema al instalar
  desde el paquete.
- **P2-9** — el changelog sigue con «Sin publicar» y `VERSION` es `0.2.0-rc.1`.
- **Deuda menor** — el `hardening` de nivel superior se propaga a todas las
  unidades de la entrega; el informe no lista fingerprints pendientes;
  `VerdictRank` y `severityRank` son escalas distintas; `candidates.json` no
  tiene esquema público; y `audit init` recorre dos veces el árbol, porque en
  la raíz `discovery` emite `project` (`path="."`) y `root` (`path="."`).

### Snapshot y vigencia de P0-3

Un blob de Git identificado por revisión es inmutable: modificar el árbol de
trabajo no invalida una cita histórica a ese blob. Validar ruta y línea contra
el blob prueba la localización de la cita, no su verdad ni su vigencia actual.
Si la corrida pretende describir el árbol actual, debe detectar divergencias y
exigir revalidación antes de presentar el hallazgo como vigente. Para árboles
sucios o sin Git hará falta guardar hashes o un snapshot del contenido; `HEAD`
por sí solo no representa esos bytes. Si la revisión no está disponible
localmente, declarar el bloqueo sin acceso a red ni sustitución silenciosa por
el árbol de trabajo.
