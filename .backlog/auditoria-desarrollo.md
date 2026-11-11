# Backlog de desarrollo y refactorización de `cgc-scan audit`

Fuente histórica: [auditoría corregida](../docs/auditoria-pendientes.md), contrastada sobre `d7b3b93`. Los estados individuales de este backlog registran la evolución posterior; la fuente histórica no es un diagnóstico del código actual. Las rutas indicadas son puntos de entrada que deben confirmarse antes de implementar.

## Estado y ruta de cierre

**Análisis actualizado:** 10 de noviembre de 2026, base `8b18490`. De las 24 tareas principales, 21 figuran completadas, P2-6 está en curso y P2-5/P2-9 están pendientes. Además siguen pendientes D-1, D-2 y D-3. Esta actualización amplía el plan; no revalida integralmente las implementaciones ni acredita pruebas nuevas.

El cierre completo exige terminar los seis frentes abiertos y verificar su integración. Excluir una tarea del release no equivale a cerrar este backlog. Las decisiones descritas como propuestas deben resolverse y documentarse durante la implementación; no son decisiones ya adoptadas ni requieren nuevas aprobaciones para elecciones rutinarias dentro del alcance autorizado.

| Paso | Trabajo pendiente | Dependencia y salida verificable | Esfuerzo orientativo |
| --- | --- | --- | --- |
| 1 | Línea base y decisiones de contrato | Estado de Git, pruebas iniciales, versiones y decisiones de P2-5/D-1/D-3 registradas | 0,5–1 día |
| 2 | P2-5: catálogo y actualización autenticada | Contrato definido; diez companions trazados, fixtures y actualización local segura | 7–15 días |
| 3 | D-1, D-2 y D-3 | Contratos finales de hardening y candidatos; escalas documentadas | 2–5 días |
| 4 | Cierre de P2-6 | P2-5 y deudas resueltas; ejemplos reproducibles, skill y trazabilidad completas | 1–3 días |
| 5 | Integración y P2-9 | Pruebas finales, migración y paquete local verificados | 2–4 días |

**Estimación restante: 12,5–28 días**, sujeta al inventario del catálogo y las decisiones de compatibilidad y firma. Es una estimación de esfuerzo, no una medición ni un plazo garantizado. Actualizarla al terminar el paso 1.

### Preparación del agente implementador

- Confirmar raíz, instrucciones aplicables, commit y cambios locales. Preservar el archivo `.backlog/.auditoria-desarrollo.md.swp` observado durante el análisis y cualquier trabajo ajeno.
- Consultar CodeGraph antes de explorar código; comprobar versiones y contratos de catálogo, estado, entregas, esquemas y paquete.
- Ejecutar `go test ./...` como línea base, registrar resultado y distinguir fallos previos de regresiones nuevas.
- Mantener las tareas completadas; reabrirlas solo con evidencia de un criterio incumplido, identificando el defecto concreto.
- Aplicar el enrutamiento de `AGENTS.md`: delegar exploración amplia o escritura no trivial según corresponda, con un único responsable por entrega. No iniciar SDD por defecto ni habilitar revisión basada en recibos. Las fases del protocolo auditado no son autorización para activar ese modo de desarrollo.
- Trabajar por entregas coherentes de código, pruebas y documentación. Registrar decisiones antes de implementar el comportamiento dependiente. Solicitar información solo cuando una decisión no pueda resolverse dentro del alcance autorizado.

### Evidencia de avance y reanudación

Al cerrar cada subtarea, añadir aquí su decisión final, archivos relevantes, referencia del commit si existe, comandos ejecutados, resultado y limitaciones. Si no existe commit, identificar el estado del árbol verificado sin inventar una referencia. Mantener el siguiente paso y los bloqueos explícitos. No marcar una tarea completada por tener código escrito o una prueba planificada.

#### Registro — paso 1: línea base y decisiones de contrato

**Fecha:** 10 de noviembre de 2026. **Base:** `8b18490`, árbol limpio salvo este
backlog y su swap (preservados). **CodeGraph:** índice activo, 232 archivos.

- **Línea base de pruebas:** `go test ./...` verde — 31 paquetes, salida 0;
  `go vet ./...` y `gofmt` sin hallazgos. Sin fallos previos que atribuir a
  regresiones.
- **Versiones vigentes:** catálogo `audit-catalog-1.1.0`; estado
  `audit-state-1.0.0`; entrega `audit-submission-1.0.0`; ledger
  `audit-ledger-1.0.0`; hallazgos `findings-1.0.0`; integridad
  `audit-integrity-1.0.0`; comparación `audit-compare-1.0.0`; importación
  `audit-import-1.0.0`; `VERSION` `0.2.0-rc.1`; skill global `1.3.0`.
- **Disponibilidad de la referencia (P2-5a):** `cloudflare/security-audit-skill`
  **no está disponible localmente** (no hay checkout ni copia en el equipo). El
  árbol de la revisión fijada `c1c8a8c1` se obtuvo de forma puntual y de solo
  lectura por HTTPS para el inventario; no se copió contenido de prompts al
  repositorio y no se reemplazó la referencia por otra versión. Los textos de
  clases nuevos serán redacción propia, como ya hace el catálogo; los
  companions aportan la estructura de dominios y clases, no su texto.
- **Inventario de los diez companions** (archivos y clases declaradas en la
  referencia fijada): WEB-PROTOCOL-AND-AUTH (20), CLIENT-SIDE (14),
  SUPPLY-CHAIN-AND-RELEASE (12), CLOUD-AND-DEPLOYMENT (15),
  PROTOCOLS-RPC-AND-MESSAGING (14), DATA-ISOLATION-AND-LIFECYCLE (15),
  DESKTOP-MOBILE-AND-LOCAL-IPC (16), MEMORY-SAFETY-AND-BINARY (20),
  AI-AND-LLM (14), RESOURCE-EXHAUSTION-AND-AVAILABILITY (13). Los dominios del
  catálogo actual ya cubren parte de supply-chain, cloud, client-side y
  protocols; el mapeo de P2-5b seleccionará clases por señales detectables en
  fuente, no 1 a 1.
- **Decisión D-3 (registrada):** el estado de verificación
  (`candidates.json`) **sigue siendo interno sin esquema público**. Motivos: no
  hay consumidor externo (el agente recibe asignaciones y entrega
  `audit-submission-1.0.0`; el estado interno lo valida y persiste el motor),
  su forma evoluciona con el protocolo (ya cambió dos veces durante este
  backlog) y publicarlo comprometería compatibilidad sin beneficio. Interfaces
  públicas declaradas: `audit-ledger.schema.json`, `findings.schema.json`,
  `report.schema.json`, `agent.schema.json`, `audit next` (tarea), entrega,
  comparación, importación y estado. Se re-evaluará si aparece un consumidor
  externo del estado.
- **Decisión D-1 (registrada):** el campo global `hardening` se conserva con su
  semántica antigua (recomendación de la unidad entregada, aplicada a todas
  las unidades que el dueño entregó) **y** se añade el campo dirigido por
  unidad, `hardening_by_unit`, con validación de que cada `coverage_id`
  referenciado pertenezca a la entrega. El campo global no se reinterpreta:
  queda documentado como deprecated-additive y la migración es el formato
  mixto (ambos coexisten; el global conserva su significado).
- **Decisión D-2 (registrada):** documentar ambas escalas junto a sus
  definiciones y en `docs/auditoria.md`; sin cambio de comportamiento.
- **Siguiente paso:** P2-5b (primeros incrementos del catálogo con fixtures).

## Reglas de ejecución

- Consultar CodeGraph antes de explorar estructura o modificar código, siguiendo `AGENTS.md`.
- Resolver las decisiones de contrato indicadas en cada tarea antes de implementar su comportamiento.
- Mantener compatibilidad con corridas existentes o proporcionar migración explícita y probada. Nunca reinterpretar silenciosamente un estado antiguo.
- Incluir código, pruebas y documentación del comportamiento modificado en la misma entrega.
- No implementar runtime de IA, ejecución del código auditado, sandbox, navegadores, parches automáticos ni atestación de verdad.
- Las pruebas de fuzzing del propio CLI sí forman parte del alcance.
- Ninguna tarea implica publicar releases, transferir archivos o ejecutar operaciones remotas.
- No activar revisiones basadas en recibos sin autorización explícita.

## Orden original de ejecución (histórico)

| Etapa | Tareas | Condición de salida |
| --- | --- | --- |
| 1. Integridad del estado | P0-5 → P0-2 → P0-1 | Cargas validadas y mutaciones serializadas y recuperables |
| 2. Evidencia y recuperación | P0-3, P0-4, P0-6 | Citas verificables, reasignación segura y entradas acotadas |
| 3. Protocolo | P1-1 → P1-3 → P1-2 → P1-4 | Perfiles, revisiones, crítica y presupuesto coherentes |
| 4. Continuidad y presentación | P1-5, P1-6 → P1-7 → P1-8; P1-9 | Prompts, continuidad, consolidación, delta e integridad |
| 5. Integración y entrega | P2-1…P2-9 | Integración, documentación, paquete y release preparados |

Este orden explica las dependencias originales; para el trabajo restante usar la ruta de cierre anterior. P2-6 se mantiene incremental. Las etapas establecen dependencias, no autorización para trabajar en paralelo.

## P0-5 — Validación semántica y estricta de candidatos

**Estado:** completada. **Dependencias:** ninguna. **Estimación original:** 1 día.

**Archivos:** `internal/audit/store.go`, `internal/audit/broker.go`.

Trabajo:

- Implementar `ValidateCandidates` y ejecutarlo al cargar y antes de persistir.
- Validar identificadores canónicos, independencia de agentes, estados, fingerprints, rama de `final` y referencias al ledger.
- Exigir coherencia de `run_id` entre documentos.
- Exigir `escalated` en `escalation`, permitiendo conservarlo como historial en `decided`.
- Exigir EOF después del objeto JSON; aceptar únicamente espacio en blanco residual.
- Devolver errores que identifiquen el candidato y la invariante incumplida.

Aceptación y pruebas:

- Rechazar verificador igual al cazador, referencias inexistentes, fingerprint divergente, rama final incorrecta y estados incompatibles.
- Rechazar un segundo objeto JSON o basura posterior.
- Aceptar estados legítimos producidos por el broker, incluido `decided` con historial de escalación.
- Una carga fallida no modifica archivos.

## P0-2 — Exclusión mutua por corrida

**Estado:** completada. **Dependencias:** P0-5. **Estimación:** 2 días.

**Archivos:** `internal/audit/store.go`, `internal/cli/audit.go`; referencia: `internal/platform/lock.go`.

Trabajo:

- Añadir bloqueo exclusivo para el ciclo completo de carga, validación, mutación y persistencia.
- Aplicarlo a `init`, `next`, `submit` y `report`; extenderlo posteriormente a `reset-unit`.
- Aplicar lectura compartida a `status` cuando sea compatible con la implementación disponible.
- Resolver la creación del bloqueo durante `init` sin dejar una ventana de carrera.
- Propagar cancelación y liberar el bloqueo en todas las salidas.

Aceptación y pruebas:

- Procesos concurrentes no asignan la misma unidad a dueños distintos ni pierden entregas.
- Las olas mantienen la semántica definida.
- Cancelar una espera no modifica la corrida.
- Probar concurrencia entre procesos y ejecutar las pruebas pertinentes con `-race`.

## P0-1 — Persistencia transaccional y recuperación

**Estado:** completada. **Dependencias:** P0-5 y P0-2. **Estimación:** 3 días.

**Decisión tomada:** estado único autoritativo (`state.json` con ledger,
candidatos y hallazgos sellados); `ledger.json`, `candidates.json` y
`findings.json` se conservan como vistas derivadas regeneradas tras cada
commit. El formato heredado de dos archivos se carga de forma explícita como
legado y migra en la primera escritura; un legado inconsistente se rechaza.

Trabajo:

- Centralizar carga y commit de una corrida en el store.
- Incluir ledger, candidatos y sellado del informe en una frontera consistente.
- Si se conservan archivos derivados, identificar su generación y regenerarlos desde el estado autoritativo.
- Definir recuperación después de interrupciones y el comportamiento ante estados antiguos inconsistentes.
- Eliminar las secuencias independientes de escritura desde la CLI.

Aceptación y pruebas:

- Inyectar fallos en cada punto de persistencia, incluida la segunda escritura.
- Al reabrir, recuperar íntegramente el estado anterior o el nuevo.
- Nunca exponer una unidad `candidate` sin candidato correspondiente.
- `status` e informe observan la misma generación.
- Repetir la recuperación no vuelve a aplicar una operación.
- Documentar qué garantías cubren caída del proceso y cuáles cubren pérdida de energía.

## P0-3 — Validación de citas y vigencia de la fuente

**Estado:** completada. **Dependencias:** P0-1. **Estimación:** 3 días.

**Decisión tomada:** el modo de fuente se declara explícitamente en el estado
interno (`state.json → source`): `revision` (snapshot de Git con árbol limpio;
las citas se resuelven contra los blobs del snapshot) o `worktree` (árbol
actual; los registros presentables sellan el hash de su fuente al crearse y
`report` declara la divergencia exigiendo revalidación). El contrato público
del ledger no cambia.

Trabajo:

- Crear un resolvedor local de fuentes para blobs Git y contenido del árbol.
- Validar rutas, existencia y límites de línea en `trace` y `evidence`.
- Definir conteo para archivos vacíos y última línea sin salto final.
- Registrar hashes o snapshot suficiente para árboles sucios o sin Git.
- Detectar divergencias cuando se requiera vigencia actual.
- No sustituir una revisión ausente por el árbol actual ni acceder a red.
- No fabricar automáticamente un `needs_validation` incompleto.

Aceptación y pruebas:

- Rechazar archivos inexistentes, líneas fuera de rango y rutas que escapen de la raíz.
- Usar un repositorio Git real con dos revisiones.
- Una cita histórica válida permanece válida aunque cambie el árbol.
- Un hallazgo no se presenta como vigente tras un cambio sin revalidación.
- Una revisión no disponible produce un bloqueo explícito.

## P0-4 — Recuperación de unidades abandonadas

**Estado:** completada. **Dependencias:** P0-1 y P0-2. **Estimación:** 2 días.

**Decisión tomada:** la ola aumenta en la siguiente asignación, no en el
reinicio; el intento archivado registra la ola que le correspondió. Solo
`in_progress` es elegible para reinicio.

Trabajo:

- Añadir `audit reset-unit --coverage-id ID --reason "..."`.
- Validar unidad, estado elegible y razón no vacía.
- Cerrar el intento abandonado como `blocked`.
- Archivar dueño, ola, razón y checks realmente disponibles.
- Devolver la unidad a `planned`, limpiando dueño y evidencia vigentes.
- Definir el incremento de ola entre reset y siguiente asignación.
- Rechazar entregas tardías del intento abandonado.

Aceptación y pruebas:

- El ledger resultante valida contra el contrato.
- Otro agente puede recibir la unidad.
- El historial permanece intacto y no contamina el nuevo intento.
- Un reset repetido o de una unidad no elegible no agrega historial falso.
- Una entrega antigua no sobrescribe el trabajo reasignado.

## P0-6 — Límites y fuzzing de entradas públicas

**Estado:** completada. **Dependencias:** P0-5. **Estimación:** 2 días.

Trabajo:

- Centralizar límites documentados: entrega 8 MiB; ledger/candidatos 16 MiB; findings 32 MiB.
- Sustituir la lectura completa previa a validación por lectura acotada.
- Aplicar límites en las API públicas de decodificación.
- Definir un límite de anidamiento y errores consistentes.
- Añadir fuzz targets para `DecodeLedger`, `DecodeFindings` y `DecodeSubmission`.
- Incorporar semillas válidas, truncadas, sobredimensionadas y anidadas.

Aceptación y pruebas:

- Probar exactamente el límite y un byte por encima.
- Ningún target entra en pánico.
- CI ejecuta 20 segundos por target.
- Las semillas válidas siguen aceptándose y los errores no provocan escrituras.

## P1-1 — Políticas explícitas por perfil

**Estado:** completada. **Dependencias:** etapa P0 completa. **Estimación:** 4 días.

**Decisión tomada:** la política de perfil vive en el catálogo versionado
(`audit-catalog-1.1.0`: metadatos por perfil, `lifecycle` por clase con
vocabulario cerrado development/distribution/runtime, y `source_version` que
fija `cloudflare/security-audit-skill@c1c8a8c1`). `profile.go` separa la
política de la construcción y selección; las fases obligatorias pendientes
(`final-critique` hasta P1-2, `prior-rework` hasta P1-6) impiden sellar la
corrida como completa.

Trabajo:

- Separar la política de perfil de la construcción y selección de unidades.
- Definir granularidad, fases obligatorias y condiciones de cierre.
- Implementar `quick` por subsistema/dominio, `standard` por subsistema/frontera/clase y `deep` por subsistema/ciclo de vida.
- Versionar los metadatos de catálogo necesarios.
- Fijar la versión de cualquier referencia externa usada para definir el protocolo.
- Preparar la integración con P1-2 y P1-3.

Aceptación y pruebas:

- Un mismo fixture produce diferencias justificadas entre perfiles.
- IDs y orden son deterministas.
- El informe declara perfil y alcance.
- Ningún perfil aparece completo mientras le falten fases obligatorias todavía no implementadas.

## P1-3 — Dos pasadas y reemplazos materiales

**Estado:** completada. **Dependencias:** P1-1. **Estimación:** 4 días.

**Decisión tomada:** la segunda pasada (`final_review`) aplica a los perfiles
con dos verificaciones (`standard`, `deep`); el candidato decidido pasa a
`review_pending` y un revisor independiente lo aprueba o reemplaza. La
materialidad (`MaterialChange`: veredicto, causa raíz, traza, ejecución,
impacto, severidad) solo se aplica en la revisión final; `quick` conserva su
escalación por rango de veredicto.

Trabajo:

- Separar validación del candidato y revisión del registro final.
- Definir transiciones e independencia de agentes para ambas fases.
- Comparar materialidad por causa raíz, traza, ejecución, impacto y severidad.
- Mantener el reemplazo propuesto pendiente hasta su revisión independiente.
- Preservar historial y ampliar la validación de candidatos.
- Mantener el comportamiento previsto de `quick`, incluida su escalación existente.

Aceptación y pruebas:

- Un reemplazo material no llega al informe final sin revisión independiente.
- El revisor requerido no es cazador, validador ni autor del reemplazo.
- Probar promociones, degradaciones, cambios materiales y cambios editoriales.
- Reabrir una corrida conserva la fase pendiente.

## P1-2 — Crítica independiente de cobertura

**Estado:** completada. **Dependencias:** P0-4, P1-1 y P1-3. **Estimación:** 6 días.

**Decisión tomada:** el estado de crítica vive en el ledger (campo `critique`,
esquema actualizado antes del release). El crítico se emite cuando la ola
completa y no puede tener unidades en curso; solo `in_progress` y `covered`
son elegibles para reasignación por crítica. La respuesta limpia —sin
`missing_units` ni `reassign_ids`— habilita el cierre.

Trabajo:

- Añadir `critique` como nuevo tipo de tarea junto a los tres existentes.
- Definir independencia, entradas y respuesta del crítico.
- Admitir `missing_units`, `reassign_ids`, `resolved_prior_leads` y `stop`.
- Reutilizar la creación de unidades utilizada por `uncovered`.
- Archivar intentos al reasignar.
- Registrar crítica por ola y crítica final según perfil.

Aceptación y pruebas:

- Una superficie omitida genera trabajo, se procesa y vuelve a crítica.
- Repetir una propuesta no duplica unidades.
- Un `stop` no evita requisitos pendientes.
- `standard` y `deep` no cierran sin crítica final limpia.
- El informe distingue crítica limpia, pendiente y no requerida.

## P1-4 — Presupuesto reservado y agotamiento coherente

**Estado:** completada. **Dependencias:** P1-1, P1-2 y P1-3. **Estimación:** 3 días.

**Decisión tomada:** reserva determinista en enteros: el reparto de caza se
niega si `used + 1 + reservas > max`, con reservas = pasadas de verificación
del perfil (1 por pasada) + 1 de crítica final cuando el perfil la exige y aún
no corrió limpia. El agotamiento unificado difiere y sella en las tres fases
antes de responder.

Trabajo:

- Definir fórmula de reserva, redondeo y coste por fase.
- Reservar crítica final y verificaciones antes de repartir caza.
- Contabilizar asignaciones nuevas sin cobrar de nuevo su recuperación.
- Unificar agotamiento en caza, verificación y crítica.
- Persistir estado y razones antes de emitir mensajes de CLI.
- Corregir el mensaje actual que anuncia un sellado inexistente.

Aceptación y pruebas:

- Tabla de presupuestos: cero, insuficiente, exacto y excedente.
- No asignar caza si deja sin reserva las fases obligatorias.
- CLI y estado persistido coinciden.
- Reiniciar no reinicia el presupuesto ni duplica consumos.

## P1-5 — Render de tareas como prompt

**Estado:** completada. **Dependencias:** contratos de tareas de P1-2 y P1-3. **Estimación:** 3 días.

**Decisión tomada:** la plantilla vive embebida en `internal/audit/prompt/v1.tmpl`
(siguiendo el patrón de `internal/report/prompt`); el bloque de datos de la
tarea se renderiza en Go con saneado de todo el contenido interpolado. El
nonce es aleatorio salvo en pruebas, que fijan uno propio no conflictivo.

Trabajo:

- Añadir `--format prompt`, conservando JSON y texto.
- Incluir contexto, invariante, checks, rutas y contrato de respuesta.
- Reutilizar saneado y delimitadores con nonce del render existente.
- Tratar contenido del proyecto como datos no confiables.
- Permitir nonce controlado en pruebas.

Aceptación y pruebas:

- Golden tests por tipo de tarea con nonce fijo.
- ANSI, controles y delimitadores aparentes no rompen el aislamiento.
- El render no cambia la asignación ni consume presupuesto adicional.
- El formato JSON mantiene compatibilidad.

## P1-6 — Continuidad verificable entre corridas

**Estado:** completada. **Dependencias:** P0-3 y P1-3. **Estimación:** 6 días.

**Decisión tomada:** la identidad de una unidad son sus rutas de partida con
el hash de su fuente, archivadas en `state.json` (`unit_identity`) al sellar el
informe; la corrida siguiente compara y declara modificados, añadidos y
eliminados. La reutilización orientativa caduca con el catálogo o el perfil.

Trabajo:

- Extraer un helper reutilizable de hash sin duplicar implementaciones.
- Definir qué archivos y condiciones forman la identidad de una unidad.
- Detectar archivos modificados, añadidos y eliminados.
- Importar confirmados previos como trabajo de revalidación.
- Reabrir rechazados cuando cambien sus condiciones.
- Mantener cobertura aunque una unidad haya sido auditada anteriormente.

Aceptación y pruebas:

- Cambios afectan todas las unidades dependientes y preservan las independientes.
- Un confirmado previo nunca se copia directamente como confirmado actual.
- Un rechazado sin cambios evita repetir la misma afirmación.
- Cambios de catálogo, perfil o condiciones relevantes invalidan la reutilización correspondiente.

## P1-7 — Consolidación por causa raíz y orden explicable

**Estado:** completada. **Dependencias:** P1-3 y P1-6. **Estimación:** 2 días.

**Decisión tomada:** la identidad de causa raíz es explícita
(`root_cause_ref` en el contrato público de hallazgos, opcional); la
selección del representativo es (veredicto desc, fingerprint asc) y el motivo
se archiva con las variantes en `merged_into`.

Trabajo:

- Definir una identidad explícita de causa raíz; no usar similitud textual como prueba suficiente.
- Conservar fingerprints de origen y relaciones de consolidación.
- Establecer selección determinista de evidencia representativa.
- Mantener la evidencia complementaria y la independencia de revisión.
- Registrar motivo y desempate de cada asignación.

Aceptación y pruebas:

- Dos variantes comprobadas del mismo defecto generan un registro consolidado.
- Defectos distintos con títulos similares permanecen separados.
- Cambiar el orden de entrada no cambia el resultado.
- Cada asignación permite reconstruir por qué fue elegida.

## P1-8 — Comparación entre auditorías

**Estado:** completada. **Dependencias:** P1-6 y P1-7. **Estimación:** 3 días.

**Decisión tomada:** la resolución exige evidencia de evaluación actual
(registro refutado en la corrida actual, o corrida actual completa sin
recurrencia); los registros marcados con cambio de fuente nunca se declaran
resueltos. Solo lectura.

Trabajo:

- Añadir `audit compare [anterior actual]`.
- Definir clasificación `new`, `persistent`, `resolved`, `not_evaluated`.
- Usar fingerprints y relaciones de consolidación.
- Exigir evidencia de evaluación actual para declarar resolución.
- Emitir salida estable y rechazar versiones incompatibles.

Aceptación y pruebas:

- Corridas parciales, bloqueadas o sin cobertura no producen falsos `resolved`.
- Probar cambios de fuente, consolidaciones y registros rechazados.
- La comparación no modifica las corridas.

## P1-9 — Integridad verificable del informe

**Estado:** completada. **Dependencias:** P0-1 y contratos finales de informe. **Estimación:** 3 días.

**Decisión tomada:** clave local dedicada en el directorio de configuración
(0600, creada al sellar); el HMAC cubre ledger y hallazgos en serialización
canónica idempotente, excluyendo su propio valor; se sella en el commit del
informe y `--verify` es solo lectura con diagnóstico explícito por fallo.

Trabajo:

- Crear una clave secreta local dedicada con almacenamiento privado.
- Definir serialización canónica, versión y campos cubiertos.
- Excluir el propio valor de autenticación del contenido autenticado.
- Integrar generación del HMAC en el commit del informe.
- Añadir `audit report --verify` sin reescritura.
- Definir tratamiento de informes antiguos sin integridad.

Aceptación y pruebas:

- Modificar ledger o registros invalida la verificación.
- Clave ausente, incorrecta o reemplazada produce diagnóstico explícito.
- La clave nunca aparece en informes, logs ni paquetes.
- Documentar que el HMAC no prueba la verdad ni protege frente a quien posee la clave.

## P2-1 — Importación de leads desde `scan` y `agent`

**Estado:** completada. **Dependencias:** P1-6 y P1-7. **Estimación:** 4 días.

**Decisión tomada:** cada hallazgo no suprimido se convierte en unidad lead
planificada (`import/<unidad-del-motor>/<fingerprint>`); el veredicto
`needs_validation` se emite solo cuando el motor aporta bloqueos
(`verification.missing`) y plan (`verification.rescan`). Los datos originales
se archivan en `state.json` (`imported_leads`), separados del veredicto.

Aceptación y pruebas:

- Ningún hallazgo importado aparece automáticamente como confirmado.
- La severidad del motor no se convierte en severidad auditada.
- Importar dos veces produce el mismo trabajo pendiente.
- Entradas incompatibles o corruptas no dejan estado parcial.

## P2-2 — Explicación y observabilidad

**Estado:** completada. **Dependencias:** P0-1, P0-4 y contratos P1. **Estimación:** 2 días.

Trabajo:

- Añadir `audit explain` por unidad o fingerprint.
- Mostrar estado, historial, razones, revisiones y próximos requisitos.
- Listar unidades bloqueadas y diferidas en `status`.
- Mejorar `audit next --format text`.
- Si se incluyen huellas pendientes truncadas, detectar ambigüedades.

Aceptación y pruebas:

- `status` y `explain` no reescriben artefactos.
- Sus salidas coinciden con el estado persistido.
- Identificadores inexistentes o ambiguos producen errores útiles.

## P2-3 — Política de salida para CI

**Estado:** completada. **Dependencias:** P1-4. **Estimación:** decisión de producto + 2 días.

**Decisión de producto tomada:** umbrales `confirmed`, `needs_validation` o
severidad auditada (overall ≥ umbral); precedencia cancelación (130) → error
operativo (2) → corrida incompleta (3) → umbral incumplido (1) → éxito (0);
sin flag, compatibilidad: corrida completa → 0. Difiere de `scan --fail-on`,
que cuenta hallazgos del motor.

Trabajo:

- Añadir `--fail-on` según la decisión documentada.
- Centralizar el cálculo del código de salida.
- Diferenciar la política de `scan --fail-on`.
- Mantener el comportamiento sin flag según compatibilidad acordada.

Aceptación y pruebas:

- Matriz de severidades, veredictos, completitud y errores.
- La política de salida no altera hallazgos ni estado.
- Ayuda y documentación describen los códigos efectivos.

## P2-4 — Destinos seguros para `--out`

**Estado:** completada. **Dependencias:** ninguna. **Estimación:** 1 día.

**Decisión de producto tomada:** se **rechaza** (no se advierte) el destino
interno no ignorado; en proyectos sin Git también se rechaza porque la
exclusión no se puede verificar. El escape por enlace simbólico se resuelve
como destino externo.

Trabajo:

- Resolver rutas relativas, inexistentes y enlaces simbólicos.
- Determinar pertenencia al repositorio y exclusión efectiva por Git.
- Definir comportamiento en proyectos sin Git.
- Ejecutar la comprobación antes de crear artefactos.

Aceptación y pruebas:

- Cubrir destino externo, interno ignorado, interno visible y escape mediante enlace.
- La comprobación no modifica `.gitignore`.
- Un rechazo no deja una corrida parcial.

## P2-5 — Catálogo ampliado y actualización autenticada

**Estado:** pendiente. **Dependencias:** P1-1. **Estimación original:** 5–10 días; reestimar tras definir distribución y firma.

Trabajo:

- Fijar la versión de referencia y mapear los diez companions a dominios y clases.
- Añadir dominios por incrementos con señales, checks y fixtures positivos y negativos.
- Versionar catálogo y reglas de compatibilidad.
- Definir formato firmado, confianza, rechazo de firmas inválidas y protección frente a versiones incompatibles.
- Preparar la herramienta de actualización sin realizar publicaciones remotas.

Aceptación y pruebas:

- Cada clase nueva tiene fixture y comportamiento esperado.
- La ausencia de señales no se presenta como cobertura.
- Un catálogo alterado o incompatible se rechaza.
- Las corridas conservan la versión usada.

### Desglose ejecutable de P2-5

- [ ] **P2-5a — Inventario y contrato.** Confirmar la referencia `cloudflare/security-audit-skill@c1c8a8c1` fijada en P1-1 y su disponibilidad local; si no está disponible, registrar el bloqueo de fidelidad sin inventar su contenido ni reemplazarla silenciosamente por una versión remota. Mapear web/auth, cliente, cadena de suministro, cloud, protocolos, aislamiento de datos, escritorio/móvil, memoria/binario, IA/LLM y agotamiento de recursos a clases, señales, invariantes y checks, sin exigir correspondencia uno a uno entre companion y dominio. Documentar límites de aplicabilidad; una exclusión debe justificarse y no contar como cobertura implementada.
- [ ] **P2-5b — Incrementos del catálogo.** Añadir grupos coherentes con fixture positivo y negativo por clase. Extender el vocabulario de señales solo cuando sea necesario. Comprobar selección, IDs y orden deterministas en quick/standard/deep. Separar reconocimiento de superficie de evidencia de cobertura.
- [ ] **P2-5c — Compatibilidad y continuidad.** Definir versiones aceptadas y migraciones. Conservar versión, identidad y política del catálogo de cada corrida; actualizar el catálogo instalado no debe reinterpretar corridas anteriores. Probar reapertura, continuidad e invalidación de reutilización tras cambios de catálogo.
- [ ] **P2-5d — Formato firmado y confianza.** Definir algoritmo, bytes autenticados, identificador de clave y límites de lectura. Propuesta: claves públicas de confianza separadas de la clave privada de firma; ninguna clave privada en repositorio, informes o paquetes. Documentar incorporación/rotación de claves y rechazo de claves desconocidas. Definir política de retroceso y recuperación; no prometer protección antirretroceso sin estado o reglas que la hagan verificable. Usar claves desechables en pruebas.
- [ ] **P2-5e — Actualización local.** Implementar una entrada de archivo local, verificar firma y compatibilidad antes de activar y sustituir de forma atómica. Definir qué ocurre ante interrupción, actualización repetida y catálogo inválido. No descargar, publicar ni transferir archivos remotamente como parte de esta tarea.
- [ ] **P2-5f — Pruebas y documentación.** Cubrir catálogo válido, alterado, truncado, sobredimensionado, firma inválida, clave desconocida, versión incompatible, política de retroceso e interrupción. Un rechazo conserva el catálogo activo y las corridas. Documentar el comando real, confianza, recuperación y límites.

Dependencias internas: a → b/c/d → e → f. La división permite entregas pequeñas; no presupone ejecución paralela. Para cerrar P2-5 deben estar resueltas todas las decisiones y entregados todos los componentes comprometidos, no solo ampliado el JSON.

## P2-6 — Requisitos, aceptación y documentación

**Estado:** en curso. **Dependencias:** incremental durante todo el backlog. **Estimación:** 3 días.

**Entregado:** RF-39…RF-56 de auditoría en §7.6 con su trazabilidad a tarea y
criterio; CA-73…CA-91 nuevos sin renumerar; comandos, perfiles, recuperación,
presupuesto, fuentes, integridad y límites documentados en
`docs/auditoria.md`. **Pendiente:** actualizar los ejemplos de `docs/uso.md` y
la skill incluida.

Trabajo:

- Añadir RF de auditoría a `requisitos-cli-seguridad.md`.
- Añadir CA con IDs nuevos sin renumerar CA-01…CA-72.
- Vincular cada requisito con tarea, prueba y comportamiento observable.
- Documentar comandos, perfiles, recuperación, presupuesto, fuentes, integridad y límites.
- Actualizar ejemplos y skill incluida conforme se entreguen funciones.

Aceptación:

- Cada comando documentado existe y sus ejemplos son reproducibles.
- Funciones pendientes están identificadas como pendientes.
- La documentación diferencia validación estructural, independencia y verdad del hallazgo.

### Trabajo restante de P2-6

- [ ] **P2-6a — Ejemplos.** Actualizar `docs/uso.md` con el ciclo init/next/submit/status/explain/reset-unit/report/verify/compare y los formatos soportados, usando la sintaxis real. Añadir el flujo de catálogo cuando P2-5 lo entregue; ejecutar ejemplos en un entorno local aislado.
- [ ] **P2-6b — Skill incluida.** Actualizar `skills/cgc-scan/SKILL.md` conforme a los contratos finales: perfiles, independencia, presupuesto, fuentes, recuperación, hardening y catálogo. No describir funciones pendientes como existentes.
- [ ] **P2-6c — Trazabilidad.** Revisar RF-39…RF-56 y CA-73…CA-91; vincular tarea → requisito → aceptación → prueba o evidencia observable. Añadir IDs nuevos si faltan criterios para catálogo o deuda sin renumerar los existentes.
- [ ] **P2-6d — Coherencia.** Contrastar ayuda CLI, ejemplos y `docs/auditoria.md`. Explicar por separado estructura, independencia, integridad y verdad del hallazgo. Cerrar después de P2-5 y D-1/D-3, conservando actualizaciones incrementales.

## P2-7 — Paquete autosuficiente con esquemas

**Estado:** completada. **Dependencias:** ninguna para el defecto actual. **Estimación:** 1 día.

**Archivo principal:** `install.sh`.

**Decisión tomada:** el instalador exige el directorio `schemas/` con los
cuatro esquemas públicos (paquete o checkout) y verifica su concordancia con
el binario; sin esquemas la instalación falla explícitamente.

Trabajo:

- Incluir los cuatro esquemas públicos indicados en la auditoría.
- Mantener concordancia entre esquemas, binario y versión.
- Evitar omitir silenciosamente la validación por ausencia de esquema.
- Probar instalación desde el paquete extraído en un destino aislado.

Aceptación y pruebas:

- El paquete contiene esquemas, documentación, skill y binario esperados.
- La comprobación de versión se ejecuta.
- Un esquema ausente o incompatible produce un error explícito.
- No depende del checkout original para instalarse.

## P2-8 — E2E, benchmarks y eliminación del recorrido duplicado

**Estado:** completada. **Dependencias:** P0 y protocolo P1 para el E2E completo. **Estimación:** 2 días.

**Decisión tomada:** `DetectRoot` se resuelve una vez por corrida de comandos
y se reutiliza entre el estado del proyecto y el ledger. Mediciones registradas
(`internal/audit/bench_test.go`): en el fixture de monorepo del repositorio,
quick ≈1,6 ms/op (821 allocs), standard ≈2,0 ms/op (989 allocs), deep ≈1,7 ms/op
(780 allocs) en Apple M1 con 10 iteraciones. Los fuzz targets de P0-6 viajan
una sola vez en CI.

Aceptación y pruebas:

- Reducir recorridos sin eliminar cobertura ni cambiar IDs injustificadamente.
- Registrar mediciones antes y después con el mismo fixture.
- El E2E no necesita red ni proveedor de IA.
- Las pruebas CLI existentes siguen pasando.

## P2-9 — Preparación de release

**Estado:** pendiente. **Dependencias:** tareas comprometidas para la versión, P2-6, P2-7 y P2-8. **Estimación:** 1 día.

Trabajo:

- Seleccionar versión conforme a compatibilidad.
- Convertir «Sin publicar» en notas con funciones, cambios de formato y migración.
- Sincronizar `VERSION`, skill, documentación y esquemas.
- Construir y verificar el paquete final.
- Registrar tareas excluidas de la versión.

Aceptación:

- Pruebas requeridas y prueba de instalación aprobadas.
- Las notas describen únicamente funciones entregadas.
- La preparación termina con artefactos locales verificables; publicación y tag quedan fuera de esta tarea.

### Secuencia de cierre de P2-9

- [ ] Elegir versión después de conocer los cambios reales de compatibilidad, incluidos D-1/D-3 y catálogo.
- [ ] Actualizar notas, `VERSION`, skill y documentación; cambiar versiones de esquemas y catálogo solo cuando su contrato lo requiera, no para igualarlas artificialmente al binario.
- [ ] Describir migración y funciones entregadas; distinguir limitaciones del producto y tareas aún abiertas.
- [ ] Construir el paquete final con la versión definitiva y repetir su comprobación de instalación aislada. Registrar ubicación, contenido y checksum del artefacto local.
- [ ] Terminar con artefactos locales verificables. No crear tag, publicar release, hacer push ni usar sesiones remotas.

## Deuda complementaria

| ID | Trabajo | Dependencia | Aceptación |
| --- | --- | --- | --- |
| D-1 | Asociar `hardening` a unidades explícitas y definir compatibilidad del campo global | P0-5 | Una recomendación dirigida a una unidad no se propaga a las demás |
| D-2 | Documentar la diferencia entre `VerdictRank` y `severityRank` | Ninguna | Comentarios y documentación explican sus dominios y usos |
| D-3 | Decidir si candidatos requiere esquema público | P1-3 | Decisión documentada; si se publica, esquema versionado, validado y empaquetado |

Estas tareas están pendientes y no tienen estimación en el documento base. El historial de intentos queda cubierto por P0-4; las huellas pendientes, por P2-2; el recorrido duplicado, por P2-8.

### Desglose de deuda pendiente

- [ ] **D-1a:** diseñar la asociación explícita de hardening a `coverage_id` y su validación. Rechazar referencias inexistentes o ajenas a la entrega cuando corresponda.
- [ ] **D-1b:** definir la compatibilidad del campo global heredado. Preservar explícitamente su semántica antigua o proporcionar migración versionada; no reinterpretarlo ni perder recomendaciones silenciosamente. Definir qué ocurre al combinar campos antiguos y nuevos.
- [ ] **D-1c:** implementar persistencia y presentación; actualizar contratos/esquemas si corresponde. Probar entregas con varias unidades, asignación dirigida, formato antiguo, formato mixto y rechazo sin escritura parcial.
- [ ] **D-2:** documentar junto a las definiciones y en la documentación del protocolo que `VerdictRank` ordena fuerza del veredicto y `severityRank` severidad. Explicar los usos sin cambiar su comportamiento ni confundir ambas escalas.
- [ ] **D-3:** registrar una decisión con sus motivos. Propuesta inicial: conservar candidatos como formato interno si no hay consumidor externo que justifique un contrato público. Si se publica, versionar y validar el esquema, incorporarlo al paquete y a las comprobaciones del instalador, y probar ausencia/incompatibilidad. En ambos casos documentar qué interfaces sí son públicas.

## Criterio común de cierre

Una tarea termina cuando cumple sus criterios, incorpora pruebas de sus fallos relevantes, mantiene contratos coherentes y documenta cualquier migración. Ejecutar pruebas focalizadas durante el desarrollo y `go test ./...` antes de entregar cambios de código; usar `-race`, fuzzing y pruebas de instalación donde corresponda.

### Validación final del conjunto

- [ ] Pruebas focalizadas de cada cambio y `go test ./...` satisfactorios sobre el estado final.
- [ ] `-race` en las áreas de estado/concurrencia modificadas y pruebas de recuperación pertinentes.
- [ ] Campañas de 20 segundos por target real de fuzzing de audit; confirmar nombres en el repositorio y conservar las semillas y configuración CI existentes. Añadir cobertura del nuevo decodificador de catálogo si se introduce.
- [ ] E2E local sin proveedor de IA: asignación, entrega, revisión/crítica según perfil, sellado, integridad, comparación y continuidad. Cubrir cambios de catálogo y compatibilidad heredada.
- [ ] Instalación desde paquete extraído en destino aislado, sin depender del checkout; comprobar binario, documentación, skill, catálogo y todos los esquemas públicos finales. Probar errores por esquema ausente o incompatible.
- [ ] Ayuda y ejemplos reproducibles; notas de release describen solo lo entregado. Ninguna clave privada o secreto en el paquete.
- [ ] P2-5, P2-6, P2-9 y D-1…D-3 cerrados con evidencia. Toda regresión detectada tiene resolución o bloqueo explícito; un bloqueo impide declarar cierre completo.

Las estimaciones originales de **68–73 días** corresponden al backlog histórico completo, sin deuda complementaria ni contingencias. No representan el esfuerzo restante; usar la estimación y secuencia de la ruta de cierre al inicio de este documento.
