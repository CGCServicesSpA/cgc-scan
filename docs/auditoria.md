# Auditoría asistida

`cgc-scan audit` implementa el **protocolo determinista** de una auditoría
asistida por un agente externo: cobertura declarada, asignaciones, verificación
independiente y reportes con tres veredictos.

No es un motor de IA. La CLI **no llama a un modelo, no ejecuta código del
proyecto y no contacta servicios externos**. El agente que invoca la CLI aporta
la evidencia; el motor valida estructura y consistencia, reparte trabajo,
contabiliza el presupuesto y deja constancia de lo que no se cubrió.

## Por qué existe

Un escaneo (`scan`/`agent`) responde «qué dicen los motores». Una auditoría
responde «qué falla de frontera se demostró y qué quedó sin probar». Son
preguntas distintas y no deben mezclarse: un candidato sin veredicto final no
hereda la severidad de una regla de Trivy.

## Flujo

```bash
cgc-scan audit init . --profile standard --budget 12
cgc-scan audit next . --agent hunter-a            # asignación de caza
# el agente caza y guarda su entrega en entrega.json
cgc-scan audit submit . --file entrega.json
cgc-scan audit next . --agent verifier-a          # verificación independiente
cgc-scan audit submit . --file verificacion.json
cgc-scan audit report .                           # findings.json + reportes
cgc-scan audit status .                           # resumen sin escribir
```

`--out DIR` fija el directorio de la corrida. Por defecto vive en el estado del
proyecto (`<cache>/cgc-scan/projects/<id>/audit`), nunca dentro del proyecto.

## Contratos

| Documento | Versión | Qué es |
| --- | --- | --- |
| `state.json` | `audit-state-1.0.0` | **Estado autoritativo**: ledger, estado de verificación y, si la corrida se selló, hallazgos en una sola frontera de commit |
| `ledger.json` | `audit-ledger-1.0.0` | Vista derivada de cobertura; se regenera desde `state.json` tras cada commit |
| `findings.json` | `findings-1.0.0` | Vista derivada de hallazgos con veredicto final, sin mezclar veredictos |
| `candidates.json` | interno | Vista derivada del estado de verificación (pendiente, escalación, decidido) |
| `audit next` | `audit-task-1.0.0` | Asignación que el agente debe cumplir |
| entrega | `audit-submission-1.0.0` | Resultado del agente para `audit submit` |

Los esquemas públicos viven en [`schemas/`](../schemas/):
`audit-ledger.schema.json` y `findings.schema.json`.

## Veredictos

| Veredicto | Qué significa | Severidad |
| --- | --- | --- |
| `confirmed` | Traza completa y resultado local acotado | Sí, acotada al impacto demostrado |
| `needs_validation` | Hipótesis de frontera con un hecho decisivo fuera de la fuente | **No** |
| `rejected` | El candidato fue refutado; queda para no repetirlo | No |

Reglas que el validador impone:

- un `needs_validation` no puede llevar `severity`, `execution` ni `remediation`;
- un `confirmed` exige `execution.observed_result` no vacío y
  `overall_severity ≤ impact`;
- una traza empieza en `entrypoint` y termina en `sink`; los pasos intermedios
  son `propagation`;
- todas las rutas son relativas al repositorio, sin `..` ni absolutas;
- un fingerprint no se repite y no cambia entre veredictos.

`findings.json` declara su procedencia:

```json
"provenance": {
  "attested_by": "caller",
  "engine_verified": false,
  "engine_role": "structure-and-consistency"
}
```

El motor **no** afirma que un hallazgo sea cierto: afirma que el registro cumple
el contrato. El reporte lo repite.

## Independencia y presupuesto

- Un agente no puede verificar un candidato que cazó.
- Un agente no puede repetir una verificación ya emitida.
- Una **promoción** de veredicto (`needs_validation` → `confirmed`) exige un
  segundo verificador distinto; mientras tanto el candidato queda en
  `escalation` y no entra a `findings.json`.
- `--budget N` cuenta invocaciones de agente. Si se agota con unidades
  pendientes, la corrida queda `incomplete` con razón `budget_exhausted` y esas
  unidades pasan a `deferred`. Nunca se excede el presupuesto en silencio.
- `audit reset-unit --coverage-id ID --reason "..."` recupera una unidad
  abandonada: cierra el intento vigente como `blocked` con la razón dada,
  archiva dueño, ola y checks realmente disponibles, y devuelve la unidad a
  `planned` con evidencia limpia. La ola aumenta en la **siguiente
  asignación**, no en el reinicio; el intento archivado registra la ola que le
  correspondió. Una entrega tardía del intento abandonado se rechaza por el
  estado y el dueño nuevos, y un reinicio repetido o de una unidad no
  elegible no agrega historial falso.

## Validación del estado de verificación

`candidates.json` es interno, pero no se confía en él: se valida semánticamente
al cargarlo y antes de persistirlo (`ValidateCandidates`), siempre contra el
ledger de la corrida. Cada error identifica al candidato y a la invariante
incumplida.

Se rechaza un estado que:

- declare un `run_id` distinto del ledger o referencie unidades inexistentes;
- tenga un candidato cuyo `unit` no lo declare en `candidate_fingerprints`, o
  viceversa;
- asigne la verificación al propio cazador, repita un verificador o conserve
  `assigned_to` en un candidato `decided`;
- mezcle fingerprints entre `proposed`, `escalated`, los intentos archivados y
  `final`;
- incumpla la rama de cada estado: `escalation` exige `escalated` con un
  veredicto que supere al propuesto; `decided` exige `final` y que coincida con
  el último intento archivado; `pending` no lleva intentos ni registros finales.
  `decided` puede conservar `escalated` como historial de la escalación;
- traiga un registro cuyo veredicto no corresponde a su autor: el cazador solo
  propone `confirmed` o `needs_validation`;
- lleve campos desconocidos o contenido JSON después del objeto (solo se
  acepta espacio en blanco residual).

Una carga fallida no modifica archivos. Si falta `candidates.json` con un
ledger presente, la corrida se declara dañada (`ErrNoCandidates`) en lugar de
reinterpretarse como vacía.

## Persistencia transaccional

El estado de una corrida vive en un solo archivo, `state.json`, que se escribe
y se lee con una operación atómica (temporal + `rename` + `fsync` del
directorio). Ledger, estado de verificación y —en el sellado— hallazgos
quedan dentro de la misma frontera: una interrupción deja íntegro el estado
anterior o el nuevo, nunca un punto intermedio.

- `ledger.json`, `candidates.json` y `findings.json` son **vistas derivadas**
  informativas: se regeneran desde `state.json` tras cada commit. Si una
  escritura de vista falla, el estado ya está íntegro y el error lo declara;
  repetir el comando regenera las vistas y no vuelve a aplicar operación
  alguna.
- Los archivos temporales abandonados (`.state.json.tmp-*`) son residuos
  inofensivos de una interrupción y se ignoran al cargar.
- **Formato heredado:** una corrida creada antes del estado único (solo
  `ledger.json` + `candidates.json`) se carga de forma explícita como legado y
  la primera escritura la migra a `state.json`. Un legado inconsistente —un
  ledger sin estado de verificación, o hallazgos de otra corrida— se rechaza;
  nunca se reinterpreta silenciosamente un estado antiguo.
- Qué cubre cada garantía: la escritura atómica protege contra la **caída del
  proceso** en cualquier punto; contra la **pérdida de energía** protegen el
  `fsync` del archivo y del directorio antes de responder.

## Perfiles

`--profile` cambia la granularidad del reparto, nunca el listón de evidencia.
La política vive en el catálogo versionado (`internal/audit/catalog.json`,
`audit-catalog-1.1.0`) y se separa de la construcción y selección de unidades
(`internal/audit/profile.go`):

| Perfil | Granularidad | Verificación | Crítica de cobertura |
| --- | --- | --- | --- |
| `quick` | subsistema × dominio | una pasada | no requerida |
| `standard` | subsistema × frontera × clase | dos pasadas | por ola + final |
| `deep` | subsistema × ciclo de vida | dos pasadas | por ola + final, y revalidación de corridas anteriores |

- Las unidades colapsadas (`quick`, `deep`) usan la clase representativa de
  mayor prioridad aplicable para el invariante y los checks de la asignación.
- Los ids de `quick` son `subsistema/dominio` con frontera `domain-wide`; los
  de `deep` son `subsistema/lifecycle/etapa` con dominio `lifecycle`. El orden
  y los ids son deterministas.
- Cada clase declara su **ciclo de vida** (`development`, `distribution`,
  `runtime`) en el catálogo; el vocabulario es cerrado y versionado.
- Las **fases obligatorias** por perfil (`hunt`, `verification`,
  `final-critique`, `prior-rework`) deben completarse antes de que la corrida
  se declare completa: `audit report` rechaza el sellado con la razón
  `phase_not_implemented` y una limitación que nombra la fase pendiente.
- La referencia externa que define el protocolo está fijada en el catálogo
  (`source_version`): los conceptos de cobertura, veredictos y verificación
  independiente se adaptaron de
  [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill)
  en la versión indicada; los textos del catálogo son propios.

## Verificación en dos pasadas

Con los perfiles con dos pasadas (`standard` y `deep`), **validar el candidato**
y **revisar el registro final** son fases distintas:

- **Primera pasada:** el verificador independiente valida el candidato
  (`verify`) y decide; una promoción escala como siempre. Con las dos pasadas
  activas, el registro decidido pasa a `review_pending` en vez de `decided`.
- **Segunda pasada:** un revisor independiente —que no es el cazador, ningún
  validador previo ni el autor de un reemplazo— recibe la tarea
  `final_review` con el registro final y lo aprueba (`verified`) o lo
  reemplaza (`replace` con registro).
- **Materialidad:** un reemplazo es **material** si altera veredicto, causa
  raíz, traza, ejecución, impacto o severidad (`MaterialChange`). Un
  reemplazo material no llega al informe: queda pendiente en `escalation`
  hasta que un verificador independiente del autor del reemplazo lo confirme,
  y el registro confirmado vuelve a revisión final. Un reemplazo editorial
  (solo redacción: título, descripción, confianza, condiciones) se aplica sin
  otra firma.
- `quick` conserva una pasada: decide en la misma verificación y su
  escalación existente compara solo el rango del veredicto.
- Reabrir una corrida conserva la fase pendiente: un candidato en
  `review_pending` sigue esperando su revisión.

## Crítica de cobertura

Los perfiles `standard` y `deep` exigen crítica independiente de cobertura;
`quick` no la requiere. Cuando la ola de caza completó (sin unidades
planificadas ni en curso y sin verificación pendiente), el motor emite la
tarea `critique` a un agente sin unidades en curso: no critica su propio
trabajo incompleto. El crítico responde con:

- `missing_units`: superficies que merecen unidad propia; se convierten en
  unidades planificadas con la misma creación que `uncovered`, y la caza las
  procesa antes de una nueva crítica;
- `reassign_ids`: unidades a reasignar por evidencia débil; el intento vigente
  se archiva con dueño, ola y checks, y la unidad vuelve a `planned`;
- `resolved_prior_leads`: hallazgos de corridas anteriores que el crítico
  resolvió; se registran para la revalidación;
- `stop`: pide cerrar el reparto; se archiva con su razón y **no evita los
  requisitos pendientes**: si la respuesta trae trabajo nuevo, la crítica no
  queda limpia.

Una crítica limpia (sin trabajo nuevo) habilita el cierre. Los perfiles
`standard` y `deep` no se declaran completos sin crítica final limpia
(`critique_pending`); `audit report` distingue crítica limpia, pendiente y no
requerida. Repetir una propuesta no duplica unidades.

## Fuentes y citas

Toda cita (`trace[].file`, `evidence[].file`) se valida contra la fuente que
la corrida declara. El modo de fuente se declara explícitamente en el estado
interno (`state.json`, campo `source`); el contrato público del ledger no
cambia:

- **`revision`**: la corrida describe el snapshot de una revisión de Git con
  el árbol limpio al iniciar. Las citas se resuelven contra los blobs de esa
  revisión (`git cat-file`, todo local, sin red) y **permanecen válidas
  aunque el árbol cambie después**.
- **`worktree`**: la corrida describe el árbol actual de trabajo (sin Git o
  con árbol sucio). Las citas se validan contra el árbol y cada registro
  presentable registra el hash de la fuente de sus archivos al crearse.

Reglas:

- En `submit`, cada registro de la entrega valida su traza y evidencia contra
  la fuente: archivo inexistente, línea fuera de rango o ruta que escapa de
  la raíz (incluso por enlace simbólico) rechazan la entrega sin mutar nada.
- Una revisión declarada que no es resoluble localmente es un **bloqueo
  explícito**, nunca un fallback al árbol actual.
- En modo `worktree`, `audit report` compara los sellos con la fuente actual:
  si un archivo citado por un registro final cambió o desapareció, la corrida
  queda `incomplete` con razón `source_diverged`, el informe declara el cambio
  y **exige revalidación**. El motor no fabrica automáticamente un
  `needs_validation`: ese veredicto exige hipótesis y bloqueo propios.
- En modo `revision` no se exige vigencia actual: el informe presenta el
  hallazgo como perteneciente al snapshot declarado.
- El conteo de líneas define que un archivo vacío tiene 0 líneas y que la
  última línea sin salto final cuenta como línea.

## Concurrencia

Toda mutación de la corrida ocurre bajo un bloqueo exclusivo por corrida
(`flock` sobre `<corrida>/.lock`): `init`, `next`, `submit` y `report`
serializan el ciclo completo de carga, validación, mutación y persistencia.
Dos `audit next` concurrentes nunca asignan la misma unidad a dueños
distintos; dos `audit submit` concurrentes nunca pierden una entrega
(última escritura gana está eliminado). `audit status` es lector: toma el
bloqueo compartido y convive con otros lectores, pero espera si hay un
escritor operando.

- El bloqueo vive en un archivo estable (`.lock`), no en los documentos:
  estos se reescriben de forma atómica y el inodo del cerrojo no cambia.
- El bloqueo muere con su proceso: un agente interrumpido no deja cerrojos
  huérfanos.
- Cancelar una espera (Ctrl-C, timeout del llamador) libera el bloqueo y no
  modifica la corrida; la espera máxima es de 30 segundos y su agotamiento
  devuelve código 3.
- `init` crea el bloqueo antes de escribir: otro proceso que llegue detrás
  espera y observa la corrida íntegra, no un ledger sin estado de
  verificación.

## Cobertura honesta

El ledger nunca declara completa una corrida con unidades `planned` o
`in_progress`, ni con candidatos sin veredicto final. En esos casos
`audit report`:

1. escribe solo los registros decididos en `findings.json`;
2. marca `run_status: incomplete` con su razón;
3. devuelve código de salida 3;
4. encabeza `REPORT.md` con la advertencia de corrida parcial.

`deferred`, `blocked` y `out_of_scope` se listan siempre; no cuentan como
cubiertos.

## Corridas anteriores

`audit init --prior DIR` expone como contexto lo que dejó otra corrida:

- unidades cubiertas con la misma revisión y ambos árboles limpios;
- fingerprints rechazados y pendientes de validación.

Es **contexto, no supresión**: todas las unidades de la corrida nueva siguen
planificadas. Una referencia de fuente por sí sola no prueba que el código no
cambió.

## Códigos de salida

| Código | Significado |
| --- | --- |
| 0 | Corrida completa (con o sin hallazgos) |
| 2 | Argumentos o entrega inválidos |
| 3 | Corrida incompleta, presupuesto agotado o agente no elegible |
| 130 | Cancelada |

`audit report` devuelve 0 solo si `run_status: complete`.

## Tareas como prompt

`audit next --format prompt` renderiza la asignación con una plantilla
versionada (`internal/audit/prompt/v1.tmpl`, `TaskPromptTemplateVersion`),
conservando JSON y texto. El prompt incluye contexto de la corrida, reglas por
tipo de tarea, el invariante y los checks de la clase, las rutas de partida y
el contrato de respuesta exigido.

- El contenido del proyecto y del agente es un **dato no confiable**: se
  sanea (`masking.Sanitize`) y se delimita con `<<<CGC_DATOS_NO_CONFIABLES_` +
  nonce. Un título con ANSI, caracteres de control o un delimitador aparente
  no rompe el aislamiento.
- El render ocurre después de la asignación persistida: no cambia la
  asignación ni consume presupuesto adicional; el formato JSON mantiene
  compatibilidad.
- Los golden del render (`testdata/prompt/*.golden`) se crean con
  `go test ./internal/audit -update-prompt`.

## Continuidad entre corridas

`audit init --prior DIR` expone el contexto de una corrida anterior con
**continuidad verificable**:

- La **identidad** de una unidad son sus rutas de partida —archivos o
  directorios reconocidos— con el hash de su fuente, junto con la versión de
  catálogo y el perfil que las produjeron. El store la archiva al sellar el
  informe (`unit_identity` en `state.json`).
- La corrida siguiente compara cada unidad con su identidad: **modificados**
  (contenido distinto), **añadidos** (archivos nuevos en el recorrido de un
  directorio) y **eliminados** (desaparecidos). Una unidad cambia si alguno
  de sus archivos participó.
- Un **confirmado previo** con la fuente cambiada exige revalidación
  (`stale_confirmed`): nunca se copia como confirmado actual; los perfiles que
  exigen prior-rework (`deep`) no cierran hasta que la crítica los revalide.
- Un **rechazado** con la fuente cambiada se reabre (`stale_rejected`): deja
  de orientar la prioridad como rechazado sin cambios. Un rechazado sin
  cambios evita repetir la misma afirmación.
- Un cambio de catálogo o de perfil invalida la reutilización orientativa
  (`same_revision_clean`, `covered_same_source`).
- La cobertura nunca se suprime: una unidad auditada anteriormente sigue en el
  mapa de la corrida nueva. Las listas orientan, no suprimen.

## Integridad del informe

`audit report --verify` verifica el **HMAC-SHA256** del informe sellado sin
reescribir nada. La clave es una **clave local dedicada** con almacenamiento
privado (`<config>/audit-report.key`, 0600); se crea al sellar el informe y
nunca aparece en informes, logs ni paquetes.

- El contenido autenticado es el **ledger y los hallazgos sellados** en una
  serialización canónica idempotente (`audit-integrity-1.0.0`), sin el propio
  valor de autenticación. Modificar el ledger o los registros invalida la
  verificación; cualquier commit posterior al sellado también.
- Cada fallo produce un diagnóstico explícito: informe antiguo sin integridad
  (vuelve a sellarse), clave ausente, clave reemplazada o contenido cambiado.
  Verificar no crea claves nuevas ni reescribe artefactos.
- **Qué prueba el HMAC:** que el contenido sellado no cambió. No prueba la
  verdad del hallazgo ni protege frente a quien posea la clave.

## Importación de leads desde el escaneo

`audit import [ruta] --file <reporte.json>` importa los hallazgos de un
escaneo (`scan`/`agent`, contrato `1.1.0`) como **leads pendientes de caza**:

- Cada hallazgo no suprimido se convierte en una unidad planificada dedicada
  (`import/<unidad-del-motor>/<fingerprint>`, dominio `import`).
- El veredicto `needs_validation` se emite **únicamente cuando su contrato se
  satisface**: bloqueos reales del motor (`verification.missing`) y un plan de
  validación (`verification.rescan`). Sin contrato satisfacible, el hallazgo
  queda como lead sin veredicto.
- **Ningún hallazgo importado aparece automáticamente como confirmado**; la
  severidad y prioridad del motor nunca se convierten en severidad auditada
  (un `needs_validation` no lleva severidad).
- Los datos originales del hallazgo se archivan separados del veredicto
  (`imported_leads` en `state.json`, con el procedimiento y motor de origen).
- Importar dos veces produce el mismo trabajo pendiente: unidades y veredictos
  se deduplican por fingerprint. Entradas incompatibles se rechazan sin dejar
  estado parcial.

## Política de salida para CI

`audit report --fail-on <umbral>` centraliza el código de salida para CI.
**Decisión de producto documentada:**

- Umbrales válidos: `confirmed` (cualquier hallazgo confirmado),
  `needs_validation` (registros pendientes de validación) o una severidad
  auditada de la escala propia del contrato (`informational|low|medium|high|
  critical`): cuenta confirmados con overall ≥ umbral.
- **Precedencia:** cancelación (130) → error operativo o argumentos (2) →
  **corrida incompleta (3)** → umbral incumplido (1) → éxito (0). La corrida
  incompleta siempre precede al umbral: una corrida parcial nunca se declara
  limpia por umbral.
- **Difiere de `scan --fail-on`**: el escaneo cuenta hallazgos del motor por
  su severidad normalizada (`info`); la auditoría cuenta veredictos auditados
  sellados con la escala del contrato de hallazgos (`informational`).
- **Sin flag:** el comportamiento de compatibilidad se mantiene: corrida
  completa → 0 sin evaluar hallazgos.
- La política de salida se evalúa tras el sellado: no altera hallazgos ni
  estado; la ayuda y esta documentación describen los códigos efectivos.

## Consolidación por causa raíz

Dos variantes comprobadas del mismo defecto se consolidan en un registro. La
identidad de causa raíz es **explícita**: el registro que introduce la
candidatura declara `root_cause_ref` (contrato público de hallazgos, campo
opcional); solo confluyen los registros que el productor agrupó con la misma
clave. La similitud textual nunca es prueba suficiente: defectos distintos con
títulos similares permanecen separados.

- El registro representativo se elige de forma determinista —mayor veredicto
  auditado y, a igualdad, menor fingerprint— y el orden de entrada no cambia
  el resultado.
- Los fingerprints de origen y las relaciones de consolidación se conservan:
  cada variante absorbida queda archivada con `merged_into`, y la limitación
  del informe permite reconstruir por qué se eligió el representante.
- La evidencia complementaria y la independencia de revisión no cambian: las
  variantes se verificaron de forma independiente antes de consolidarse.

## Comparación entre auditorías

`audit compare <anterior> <actual>` clasifica los hallazgos confirmados entre
dos corridas sin modificarlas. Clasificaciones:

| Clasificación | Qué significa |
| --- | --- |
| `persistent` | Confirmado en ambas corridas |
| `new` | Confirmado ahora, sin confirmación anterior |
| `resolved` | Confirmado antes y evaluado como ausente o refutado **con evidencia de evaluación actual** |
| `not_evaluated` | Confirmado antes, sin evidencia de evaluación actual |

- La resolución exige evidencia: el registro refutado en la corrida actual, o
  una corrida actual `complete` sin recurrencia. Corridas parciales,
  bloqueadas o con el registro marcado por cambio de fuente no producen
  falsos `resolved` (`not_evaluated`).
- Usa fingerprints y **relaciones de consolidación**: un registro consolidado
  evalúa a sus variantes absorbidas.
- La salida es estable (orden por fingerprint) y rechaza versiones de
  contrato incompatibles o la comparación de una corrida consigo misma.

## Presupuesto

`--budget N` es el máximo de invocaciones de agente en **todas las fases**, con
coste por fase determinista:

| Fase | Coste |
| --- | --- |
| caza | 1 invocación por asignación nueva |
| verificación | 1 invocación por candidato nuevo y por cada firma extra (escalación, revisión final) |
| crítica de cobertura | 1 invocación por tarea de crítica |
| recuperación (`reset-unit`, reasignación por crítica) | 0: no se cobra de nuevo; la siguiente asignación vigente cobra 1 como asignación nueva |

- **Reserva:** antes de repartir caza, el motor se niega si el presupuesto no
  cubre el propio reparto más la cadena de verificación de un candidato (una
  invocación por pasada del perfil) más la crítica final cuando el perfil la
  exige y aún no corrió limpia. La reserva se computa en enteros.
- **Agotamiento unificado:** en caza, verificación y crítica, agotar el
  presupuesto difiere las unidades planificadas restantes y sella la corrida
  `incomplete` con razón `budget_exhausted` antes de responder. El mensaje de
  la CLI informa las unidades diferidas reales y coincide con el estado
  persistido.
- Una promoción de veredicto consume una invocación extra no reservada: la
  reserva garantiza el mínimo documentado, no el peor caso.
- Reiniciar una unidad no reinicia el presupuesto ni duplica consumos; repetir
  `audit next` con una asignación vigente no cobra de nuevo.

## Límites declarados

Tamaños y anidamiento de las entradas públicas (`internal/audit/limits.go`),
aplicados por los decodificadores y por la lectura del store:

| Entrada | Límite |
| --- | --- |
| entrega (`audit submit --file`) | 8 MiB |
| `ledger.json` | 16 MiB |
| `candidates.json` | 16 MiB |
| `findings.json` | 32 MiB |
| `state.json` | 64 MiB (suma de los anteriores) |
| anidamiento JSON | 64 niveles |

Un documento que supera el límite se rechaza antes de decodificarse; la
lectura de archivos es acotada (no se carga el documento completo para
comprobar su tamaño después). Un objeto o arreglo más profundo que el límite
se rechaza con error explícito. Los cuatro decodificadores públicos tienen
fuzz targets (`DecodeLedger`, `DecodeFindings`, `DecodeSubmission`,
`DecodeCandidates`) que CI corre 20 segundos cada uno; las semillas válidas,
truncadas, sobredimensionadas y anidadas forman parte del corpus.

Además:

- En esta versión el perfil es **declarativo**: queda registrado en el ledger y
  en el informe, pero no altera el reparto ni el listón de evidencia.
- Una corrida por defecto usa semántica `quick`: la verificación de candidato y
  la revisión final del registro ocurren en el mismo verificador. La promoción
  de veredicto sigue exigiendo un segundo verificador.
- El reconocimiento de señales tiene un tope de archivos por unidad; si se
  alcanza, el ledger lo declara en `limitations` y `REPORT.md` lo lista. Nunca
  se omite en silencio.
- El catálogo de clases (`internal/audit/catalog.json`) es un conjunto acotado y
  versionado. Una superficie que no esté en el catálogo se puede declarar en
  `uncovered` y se convierte en unidad planificada.
- El motor no ejecuta el objetivo. Un hallazgo que exige ejecución queda en
  `needs_validation` con su plan local acotado.
- Una asignación abandonada no se reasigna automáticamente: `audit reset-unit`
  la recupera y la crítica de cobertura puede reasignarla archivando el
  intento vigente.
- El catálogo de clases y parte de la estructura del protocolo derivan de
  [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill)
  (MIT); ver [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
