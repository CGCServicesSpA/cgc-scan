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

## Límites declarados

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
- Una asignación abandonada no se reasigna automáticamente (no hay olas de
  crítica en esta versión). Para recuperar el contexto, inicia una corrida nueva
  con `--prior <dir-de-la-anterior>`; la anterior queda como evidencia de lo
  intentado.
- El catálogo de clases y parte de la estructura del protocolo derivan de
  [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill)
  (MIT); ver [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
