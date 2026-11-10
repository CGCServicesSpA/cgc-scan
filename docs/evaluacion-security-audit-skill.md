# Evaluación: `cloudflare/security-audit-skill` dentro del motor de CGC Scan

> **Fecha:** 9 de noviembre de 2026 · **Estado:** evaluación, sin cambios de código
> **Fuente evaluada:** `cloudflare/security-audit-skill` (MIT), rama `main`
> **Pregunta:** ¿qué parte de esa skill se puede implementar en el *engine* de
> `cgc-scan`, no como skill?

---

## 1. Veredicto

**No es factible implementarla completa, y intentarlo rompería el producto.**
Sí es factible —y es lo más valioso— implementar su **sustrato determinista**:
ledger de cobertura, contrato de hallazgos con tres veredictos, validador,
máquina de estados de verificación adversarial, contabilidad de presupuesto y
derivación de reportes.

| Parte de la skill | Naturaleza | ¿Cabe en v1? |
| --- | --- | --- |
| Ledger de cobertura + validador | Determinista | **Sí**, encaja casi 1:1 |
| `report-schema.json` + `validate-findings.cjs` | Determinista | **Sí**, portarlo a Go |
| Reglas de aceptación (gate, severidad, `needs_validation`) | Determinista | **Sí**, como validación de contrato |
| Independencia cazador/verificador, reemplazo material, presupuesto | Determinista (máquina de estados) | **Sí**, si el motor es el *broker* de asignaciones |
| Clases de ataque y *companions* | Datos | **Sí**, como catálogo embebido y validado |
| Reportes `REPORT.md` / `FINDINGS-DETAIL.md` / `NEEDS-VALIDATION.md` | Derivación | **Sí** |
| Reconocimiento semántico (`architecture.md`) | Juicio de modelo | No en v1; solo heurísticas parciales |
| Caza dirigida por cobertura | Juicio de modelo (subagentes) | **No**: es el agente llamador |
| Validación adversarial de candidatos | Juicio de modelo | **No**: el motor no puede ser el adversario |
| Sandbox con ejecución de código del proyecto | Capacidad de host | **No**: prohibido por PRD |
| Orquestación de agentes / proveedor de LLM | Runtime de IA | **No**: prohibido por PRD (CA-04, CA-05) |

**Cuantificación aproximada:** ~60 % del contenido de la skill es protocolo
verificable sin modelo y se puede volver contrato del engine; ~40 % son
capacidades de host (modelo + sandbox) que en v1 deben quedar fuera del binario.

La observación clave: **el valor de esa skill no está en los prompts, está en la
disciplina**. Y la disciplina (cobertura declarada, veredictos distintos,
independencia, no inventar severidad) es exactamente lo que un motor determinista
puede *imponer* mejor que un prompt.

---

## 2. El desajuste de fondo

| | `security-audit-skill` | `cgc-scan` v1 |
| --- | --- | --- |
| Unidad de trabajo | Agente LLM con subagentes | Proceso externo fijo (adaptador) |
| Produce | Prosa + JSON redactado por el modelo | JSON normalizado por parser |
| Verdad de un hallazgo | Reproducción local por un verificador | Regla del motor + evidencia de la fuente |
| Ejecuta código del proyecto | Sí, en sandbox obligatorio | **Nunca** (PRD §6.6, RF-11) |
| Red | Bloqueada en el sandbox | Bloqueada en escaneo; solo preparación |
| Determinismo | No (misma entrada → distinta salida) | Requisito (CA-45, CA-56) |
| IA | Es el producto | Fuera de v1 (§2.2, CA-04, CA-05) |

Restricciones del PRD que condicionan todo lo demás:

- **§2.2** — «Sin IA en v1. La interpretación corresponde al agente llamador.»
- **RF-11** — entregar evidencia «sin inferencia ni recomendaciones generadas con IA».
- **CA-04 / CA-05** — la CLI se instala y ejecuta sin modelo ni credenciales; un
  parámetro de IA devuelve error de argumentos.
- **§6.6** — la CLI no ejecuta tests, build ni hooks del proyecto; si faltan
  dependencias, la ejecución es incompleta, no se improvisa un entorno.
- **§10.1** — el prompt de remediación usa plantilla, no modelo; por eso entra en v1.

Conclusión: en v1 el motor **no puede cazar ni verificar por sí mismo**. Puede
**definir, repartir, validar y contabilizar** el trabajo que hace un agente
externo. Eso es precisamente el rol «parent» de la skill, no el rol «hunter».

---

## 3. Inventario de portabilidad, pieza por pieza

### 3.1 Portables tal cual (contrato puro)

| Pieza de la skill | Destino propuesto | Nota |
| --- | --- | --- |
| `coverage-ledger.json` + `validate-coverage-ledger.cjs` | `internal/audit` + `schemas/audit-ledger.schema.json` | Extiende `internal/plan` (§9.4) y `report.coverage`; no lo reemplaza |
| `report-schema.json` (3 veredictos) | `schemas/findings.schema.json` | Contrato *adicional*, no una mutación de `report-1.1.0` |
| `validate-findings.cjs` | `internal/audit/validate.go` | Ya está `santhosh-tekuri/jsonschema/v6` como dependencia directa |
| Gate de candidato (traza + resultado) | Reglas del validador | Verificable sin modelo |
| `needs_validation` sin severidad | Regla del validador | `additionalProperties: false` ya lo impone en el esquema original |
| Presupuesto de invocaciones | Contador del broker | El motor entrega asignaciones de a una: puede contarlas |
| Independencia cazador ≠ verificador | `agent_id` + rol en el ledger | Se rechaza un verificador con el mismo `agent_id` del dueño de la unidad |
| Reemplazo material → segundo verificador | Máquina de estados | Se exige un `agent_id` distinto y sin rol previo en ese fingerprint |
| Aditividad entre corridas | `internal/projectstate` (§19.1) | Ya existe `latest.json`, `baseline.json`, `index.json`: el mismo patrón |
| Reportes de Fase 6 | `internal/report` | Renderizador Markdown determinista desde registros verificados |

### 3.2 Portables con adaptación

| Pieza | Qué cambia al entrar al engine |
| --- | --- |
| Clases de ataque (`ATTACK-CLASSES.md` y 10 *companions*) | De prompt en Markdown a **catálogo de datos** (`id`, dominio, señal de activación, invariante, checklist). El agente sigue redactando el juicio; el motor solo valida que la clase exista y se aplique a una unidad real |
| `run-metadata.json` | Se fusiona con `report.run` y el estado por proyecto; no hace falta un archivo paralelo |
| Prompts de cazador/verificador | El motor **no** los ejecuta: los **compone** (contexto + bloques verbatim + contrato de resultado) y los entrega por stdout. Reutiliza el saneado y los delimitadores con nonce de `report/prompt.go` |
| Write isolation / promoción de artefactos | Se hereda el patrón de `os.Root` y escritura atómica que ya usa la CLI; los descriptores `no-follow` son POSIX y no aportan en v1 porque no hay ejecución de código del proyecto |
| Perfiles `quick`/`standard`/`deep` | Viables como política de reparto (cuántas unidades, cuántas olas, cuántos verificadores); no como promesa de profundidad |

### 3.3 No portables en v1

| Pieza | Motivo | Qué haría falta |
| --- | --- | --- |
| Caza dirigida por cobertura | Requiere modelo con subagentes | Runtime de IA + red + credenciales (contradice CA-04/CA-05) |
| Validación adversarial real | El motor no puede razonar sobre source | Igual que arriba |
| Sandbox de ejecución del objetivo | El PRD prohíbe ejecutar código del proyecto | Cambio de PRD + sandbox por plataforma + revisión de seguridad |
| `architecture.md` sintetizado | Requiere inferencia sobre el código | Heurísticas de señales (rutas, middleware, acceso a datos), parciales |
| Navegadores, emuladores, fuzzers, IPC local | Fuera del alcance del producto | Otro producto |

---

## 4. Diseño propuesto: el motor como *harness* del agente

En lugar de «implementar la skill», el engine implementa el **protocolo** que la
skill describe, y el agente llamador sigue siendo el que caza y verifica. Esto
respeta la arquitectura declarada en el PRD («una futura capa de IA consumirá el
mismo contrato de reportes sin acoplarse a los motores»).

### 4.1 Flujo

```text
cgc-scan audit init .            → recon determinista + ledger de cobertura
cgc-scan audit next              → compone la siguiente asignación (JSON)
                                   agente externo caza y devuelve un resultado
cgc-scan audit submit            → valida, deduplica y actualiza el ledger
cgc-scan audit next ...          → crítica de cobertura / verificación
cgc-scan audit report --out DIR  → findings.json + REPORT.md + FINDINGS-DETAIL.md
                                   + NEEDS-VALIDATION.md
```

Sin red, sin modelo, sin ejecución del proyecto. Todo son archivos y códigos de
salida, como el resto de la CLI.

### 4.2 Contratos nuevos (aditivos)

| Contrato | Versión | Contenido |
| --- | --- | --- |
| `audit-ledger-1.0.0` | nueva | `coverage_id`, superficie, frontera, subsistema, clase, rutas, dueño, ola, estado (`planned/in_progress/covered/candidate/blocked/deferred/out_of_scope`), `attempts[]`, `local_checks[]` |
| `findings-1.0.0` | nueva | `confirmed` \| `needs_validation` \| `rejected`, con `fingerprint`, `trace`, `evidence`, `conditions`, `execution`, `remediation`, `severity{likelihood,impact,overall}`, `confidence` |
| `agent-1.0.0` | existente | Sin cambios: el one-shot de remediación sigue igual |

`report-1.1.0` no se toca. Los hallazgos del motor y los hallazgos de auditoría
son universos distintos: uno es «el motor X dijo esto», el otro es «un agente
demostró esta falla de frontera». Mezclarlos obligaría a inventar severidad para
lo que no la tiene, que es el peor anti-patrón de ambos mundos.

### 4.3 Mapeo con lo que ya existe

| Ya existe | Se reutiliza para |
| --- | --- |
| `internal/discovery` (unidades, `os.Root`) | Universo de subsistemas y rutas base del ledger |
| `internal/plan` (§9.4, exclusiones con origen) | Cobertura determinista y parcialidad declarada |
| `internal/normalize` (fingerprint, severidad, `Confidence`) | Base del `fingerprint` de auditoría; `Confidence` ya se modela como «de la fuente, nunca inventada» |
| `internal/projectstate` (§19.1) | Aditividad entre corridas: `latest`, `baseline`, `index` |
| `internal/policy` (excepciones, `Decide`) | Códigos de salida del flujo de auditoría |
| `internal/report` + `prompt.go` (nonce, saneado) | Composición de asignaciones y reportes Markdown |
| `schemas/*.json` + `jsonschema` | Validación de los dos contratos nuevos |
| `internal/masking` | Higiene de rutas y textos del objetivo en los reportes |

### 4.4 Invariantes que el motor **sí** puede imponer

Estas son las que hoy el prompt solo *pide* y el engine puede *verificar*:

1. Toda unidad del ledger tiene disposición terminal antes de emitir «completa».
2. Un `needs_validation` no tiene severidad ni `execution`.
3. Un `confirmed` tiene traza completa, `conditions` y `observed_result` no vacío.
4. Un `rejected` tiene `reason` y no tiene severidad ni plan de validación.
5. Un verificador no puede ser el dueño de la unidad que verifica.
6. Un reemplazo que sube de veredicto requiere un segundo verificador distinto.
7. Ningún fingerprint se repite con dos veredictos.
8. El presupuesto de invocaciones no se excede en silencio: si no alcanza, el run
   queda `incomplete` con su causa, y ningún candidato no validado entra a
   `findings.json`.
9. Las rutas de traza son relativas al repositorio y existen en el `source_ref`
   declarado.

Lo que el motor **no** puede imponer: que la traza sea cierta, que la severidad
sea justa, que el impacto sea real. Por eso el contrato debe declarar procedencia
(`attested_by: caller`, `engine_verified: false`) y el reporte debe decir que la
verificación es **de estructura y consistencia, no de verdad**. Sin esa
declaración, el motor se arroga una autoridad que no tiene.

---

## 5. Esfuerzo estimado

Supuesto: 1 desarrollador senior, mismo nivel de pruebas que el resto del repo
(unitarias, contrato, golden, `testscript`).

| Fase | Entregable | Semanas |
| --- | --- | --- |
| A | Contratos: ledger + findings + esquemas + validadores Go + ADR/PRD de alcance | 3–4 |
| B | `audit init`: ledger determinista desde `discovery` + `plan`, IDs estables, cobertura parcial | 2–3 |
| C | Broker: `audit next`, `audit submit`, estados, independencia, presupuesto, dedupe por fingerprint y causa raíz | 3–4 |
| D | Reportes de Fase 6 (`REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`) | 1–2 |
| E | Catálogo de clases de ataque como datos + validación de selección | 1–2 |
| F | Aditividad con `projectstate`, `--changed`, revalidación de fuente cambiada | 1–2 |
| G | Documentación (PRD, design, workload, skill recortada), golden files, CI | 1–2 |
| | **Total** | **12–19** |

**MVP recomendado (A + B + C + D + G parcial): 9–12 semanas.** Deja fuera el
catálogo de clases y la aditividad avanzada, que son las dos piezas con más
superficie de mantenimiento.

Para comparar: añadir orquestación de LLM y sandbox de ejecución son ~10–16
semanas **más** un cambio de PRD y una revisión de seguridad propia, y
contradicen CA-04/CA-05. No se recomienda.

---

## 6. Riesgos

| ID | Riesgo | Impacto | Mitigación |
| --- | --- | --- | --- |
| E-01 | Doble contrato (`report-1.1.0` + `findings-1.0.0`) confunde a los consumidores | Medio | Documentar la frontera: «motor encontró» vs «agente demostró»; no mezclar listas |
| E-02 | El motor parece avalar verdad que solo validó estructuralmente | **Alto** | `attested_by`, `engine_verified: false` obligatorios; el reporte lo repite |
| E-03 | Fingerprint inestable entre corridas (línea, ola, agente) | Alto | Misma regla que §9.1: identidad estable, sin línea ni veredicto; el validador rechaza huellas con `:` de ola o severidad |
| E-04 | Cobertura declarada «completa» sin serlo | **Alto** | Regla del ledger: sin disposición terminal no hay estado `complete`; `deferred` y `out_of_scope` nunca cuentan como cubierto |
| E-05 | Inyección de instrucciones en el contexto que se entrega al agente | Medio | Reutilizar nonce + saneado de `report/prompt.go`; el objetivo siempre son datos no confiables |
| E-06 | Deriva de alcance: el engine empieza a ejecutar código o a llamar modelos | **Alto** | ADR explícita; CA-04/CA-05 como prueba de contrato (`--ai` → código 2) |
| E-07 | Coste de mantenimiento del catálogo de clases | Medio | Empezar con un subconjunto (web/API, dependencias, secretos, configuración) y validarlo contra fixtures reales |
| E-08 | Licencia MIT del material reutilizado | Bajo | Atribución en `THIRD_PARTY_NOTICES.md`; no copiar texto sin conservar el aviso |

---

## 7. Qué NO adoptaría

1. **Los prompts como producto.** Copiar los `.md` dentro del motor los vuelve
   deuda: cambian con el modelo, no con el código. Solo los datos estructurados
   (clases, invariantes, campos) merecen ser contrato.
2. **El sandbox de ejecución.** Su propio README exige que «sin esos controles,
   el lead queda en `needs_validation` en lugar de ejecutar código». El PRD ya
   elige esa rama por diseño: no ejecuta. Adoptar el sandbox es cambiar de
   producto.
3. **La promesa de cobertura completa.** La skill es honesta («no una pasada no
   es completa»). Un CLI que corre en CI necesita además un criterio de salida
   binario; usar el mismo: incompleto → código 3 y nada de «limpio».
4. **La mezcla de veredictos con el reporte canónico.** Mantener `findings.json`
   separado evita que un `needs_validation` herede la severidad de Trivy.

---

## 8. Recomendación

**Adoptar el sustrato (≈60 %), rechazar la orquestación (≈40 %).**

Concretamente, en este orden:

1. **ADR + contrato primero.** `audit-ledger-1.0.0` y `findings-1.0.0` escritos a
   mano, con validadores Go y pruebas de contrato. Sin esto, el resto deriva.
2. **`audit init`** sobre `discovery` y `plan`: es la pieza que más reutiliza el
   engine y la que hace verificable la afirmación de cobertura.
3. **Broker de asignaciones** con independencia, presupuesto y estados. Es donde
   el motor aporta algo que ningún prompt puede: *no se puede mentir sobre el
   orden ni sobre quién verificó qué*.
4. **Reportes** derivados solo de registros con disposición terminal.
5. **Catálogo de clases** al final, y solo si hay evidencia de uso real.

Criterio de éxito del MVP: sobre un fixture con una falla de frontera conocida y
otra refutada, dos corridas con agentes distintos producen el mismo `findings.json`
(salvo `run`), el ledger cierra todas las unidades o declara las pendientes, y el
validador rechaza los cinco casos de contrato rotos (severidad en
`needs_validation`, verificador repetido, traza sin `sink`, fingerprint duplicado,
reemplazo material sin segundo verificador).

---

## 9. Referencias

- `cloudflare/security-audit-skill`: `SKILL.md`, `HUNTING.md`,
  `VALIDATION-AND-REPORTING.md`, `report-schema.json`,
  `validate-findings.cjs`, `validate-coverage-ledger.cjs` (MIT).
- `design.md` §9.4 (cobertura y parcialidad), §9.5 (recetas y frontera de
  confianza), §10.3 (nonce y saneado), §19.1 (estado por proyecto).
- `requisitos-cli-seguridad.md` §2.2, RF-11, CA-04, CA-05, §6.6, §10.1.

---

## 10. Estado de implementación (9 de noviembre de 2026)

Implementado en `internal/audit` y `cgc-scan audit`:

| Etapa | Estado | Dónde |
| --- | --- | --- |
| A — contratos y validadores | Hecho | `schemas/audit-ledger.schema.json`, `schemas/findings.schema.json`, `internal/audit/{schema,validate}.go` |
| B — ledger determinista | Hecho | `internal/audit/{build,catalog}.go`, `catalog.json` |
| C — broker, independencia y presupuesto | Hecho | `internal/audit/broker.go` |
| D — reportes derivados | Hecho | `internal/audit/report.go` |
| E — catálogo de clases | Hecho (conjunto acotado) | `internal/audit/catalog.json` |
| F — contexto entre corridas | Hecho en su forma segura | `audit init --prior`, `PriorFrom` |
| G — documentación | Hecho | `docs/auditoria.md`, `design.md` §20, skill 1.3 |

Desviaciones deliberadas respecto de la skill original:

- **Una sola pasada de verificación** (semántica `quick`): el mismo verificador
  valida el candidato y el registro final. Solo la promoción de veredicto exige
  un segundo verificador. Dos pasadas separadas quedan como perfil `deep`.
- **Sin aritmética de reserva de críticos**: el presupuesto cuenta invocaciones y
  agota el trabajo de forma explícita; la reserva fino-granular de la skill
  requiere un planificador de olas que este MVP no incluye.
- **Sin promoción de artefactos `no-follow`**: no hay ejecución de código del
  proyecto, así que no hay artefactos controlados por el objetivo que promover.
- **Aditividad como contexto, no como supresión**: `same_revision_clean` es
  informativo y todas las unidades siguen planificadas.

No implementado, por diseño: orquestación de LLM con subagentes y sandbox de
ejecución del objetivo (contradicen CA-04/CA-05 y §6.6).
