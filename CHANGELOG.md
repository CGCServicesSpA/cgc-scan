# Changelog

## Sin publicar

- `audit next --format prompt` renderiza la asignación como prompt con una
  plantilla versionada: contexto de la corrida, reglas por tipo de tarea
  (caza, verificación, revisión de escalación, revisión final, crítica), el
  invariante y los checks de la clase, las rutas de partida y el contrato de
  respuesta exigido. El contenido del proyecto y del agente se sanea y se
  delimita con un nonce; ANSI, caracteres de control y delimitadores
  aparentes no rompen el aislamiento. JSON y texto siguen disponibles.
- `--budget` de `audit` reserva presupuesto para las fases obligatorias antes
  de repartir caza: el motor se niega a lanzar cazadores si el presupuesto no
  cubre el reparto más la cadena de verificación de un candidato y la crítica
  final exigida por el perfil. El agotamiento queda unificado en caza,
  verificación y crítica: difiere las unidades planificadas y sella la corrida
  `incomplete` con razón `budget_exhausted` antes de responder, y el mensaje
  de la CLI informa las unidades diferidas reales (corregido el mensaje que
  anunciaba un sellado inexistente). La recuperación de unidades no se cobra
  de nuevo y el sellado de la crítica cuesta una invocación.
- Nueva fase de **crítica independiente de cobertura** para `standard` y
  `deep`: cuando la ola de caza completa, el motor emite la tarea `critique` a
  un agente sin unidades en curso. El crítico responde con `missing_units`
  (superficies que se convierten en unidades planificadas), `reassign_ids`
  (reasignaciones que archivan el intento vigente), `resolved_prior_leads`
  (registrados para revalidación) y `stop` (archivado; no evita requisitos
  pendientes). Los perfiles que la exigen no se declaran completos sin crítica
  final limpia (`critique_pending`) y el informe distingue crítica limpia,
  pendiente y no requerida.
- `standard` y `deep` verifican en dos pasadas: validar el candidato y revisar
  el registro final son fases distintas. El registro decidido pasa a
  `review_pending` y un revisor independiente (que no es cazador, validador
  previo ni autor de reemplazos) lo aprueba con `final_review` o lo
  reemplaza. Un reemplazo **material** (cambia veredicto, causa raíz, traza,
  ejecución, impacto o severidad) no llega al informe sin revisión
  independiente: queda en `escalation` y el registro confirmado vuelve a
  revisión final; un cambio editorial se aplica sin otra firma. `quick`
  conserva una pasada y su escalación por rango de veredicto. `audit status`
  informa los candidatos en revisión final.
- `--profile` de `audit` tiene semántica real: `quick` agrupa unidades por
  subsistema × dominio (una pasada de verificación, sin crítica), `standard`
  por subsistema × frontera × clase (dos pasadas, crítica por ola y final) y
  `deep` por subsistema × ciclo de vida (dos pasadas, crítica y revalidación
  de corridas anteriores). La política vive en el catálogo versionado
  (`audit-catalog-1.1.0`, con metadatos por perfil, ciclo de vida por clase y
  la referencia externa fijada) y una corrida no se declara completa mientras
  le falte una fase obligatoria de su perfil (`phase_not_implemented`).
- `audit` acota sus entradas públicas: la entrega 8 MiB, el ledger y el estado
  de verificación 16 MiB, los hallazgos 32 MiB y 64 niveles de anidamiento
  JSON, con límites aplicados por los decodificadores y lectura de archivos
  acotada. Los cuatro decodificadores (`DecodeLedger`, `DecodeFindings`,
  `DecodeSubmission`, `DecodeCandidates`) tienen fuzz targets con semillas
  válidas, truncadas, sobredimensionadas y anidadas; CI los corre 20 segundos
  cada uno. El fuzzing ya destapó y corrigió entregas y estados con
  veredictos desconocidos que no podían serializarse.
- `audit` valida las citas (`trace` y `evidence`) contra la fuente declarada
  por la corrida y la representa explícitamente: modo `revision` (snapshot de
  Git con árbol limpio; las citas se resuelven contra los blobs y siguen
  válidas aunque el árbol cambie) o modo `worktree` (árbol actual; los
  registros presentables sellan el hash de su fuente al crearse). Una traza
  fabricada se rechaza en `submit`; una revisión no disponible es un bloqueo
  explícito; un archivo citado que cambió impide presentar el hallazgo como
  vigente: la corrida queda incompleta con razón `source_diverged` y el
  informe exige revalidación, sin fabricar veredictos automáticos.
- `audit` persiste la corrida de forma transaccional en un único archivo
  autoritativo (`state.json`, `audit-state-1.0.0`): ledger, estado de
  verificación y —en el sellado— hallazgos comparten una frontera de commit
  atómica, así que una interrupción deja íntegro el estado anterior o el
  nuevo y ya no existe la combinación «unidad `candidate` sin candidato».
  `ledger.json`, `candidates.json` y `findings.json` quedan como vistas
  derivadas regeneradas tras cada commit, y una corrida antigua de dos
  archivos se carga como legado y migra en la primera escritura.
- `audit` serializa la corrida con un bloqueo exclusivo por directorio
  (`flock` sobre `<corrida>/.lock`): `init`, `next`, `submit` y `report`
  ejecutan su ciclo completo de carga-mutación-persistencia bajo el bloqueo y
  `status` lee con bloqueo compartido. Dos procesos concurrentes ya no pueden
  asignar la misma unidad a dueños distintos ni perder entregas; cancelar una
  espera no modifica la corrida y el bloqueo muere con el proceso.
- Nuevo `audit reset-unit --coverage-id ID --reason "..."`: recupera una
  unidad abandonada devolviéndola a `planned`, cierra el intento vigente como
  `blocked` con su razón y archiva dueño, ola y checks disponibles. La ola
  aumenta en la siguiente asignación; las entregas tardías del intento
  abandonado se rechazan y un reinicio repetido no agrega historial falso.
- `audit` valida semánticamente `candidates.json` al cargarlo y antes de
  persistirlo (`ValidateCandidates`): independencia entre cazador y
  verificadores, ramas `escalated`/`final` permitidas por estado, coherencia de
  `run_id` con el ledger y referencias en ambas direcciones. La decodificación
  exige EOF después del objeto JSON, y una corrida con ledger pero sin estado
  de verificación se declara dañada en lugar de reinterpretarse como vacía.
- Nuevo protocolo `cgc-scan audit` (aditivo): ledger de cobertura
  (`audit-ledger-1.0.0`), asignaciones, verificación independiente, presupuesto y
  reportes derivados. El motor no llama a un modelo ni ejecuta código del
  proyecto; la evidencia la aporta el agente y el documento declara
  `attested_by: caller` y `engine_verified: false`.
- Contrato `findings-1.0.0` con tres veredictos (`confirmed`,
  `needs_validation`, `rejected`), validadores de esquema y semántica, y reglas
  de independencia: un cazador no verifica su candidato y una promoción de
  veredicto exige un segundo verificador.
- Catálogo de clases versionado (`internal/audit/catalog.json`) usado para
  construir el ledger desde el descubrimiento; una corrida incompleta devuelve
  código 3 y encabeza el informe con la advertencia de parcialidad.
- `audit init --prior DIR` expone el contexto de una corrida anterior sin
  suprimir unidades. El reconocimiento acotado declara sus truncamientos en
  `limitations`, y la skill global sube a 1.3 con el protocolo.

- Los adaptadores pueden ejecutarse sin toolchains en el equipo: con Docker
  disponible, la CLI detecta la versión del lenguaje que declara el proyecto
  (`go.mod`, `.nvmrc`/`engines.node`, `composer.json`, `Cargo.toml`,
  `pyproject.toml`), construye una imagen derivada de la imagen oficial
  (`golang`, `node`, `php`, `rust`, `python`), instala la herramienta fijada en
  el manifiesto y la ejecuta con el proyecto montado en solo lectura.
- La imagen base se fija por el digest resuelto al construir; el reporte
  registra la imagen, la base y la limitación de no estar en el manifiesto.
  Los motores en contenedor declaran `isolation: configured` porque la red se
  habilita para resolver dependencias.
- Las bases locales y la configuración de Psalm se montan desde un directorio
  temporal compartido con el daemon, y cada lenguaje usa un volumen de caché
  propio del usuario.
- Sin Docker, o si una imagen no se puede preparar, se mantiene el toolchain
  del host y la unidad sin toolchain queda con `requirement_missing`.
  `--offline` y `--no-auto-install` reutilizan solo imágenes ya construidas.
- El runner Docker acepta imagen, montajes y variables de entorno por
  invocación, y la caché incremental considera la imagen y los montajes.
- La skill global sube a 1.2 con el modelo de toolchains. La documentación
  (privacidad, legal, seguridad, FAQ, agentes, cobertura, benchmarks y matriz de
  aceptación) declara la red de resolución de dependencias, el digest de la base
  fuera del manifiesto y el fallback al host.
- `install.sh` actualiza la skill global después de verificar el binario
  (`--no-skill` para omitirla, `--skill-target` para elegir destino). El paquete
  de `--package` incluye `scripts/install-skill.sh` y `skills/cgc-scan/`, y la
  verificación del esquema deja de estar fijada a `1.0.0`.

## 0.2.0-rc.1 — 2026-10-30

- `cgc-scan agent`: one-shot con escaneo, grupos de remediación, prioridad
  explicable, próximas acciones, delta contra la línea base y `report_path`.
- Estado local por proyecto en la caché (`latest`, `baseline`, `index`, `units`),
  con escritura atómica y permisos 0600/0700. Nuevos comandos `status`, `plan`,
  `explain`, `verify`, `baseline set|show|clear` y `compare --baseline`.
- Grupos de remediación por componente: una acción para los cinco hallazgos de
  `golang.org/x/text` con destino `v0.41.0`, cálculo de `breaking_risk` por
  ecosistema, comandos de aplicación como sugerencias y detección de
  dependencias transitivas con override.
- Prioridad 0–100 con factores visibles (`kev`, EPSS, alcanzabilidad, corrección,
  dependencia directa, contexto de test/fixtures/examples).
- `next_actions` deterministas; incluye recetas faltantes, grupos, secretos que
  exigen al usuario y herramientas o bases ausentes.
- `verify` reescanea solo la unidad y los motores afectados, fusiona el resultado
  y reporta `resolved|persistent|partial` por huella.
- Alcance reducido: `--only`, `--engines`, `--changed` y `--no-cache`.
- Caché incremental por unidad y motor con invalidación por tipo (deps/source/
  full), origen `hit|miss|mixed|disabled` en el reporte y `--no-cache`.
- `db.refresh_after` (12 h) reutiliza Trivy y el espejo de Go sin red; el espejo
  de Go descarga solo avisos con `modified` nuevo.
- Semgrep usa un contenedor por escaneo en vez de uno por unidad.
- govulncheck resuelve el toolchain desde el `GOROOT` de la CLI y funciona sin
  red con un toolchain cacheado; un toolchain ausente falla explícitamente.
- El workflow de aislamiento genera el token de prueba en tiempo de ejecución:
  el repositorio ya no contiene un literal con forma de credencial.
- `cgc-scan.toml` excluye `testdata/**` de los escaneos de producción; los
  fixtures vulnerables son entradas de pruebas y la exclusión se declara como
  cobertura parcial.
- Esquema `report-1.1.0` aditivo y contrato separado `agent-1.0.0`; skill 1.1,
  PRD, design y workload actualizados.

## 0.1.0-rc.4 — 2026-10-28

- `scan --confirm-recipes`: confirma en una sola orden los candidatos de
  test/build detectados para las unidades del escaneo. Solo añade recetas
  faltantes, no sobrescribe comandos del usuario y las guarda en la
  configuración de usuario para los escaneos siguientes.
- Corregido el caso en que la unidad de proyecto y un módulo comparten ruta
  (`backoffice`): la receta del módulo se aplica al hallazgo.
- `--set` actualiza solo las unidades declaradas y conserva las demás recetas
  del proyecto.
- Skill global `cgc-scan` para agentes y `scripts/install-skill.sh` con
  `~/.agents/skills` como fuente canónica y enlaces desde DevPass, OpenCode,
  Claude, Codex, Kiro, mcode (MiniMax) y Pi; actualización atómica, respaldo,
  estado, comprobación y desinstalación.

## 0.1.0-rc.3 — 2026-10-28

- Salida enriquecida: por hallazgo se muestran versión corregida, descripción,
  severidad original y de otras fuentes, CVSS, alcanzabilidad, remediación y
  referencias.
- Receta de verificación por hallazgo (`verification`): recetas confirmadas de
  test/build de su unidad, candidatos detectados como no confiables, recetas
  faltantes y comando de reescaneo con la modalidad y el modo offline originales.
- Los secretos no se declaran listos para validar: exigen revocación y rotación.
- Actualización a Go 1.27.3 y dependencias (`x/text`, `x/telemetry`, `pflag`).
- Instalador local `install.sh` con compilación, empaquetado, instalación
  atómica, respaldo, instalación desde artefacto y desinstalación.
- El paquete local incluye `INSTALL.txt`, licencia, avisos de terceros y el
  instalador para máquinas sin Go.

## 0.1.0-rc.2 — 2026-10-28

- SBOM CycloneDX 1.6, firma cosign y atestación de procedencia verificadas.
- Fórmula Homebrew con checksums reales.

## 0.1.0-rc.1 — 2026-10-27

- Primer release candidate firmado con checksums y SBOM.
