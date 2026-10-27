# CGC Scan — Registro de decisiones de preparación (Hito P)

> **Versión:** 1.0 · **Fecha:** 27 de octubre de 2026
> **Alcance:** decisiones P-01 a P-06 del `workload.md`. Los spikes P-07 a P-11 se documentan en `docs/spikes/`.
> **Convención:** cada decisión cita su origen (O-, T-, RF, CA, R) y la evidencia que la respalda. Una decisión solo pasa a *Cerrada* cuando la evidencia es reproducible con los comandos indicados.

---

## D-01 — Aprovisionamiento de herramientas de adaptadores (P-01)

**Origen:** design O-1, §8.1; T-04; PRD §6.3.
**Estado:** Cerrada. Extiende el mecanismo del manifiesto de confianza a todas las herramientas de adaptadores.

**Decisión.** El aprovisionamiento verificado se extiende a ESLint (con sus plugins), Psalm, Bandit, cargo-audit y govulncheck, con estas reglas:

| Herramienta | Forma de distribución | Verificación | Sin scripts |
| --- | --- | --- | --- |
| Trivy | Archivo tar.gz oficial por plataforma | SHA-256 del manifiesto + `--version` | No aplica (binario) |
| govulncheck | Binario Go compilado en CI de la CLI o módulo Go | `go mod verify` (sumdb) + SHA-256 del manifiesto | No aplica (binario) |
| cargo-audit | Archivo `.crate`/binario precompilado del release | SHA-256 del manifiesto + `cargo-audit --version` | `cargo install --locked` no ejecuta build scripts ajenos; se prefiere el binario precompilado |
| Bandit | Wheel de PyPI | SHA-256 del manifiesto (hash por archivo, no solo versión) | `pip install --no-deps --require-hashes` |
| ESLint y plugins | Tarballs npm con `package-lock.json` de integridad | `npm ci --ignore-scripts` contra el lockfile empaquetado | `--ignore-scripts` obligatorio |
| Psalm | Phar oficial | SHA-256 del manifiesto | No aplica (phar) |

Reglas comunes, sin excepciones:

1. Todo artefacto se fija por versión **y** hash en `manifest/trust.json`; nunca se resuelve `latest`.
2. La instalación ocurre en `<data>/cgc-scan/engines/<motor>/<versión>/` con escritura atómica; jamás en el proyecto.
3. No se ejecuta `sh`, `bash`, `postinstall`, `setup.py` ni ningún script del artefacto.
4. Si falta el toolchain del ecosistema (Node, PHP, Python, Cargo, Go), el adaptador se omite con `requirement_missing`, la ejecución es incompleta y el código de salida es 3.
5. Los paquetes de ecosistema se instalan desde un lockfile empaquetado en el binario (integridad), no desde el lockfile del proyecto.
6. `scan` nunca instala herramientas de adaptadores sin `--no-auto-install` explícito; la preparación de adaptadores ocurre en `setup` o en el primer `scan` con auto-instalación permitida, y queda registrada en `state.json`.

**Descartado.** (a) Requerir que el usuario instale cada herramienta a mano: deja la cobertura a la deriva y contradice RF-21. (b) Instalar con los gestores del proyecto (`npm i`, `composer require`, `pip install`): ejecuta scripts y mezcla dependencias del proyecto. (c) Empaquetar los motores dentro del binario de la CLI: multiplica el tamaño y rompe la actualización independiente.

**Consecuencia.** PRD §6.3 se amplía: el aprovisionamiento automático deja de ser exclusivo de Trivy, pero conserva todas sus garantías. El detalle de implementación vive en H4-02.

---

## D-02 — Repositorio y CI (P-02)

**Origen:** design O-5.
**Estado:** Cerrada.

**Decisión.** Repositorio **público** en GitHub (organización `CGCServicesSpA`, repositorio `cgc-scan`) y **GitHub Actions** como CI. Se habilitan:

- Firma sin clave con Sigstore/cosign (`cosign sign-blob` con identidad OIDC de GitHub Actions) y transparencia en Rekor.
- Atestación de procedencia SLSA nivel 3 mediante `slsa-framework/slsa-github-generator` cuando el repositorio es público (requisito del generador).
- SBOM CycloneDX por release.

**Descartado.** Repositorio privado: obligaría a gestionar claves de firma a mano y a renunciar a la atestación SLSA pública; el producto es una CLI de seguridad cuya cadena de suministro debe ser verificable por terceros.

**Verificación disponible.** `gh auth status` autenticado; no existe todavía el remoto (se crea en H0-01). La matriz de CI se define en H0-03.

**Consecuencia.** La CLI no contiene telemetría ni autoactualización: un repositorio público no cambia el modelo de privacidad (PRD §1).

---

## D-03 — Nombre definitivo (P-03)

**Origen:** PRD §15.
**Estado:** Cerrada para paquetes y dominios; verificación de marca registrada pendiente como gate legal (H7-06).

**Decisión.** Se fija el nombre **`cgc-scan`** (binario) / **CGC Scan** (nombre comercial), propiedad de CGC Services SpA.

**Evidencia (27-10-2026):**

| Comprobación | Comando | Resultado |
| --- | --- | --- |
| npm | `npm view cgc-scan version` | 404 (libre) |
| PyPI | `GET https://pypi.org/pypi/cgc-scan/json` | 404 (libre) |
| crates.io | `GET https://crates.io/api/v1/crates/cgc-scan` | `crate does not exist` (libre) |
| RubyGems | `GET https://rubygems.org/api/v1/gems/cgc-scan.json` | 404 (libre) |
| NuGet | `GET https://api.nuget.org/v3-flatcontainer/cgc-scan/index.json` | 404 (libre) |
| GitHub | `GET https://github.com/CGCServicesSpA/cgc-scan` | 404 (libre) |
| Dominio `.cl` | `whois -h whois.nic.cl cgc-scan.cl` | `no entries found` (libre) |
| Dominio `.com` | `whois cgc-scan.com` | `No match` (libre) |
| Dominio `.io` | `whois cgc-scan.io` | `Domain not found` (libre) |
| INAPI | `https://buscadormarcas.inapi.cl` | requiere reCAPTCHA; **no automatizable**. Se hará búsqueda manual de «CGC Scan» y «cgc-scan» en clases 9 y 42 y se registra en H7-06 |

**Riesgo asumido.** La búsqueda de marca en INAPI no puede completarse desde la CLI ni de forma automatizada (reCAPTCHA). El nombre es reversible mientras no se publique v1.0.0, y el resultado se registra como gate de H7-06. No bloquea H0: el repositorio, los paquetes y los dominios están libres.

---

## D-04 — Defaults pendientes (P-04)

**Origen:** PRD §15; design O-4.
**Estado:** Cerrada.

| Tema | Decisión | Justificación |
| --- | --- | --- |
| Umbral `--fail-on` | `high` | Recomendación del PRD; `info` no bloquea y `unknown` cuenta solo si la política lo declara (`policy.unknown_counts = true` por defecto) |
| Antigüedad de bases | Aviso a las **72 h**; bloqueo en offline a los **7 días** (168 h) | Evita datos rancios sin impedir trabajo diario; configurable en `config.toml` |
| Archivos ignorados por Git (`.env`) | Se analizan **solo para secretos**, con enmascarado; quedan fuera del análisis de código | PRD §4.4; captura el caso de mayor riesgo sin analizar semántica de archivos no versionados |
| Prioridad 3 sobre 1 | Se mantiene **3** cuando la ejecución es incompleta, con `policy` y `run` visibles en JSON; sin código adicional | PRD §8.1; el JSON conserva ambos resultados |
| Lotes del prompt | Umbral **120 000 caracteres** por lote, división por unidad de parche con índice y referencia al reporte completo; nunca truncar en silencio | Caben en contextos de 32k tokens con margen; configurable |
| Archivo de política del proyecto | **`cgc-scan.toml`** en la raíz detectada del proyecto | Cierra O-4 |
| Exclusiones de usuario | Solo en `config.toml`; el archivo del proyecto solo agrega | PRD §6.8 |

**Consecuencia.** El valor `unknown` cuenta contra el umbral por defecto y la decisión queda registrada en `policy` de cada reporte.

---

## D-05 — Runner de Semgrep y reglas propias (P-05)

**Origen:** PRD §5.2, §15; R3.
**Estado:** Cerrada.

**Decisión.**

1. **Runner.** Semgrep sigue la modalidad guardada de Trivy: en `docker`, imagen fijada por digest ejecutada con `--network none`; en `global`, binario instalado en `engines/semgrep/<versión>/` e invocado por ruta absoluta con el entorno mínimo. Nunca se usa el `semgrep` del `PATH` del usuario.
2. **Reglas.** El conjunto propio de CGC se mantiene en el repositorio bajo **Apache-2.0** (compatible con la licencia Apache-2.0 del motor Trivy y con las reglas propias), versionado con `rules_version` y hash registrado en el reporte. No se descargan ni redistribuyen reglas del registro público de Semgrep.
3. **Responsable.** El equipo de seguridad de CGC Services SpA mantiene el conjunto; cada cambio exige un fixture que lo demuestre (H6-03).
4. **Habilitación.** Solo `setup` escribe `semgrep_enabled`; `scan` ni el archivo del proyecto pueden habilitarlo (RF-30, CA-49).

**Descartado.** Usar reglas del registro público: su licencia (Semgrep Rules License) prohíbe redistribución y uso comercial sin acuerdo; descargarlas en tiempo de ejecución violaría el aislamiento y R3.

---

## D-06 — Revisión de licencias (P-06)

**Origen:** PRD R3, §12; design §14.
**Estado:** Cerrada para v1; la revisión legal final es H7-06.

**Licencia de la CLI:** **Apache-2.0** (patente explícita, compatible con todo el stack).

**Motores y reglas** (verificado contra el metadato del proyecto el 27-10-2026):

| Componente | Versión fijada | Licencia | Redistribución |
| --- | --- | --- | --- |
| Trivy | 0.76.1 | Apache-2.0 | Se descarga del release oficial; no se empaqueta |
| govulncheck (`golang.org/x/vuln`) | v1.9.0 | BSD-3-Clause | Se descarga; alternativa: biblioteca |
| ESLint | 10.13.0 | MIT | Tarball npm |
| eslint-plugin-security | 4.2.0 | Apache-2.0 | Tarball npm |
| @typescript-eslint/parser | 8.72.1 | MIT | Tarball npm |
| Psalm | 6.20.3 | MIT | Phar oficial |
| cargo-audit | 0.22.2 | MIT OR Apache-2.0 | Binario del release |
| Bandit | 1.9.4 | Apache-2.0 | Wheel de PyPI |
| Semgrep CE | 1.x (fijada en H6) | LGPL-2.1 | Se descarga; no se enlaza |
| Reglas propias CGC | v1 | Apache-2.0 | Empaquetadas |

**Dependencias Go directas:** cobra (Apache-2.0), go-toml/v2 (MIT), flock (BSD-3-Clause), doublestar/v4 (MIT), jsonschema/v6 (Apache-2.0), go-cmp (BSD-3-Clause), go-internal/testscript (BSD-3-Clause), x/sync (BSD-3-Clause). Todas permisivas y compatibles con Apache-2.0.

**Obligaciones.** El release incluye `THIRD_PARTY_NOTICES.md` generado desde el SBOM y la licencia Apache-2.0 del proyecto; los binarios descargados conservan su licencia en el manifiesto. Ninguna licencia copyleft se enlaza estáticamente con la CLI (Semgrep es un proceso externo, LGPL-2.1, sin enlace).

**Conclusión.** No hay bloqueo legal para v1. Persisten dos obligaciones de H7-06: (a) revisión de la Ley 21.719 con el texto final, (b) búsqueda manual de marca en INAPI.
