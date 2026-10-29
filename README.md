# CGC Scan

CLI local de análisis de seguridad para proyectos de software. Combina **Trivy** (dependencias, secretos y configuraciones) con adaptadores por lenguaje —**govulncheck, ESLint, Psalm, cargo-audit y Bandit**— y, de forma opcional, **Semgrep CE** con reglas locales. Entrega un reporte determinista en JSON, texto legible o un prompt de remediación para agentes.

> **Estado:** release candidate interno. La CLI implementa el contrato de v1
> (escaneo con Trivy y cinco adaptadores, Semgrep opcional, formatos JSON/texto/
> prompt, comparación, política y recetas). Falta cerrar el release firmado
> (H6-08/H6-09) y la matriz completa de aceptación (H7). No se publica v1.0.0
> hasta completarlos.

## Principios

- **Local primero.** El código, los inventarios y los resultados no salen del equipo. No hay telemetría, cuentas ni servicios propios.
- **Sin IA en v1.** La interpretación la hace el agente que invoca la CLI; la CLI genera evidencia y políticas deterministas.
- **Nunca un resultado limpio con cobertura incompleta.** Si falta un motor, una base o una herramienta, el reporte lo dice y el código de salida es 3.

## Requisitos

- macOS o Linux en amd64/arm64. Windows se usa mediante WSL2.
- Docker local (opcional, para el runner aislado) o conexión a internet para la preparación inicial.
- Los toolchains de los proyectos que se quieran analizar con adaptadores: Go, Node, PHP/Composer, Rust y Python.

## Compilar e instalar localmente

```bash
./install.sh                 # compila, empaqueta e instala en ~/.local/bin
./install.sh --package       # además deja el tar.gz y su SHA-256 en dist/
./install.sh --prefix DIR    # instala en otro prefijo
./install.sh --uninstall     # elimina el binario, sin tocar la configuración
```

El instalador verifica la versión y el esquema antes de publicar el binario, y
conserva el anterior como `cgc-scan.bak`. El paquete generado incluye un
`install.sh` que instala sin necesidad de Go ni de red.

## Uso

```bash
cgc-scan setup                 # elección Docker/global y Semgrep opcional
cgc-scan setup --trivy-mode docker --semgrep disable --non-interactive
cgc-scan doctor --format json
cgc-scan scan . --format json
cgc-scan scan . --format text --fail-on high
cgc-scan scan . --format prompt --report-out ./reporte.json
cgc-scan compare anterior.json actual.json --format json
cgc-scan update-db
```

Los códigos de salida son estables: `0` sin incumplimiento, `1` política incumplida, `2` argumentos o configuración inválidos, `3` ejecución incompleta o fallida y `130` cancelación.

Documentación:

- [Instalación](docs/instalacion.md) · [Uso](docs/uso.md) · [Cobertura](docs/cobertura.md)
- [Privacidad](docs/privacidad.md) · [FAQ](docs/faq.md) · [Integración con agentes](docs/integracion-agentes.md)
- [Verificación de releases](docs/verificacion-release.md) · [Soporte](docs/soporte.md) · [Legal](docs/legal.md)
- [Matriz de aceptación](docs/aceptacion.md) · [Revisión de seguridad](docs/revision-seguridad.md) · [Benchmarks](docs/benchmarks.md)

## Skill para agentes

El repositorio incluye una skill global en [`skills/cgc-scan/SKILL.md`](skills/cgc-scan/SKILL.md) y un instalador:

```bash
./scripts/install-skill.sh                 # detecta DevPass/OpenCode y Claude
./scripts/install-skill.sh --target all    # agents + OpenCode + Claude
./scripts/install-skill.sh --target agents # solo la copia canónica
./scripts/install-skill.sh --status
./scripts/install-skill.sh --check
./scripts/install-skill.sh --uninstall
```

La skill enseña al agente el contrato JSON, la cobertura, las recetas de
validación, el flujo parche → tests → build → reescaneo y las reglas de
seguridad. La copia canónica vive en `~/.agents/skills/cgc-scan`; DevPass,
OpenCode, Claude, Codex, Kiro, mcode (MiniMax) y Pi se enlazan a ella, de modo
que actualizar una vez actualiza todos los harness.

El contrato del reporte vive en [`schemas/report.schema.json`](schemas/report.schema.json).

## Desarrollo

```bash
go test -race ./...
go vet ./...
golangci-lint run
```

- Requisitos y criterios de aceptación: [`requisitos-cli-seguridad.md`](requisitos-cli-seguridad.md).
- Decisiones técnicas: [`design.md`](design.md) y [`docs/decisiones-preparacion.md`](docs/decisiones-preparacion.md).
- Plan de trabajo: [`workload.md`](workload.md).

Las contribuciones se describen en [`CONTRIBUTING.md`](CONTRIBUTING.md); los reportes de seguridad siguen [`SECURITY.md`](SECURITY.md).

## Licencia

Apache-2.0. Ver [`LICENSE`](LICENSE).
