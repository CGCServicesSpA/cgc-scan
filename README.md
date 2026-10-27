# CGC Scan

CLI local de análisis de seguridad para proyectos de software. Combina **Trivy** (dependencias, secretos y configuraciones) con adaptadores por lenguaje —**govulncheck, ESLint, Psalm, cargo-audit y Bandit**— y, de forma opcional, **Semgrep CE** con reglas locales. Entrega un reporte determinista en JSON, texto legible o un prompt de remediación para agentes.

> **Estado:** desarrollo previo a v1.0.0. La CLI compila y sus comandos de fundación funcionan; los hitos H1 a H7 están en construcción. Este README se actualiza junto con el release.

## Principios

- **Local primero.** El código, los inventarios y los resultados no salen del equipo. No hay telemetría, cuentas ni servicios propios.
- **Sin IA en v1.** La interpretación la hace el agente que invoca la CLI; la CLI genera evidencia y políticas deterministas.
- **Nunca un resultado limpio con cobertura incompleta.** Si falta un motor, una base o una herramienta, el reporte lo dice y el código de salida es 3.

## Requisitos

- macOS o Linux en amd64/arm64. Windows se usa mediante WSL2.
- Docker local (opcional, para el runner aislado) o conexión a internet para la preparación inicial.
- Los toolchains de los proyectos que se quieran analizar con adaptadores: Go, Node, PHP/Composer, Rust y Python.

## Compilar

```bash
go build ./cmd/cgc-scan
./cgc-scan --version
```

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

La documentación completa de instalación, flags, cobertura y privacidad se publica en H7. El contrato del reporte vive en [`schemas/report.schema.json`](schemas/report.schema.json).

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
