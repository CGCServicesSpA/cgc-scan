# Contribuir a CGC Scan

Gracias por querer contribuir. Este documento describe el flujo y las reglas que la CI verifica.

## Antes de empezar

- Lee [`requisitos-cli-seguridad.md`](requisitos-cli-seguridad.md) (el contrato) y [`design.md`](design.md) (las decisiones técnicas).
- Para cambios de alcance, abre primero un issue con el requisito o criterio de aceptación afectado.
- Toda decisión técnica nueva se registra en el ADR de `design.md` §17; toda decisión de producto, en el PRD.

## Entorno

```bash
go version          # 1.27.3 (la versión fijada en go.mod)
go build ./cmd/cgc-scan
go test -race ./...
```

Herramientas de CI (versiones fijadas en `.github/workflows/ci.yml`): `golangci-lint`, `staticcheck`, `govulncheck` y `goreleaser` para los releases.

## Reglas de código

1. **stdout es contrato.** Solo `internal/report` escribe en stdout. Todo lo demás va por `slog` a stderr. El linter `forbidigo` bloquea `fmt.Print*` y `os.Stdout` fuera de `report`.
2. **Nada de datos inventados.** Un campo que un motor no entrega queda nulo u omitido; nunca se rellena con valores plausibles.
3. **Sin mocks en la lógica.** Las pruebas de integración usan motores y fixtures reales; las unitarias prueban funciones puras. Si algo no se puede probar sin red, se marca `//go:build integration` y se documenta.
4. **Datos no confiables.** Todo lo que viene de un proyecto (TOML, salida de motores, rutas) se valida, se limita en tamaño y pasa por `masking` antes de persistirse.
5. **Contratos versionados.** Un cambio en flags, JSON o códigos de salida actualiza el esquema, el PRD y las pruebas de referencia en el mismo cambio.
6. **Sin dependencias nuevas sin justificación.** Cada dependencia directa se documenta en `design.md` §2.

## Pruebas

| Cambio | Prueba exigida |
| --- | --- |
| Parser de un motor | Tabla de casos + entrada malformada/truncada + fuzz |
| Reporte o esquema | Validación contra `schemas/report.schema.json` + golden sin campos volátiles |
| Política | Tabla de códigos de salida y excepciones vencidas |
| Aislamiento | Prueba con red bloqueada o `strace` por versión fijada |
| CLI | `testscript` con códigos de salida y stdout/stderr separados |

## Commits y PRs

- Commits pequeños y revisables; el mensaje explica el *porqué*.
- El PR describe el requisito, el criterio de aceptación y cómo se verificó.
- La CI debe estar en verde: build, `go test -race` en la matriz, linters y `govulncheck`.
- No se aceptan cambios que relajen una prueba, un umbral o una exclusión sin una decisión registrada.

## Código de conducta

Trata a las demás personas con respeto. La revisión se centra en el código y en la evidencia; las críticas deben ser concretas y accionables.
