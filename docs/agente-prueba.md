# Prueba con un agente consumidor

> Ciclo controlado ejecutado el 27-10-2026 sobre una copia del fixture Go
> vulnerable. El consumidor fue un agente de desarrollo que siguió únicamente el
> prompt generado y el JSON canónico. No es una garantía de obediencia de
> cualquier agente externo (PRD §10.1).

## Preparación

```bash
cgc-scan scan "$PROYECTO" --trivy-mode docker --offline --format json \
  --report-out before.json
cgc-scan scan "$PROYECTO" --trivy-mode docker --offline --format prompt \
  --report-out before.json > prompt.txt
```

Recetas confirmadas para la unidad `root` (configuración de usuario):

```toml
[[recipes]]
unit = "root"
[recipes.test]
command = "go test ./..."
workdir = "."
[recipes.build]
command = "go build ./..."
workdir = "."
```

## Estado inicial

- 29 hallazgos (5 de Trivy y el resto de govulncheck, correlacionados).
- Cobertura completa, sin errores.
- El prompt enumera fingerprints, rutas, paquetes, versiones corregidas,
  motores y remediaciones dentro de un bloque con nonce.

## Parche aplicado por el agente

1. Actualizó `golang.org/x/text` de `v0.3.0` a `v0.41.0` en `go.mod` y `go.sum`.
2. Ejecutó los tests de la receta sin modificarlos:
   `go test ./...` → `[no test files]`, sin fallos.
3. Ejecutó el build: `go build ./...` → OK.
4. Reescaneó el mismo ámbito con el mismo comando.

## Resultado

```text
Comparación: before -> after
Nuevos: 0
Persistentes: 0
Resueltos: 29
No evaluados: 0
Cobertura comparable: true
```

- No aparecieron hallazgos nuevos.
- El escaneo posterior fue completo (`coverage.partial=false`, sin errores).
- Los tests y el build quedaron registrados; ningún archivo de test se modificó.
- La comparación solo marcó `resolved` porque la cobertura era comparable.

## Conclusión

El contrato JSON y el prompt bastan para que un agente realice el ciclo
parche → tests → build → reescaneo → comparación sin intervención de la CLI en
la ejecución de tests, build ni parches. La CLI no llamó a ningún modelo ni
ejecutó comandos del proyecto.
