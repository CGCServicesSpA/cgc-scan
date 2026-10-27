# Fixtures

Cada lenguaje tiene un par de proyectos mínimos, **vulnerable** y **corregido**, más un monorepo mixto. Los fixtures se ejecutan con los motores reales en las pruebas de integración; no se usan dobles ni salidas pregrabadas como sustituto de la ejecución.

## Convención

```text
testdata/fixtures/
├── go/
│   ├── vulnerable/      # dependencia vulnerable + caso de código
│   └── fixed/           # la misma unidad con la corrección aplicada
├── javascript/{vulnerable,fixed}/
├── typescript/{vulnerable,fixed}/
├── php/{vulnerable,fixed}/
├── rust/{vulnerable,fixed}/
├── python/{vulnerable,fixed}/
└── monorepo/            # varias unidades y lenguajes en un solo árbol
```

Reglas:

1. **Nada de secretos reales.** Los fixtures de secretos usan valores aleatorios generados en el momento o cadenas evidentemente ficticias que no estén en la allowlist de los motores.
2. **Sin `vendor/`, `node_modules/` ni artefactos de build versionados.** La preparación de cada fixture se documenta en su `README.md` cuando requiere un comando (`composer install`, `npm ci`, `cargo generate-lockfile`).
3. **Cada fixture declara qué demuestra** en un `EXPECTED.md`: hallazgo esperado, motor que lo detecta y línea aproximada. La prueba comprueba el hallazgo, no la línea exacta.
4. **El par `fixed` conserva la estructura** del vulnerable para que la comparación (nuevo/persistente/resuelto) sea significativa.
5. **Sin datos cocinados.** Las pruebas de contrato serializan el reporte real; los golden solo eliminan campos volátiles (`run.id`, fechas, duraciones).
6. Los fixtures que necesiten red para prepararse se marcan `//go:build integration` y no se ejecutan en la matriz por defecto.

## Uso en pruebas

- Integración: etiqueta `integration`, motores reales, versiones del manifiesto.
- Contrato: `internal/testutil/golden` valida el JSON contra `schemas/report.schema.json` y compara tras eliminar los campos volátiles.
- Regresión del prompt: los casos de inyección viven en `testdata/fixtures/prompt/` y no ejecutan motores.
