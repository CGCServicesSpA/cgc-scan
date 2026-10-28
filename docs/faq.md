# Preguntas frecuentes

**¿Por qué el escaneo devuelve 3 si encontró hallazgos?**
El código 3 significa ejecución incompleta (un motor, una base o una herramienta
faltó). Tiene prioridad sobre el 1. El JSON conserva `policy.violated` y la lista
de `errors`; revisa `coverage` y `tools.engines`.

**¿Por qué no analiza `node_modules`, `vendor` o `target`?**
Son exclusiones intrínsecas: contenido instalado o generado que no es analizable
por definición. No marcan el escaneo como parcial. Si necesitas analizar algo
concreto, usa `--include`; no reactivarás una exclusión intrínseca.

**¿Por qué `--exclude` no reduce los hallazgos?**
Las exclusiones se aplican al ámbito de las unidades. Si el patrón no coincide
con ninguna unidad, no hay nada que excluir. Revisa `coverage.exclusions` y
`coverage.not_analyzed`; los patrones son relativos al objetivo del escaneo y
admiten `**`.

**¿Por qué Psalm se omite en un proyecto PHP?**
Falta `vendor/autoload.php`. Ejecuta `composer install` en la unidad. Si no hay
`composer.json`, Psalm puede analizar el árbol igualmente.

**¿Por qué govulncheck no encuentra nada?**
Comprueba que el toolchain Go esté en `PATH`, que el módulo tenga `go.mod` y que
la base local exista (`cgc-scan update-db`). En modo offline no se descargan
módulos: si faltan en la caché de Go, la unidad queda incompleta.

**¿La CLI envía datos a algún servicio?**
No. La preparación descarga motores y bases de fuentes públicas; el escaneo no
tiene red en Docker y usa un proxy cerrado en global. No hay telemetría.

**¿Puedo escanear una subcarpeta de un monorepo?**
Sí. El objetivo es la subcarpeta; la raíz detectada sirve para enumerar lo que
queda fuera del alcance. Las rutas del reporte son relativas a la raíz y el
ámbito analizado es el objetivo.

**¿Por qué el reporte de dos ejecuciones no es idéntico?**
Los campos volátiles están en `run` (ID, fechas, duración) y los derivados del
tiempo en `tools.engines[].duration_ms` y `db.age_seconds`. El resto debe ser
idéntico con las mismas entradas, versiones y bases.

**¿Semgrep está activo?**
Solo si `setup` lo habilitó. Con Semgrep desactivado, `tools` lo registra como
`disabled` y la ejecución no se marca incompleta. `scan` nunca lo habilita,
instala ni descarga.

**¿Qué pasa si el proyecto cambia durante el escaneo?**
El reporte puede mezclar estados. La CLI no bloquea el proyecto; repite el
escaneo antes de dar un parche por resuelto. Los cambios sin commit y los
archivos nuevos sí se analizan.

**¿Cómo reporto una vulnerabilidad de CGC Scan?**
Usa GitHub Security Advisories o `seguridad@cgcservices.cl`; consulta
[`SECURITY.md`](../SECURITY.md). No adjuntes secretos reales.

**¿Hay soporte para Windows nativo?**
No en v1. Usa WSL2 con el binario de Linux.
