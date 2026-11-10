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
Comprueba que el módulo tenga `go.mod`, que la base local exista
(`cgc-scan update-db`) y que el motor haya completado. Con Docker se ejecuta en
una imagen derivada de la versión Go del proyecto; revisa
`tools.engines[].preparation[]` y `coverage.limitations`. Sin Docker necesita el
toolchain Go en `PATH`. En modo offline no se descargan módulos: si faltan en la
caché del lenguaje, la unidad queda incompleta.

**¿Necesito instalar Go, Node, PHP, Rust o Python?**
No si Docker está disponible. CGC Scan lee la versión que declara el proyecto,
construye la imagen del lenguaje y ejecuta el adaptador dentro. La primera vez
puede tardar por la descarga de la imagen base y la instalación de la
herramienta; las siguientes reutilizan la imagen y el volumen de caché. Sin
Docker sí hacen falta los toolchains del equipo y, si falta alguno, el adaptador
se omite con `requirement_missing`.

**¿Por qué la primera ejecución es más lenta?**
Prepara bases, descarga la imagen base del lenguaje y construye la imagen
derivada con la herramienta fijada. La segunda ejecución reutiliza todo eso y,
si el proyecto no cambió, la caché por unidad devuelve `hit`.

**¿Puedo evitar que las dependencias salgan del equipo?**
Con `--offline`, el contenedor de toolchain corre sin red y usa el volumen de
caché; si las dependencias no están cacheadas, la unidad queda incompleta.
`CGC_SCAN_TOOLCHAIN=host` fuerza los toolchains del equipo con el proxy cerrado.
Con Docker y red, el registro del ecosistema ve nombres y versiones de
dependencias, nunca código ni secretos; el reporte lo declara.

**¿La CLI envía datos a algún servicio?**
No envía código, secretos ni resultados a CGC ni a terceros; no hay telemetría.
La preparación descarga motores, imágenes y bases de fuentes públicas. Con
Docker, los contenedores de toolchain resuelven dependencias contra el registro
público del ecosistema (nombres y versiones, no código); el resto de motores usa
red cerrada y proxy inválido.

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
