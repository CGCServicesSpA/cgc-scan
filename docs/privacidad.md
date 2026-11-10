# Privacidad y seguridad de la ejecución

## Local primero

CGC Scan no envía código, secretos ni resultados a CGC Services ni a terceros.
No hay telemetría, cuentas ni licenciamiento en línea en v1. La preparación
descarga imágenes, binarios y bases desde fuentes públicas, sin adjuntar datos
del proyecto.

**Excepción declarada: dependencias en contenedores de toolchain.** Cuando un
adaptador se ejecuta en la imagen del lenguaje (Docker disponible), el motor
resuelve las dependencias del proyecto contra el registro público del
ecosistema (`proxy.golang.org`, npm, Packagist, crates.io, PyPI). Eso revela al
registro los **nombres y versiones de las dependencias**, no el código fuente
ni los secretos. El reporte lo declara en `coverage.limitations`, el motor queda
como `isolation: configured` y nunca `enforced`. Para evitarlo:

- `--offline`: el contenedor corre con red deshabilitada y usa el volumen de
  caché del lenguaje; si las dependencias no están cacheadas, la unidad queda
  incompleta.
- `CGC_SCAN_TOOLCHAIN=host`: usa los toolchains del equipo con el proxy cerrado
  y el HOME aislado, como antes de esta función.
- Sin Docker: se mantiene el comportamiento del host.

El agente que invoca la CLI puede enviar el reporte a su proveedor; eso queda
fuera del control de la CLI. La configuración de ese agente determina el
tratamiento posterior.

## Fases separadas

1. **Preparación**: se permite red para descargar motores, imágenes, bases y
   para construir la imagen derivada del lenguaje. Nunca se monta ni se lee el
   proyecto en esta fase.
2. **Escaneo**: el proyecto se monta en solo lectura. El runner global usa un
   proxy inválido y variables de entorno mínimas; el runner Docker usa
   `--network none`, salvo los contenedores de toolchain, que mantienen red para
   resolver dependencias (ver la excepción anterior). No hay `clone`, `fetch`,
   `pull` ni `checkout` del proyecto.

## Aislamiento

| Nivel | Cómo se logra | Garantía |
| --- | --- | --- |
| `enforced` | Contenedor con `--network none` | El sistema impide la salida de red |
| `configured` | Opciones offline, telemetría y versión desactivadas, HOME aislado, proxy cerrado | Ningún motor soportado intenta conectarse por su cuenta; no es un sandbox |
| `configured` (toolchain) | Imagen oficial del lenguaje con la herramienta fijada; proyecto en solo lectura; red habilitada solo para resolver dependencias | Se declara `configured`, nunca `enforced`; la limitación es visible en el reporte |

El reporte declara el nivel efectivo y `verified_by`. Nunca declara `enforced` sin
haberlo logrado. `--require-isolation enforced` falla antes de analizar si algún
motor del proyecto solo ofrece `configured`.

La verificación por versión fijada se ejecuta con `strace` y falla ante cualquier
`connect` no local (`.github/workflows/isolation.yml`). La prueba cubre el
runner de motores sin dependencias; el tráfico de resolución de dependencias de
un contenedor de toolchain es intencional y se documenta como limitación, no
como `enforced`.

## Dependencias de proyecto en contenedores

- El proyecto se monta en `/src` en **solo lectura**. La CLI nunca escribe en el
  proyecto ni ejecuta `composer install`, `npm install`, `pip install` ni
  `cargo build` sobre él.
- Las bases locales (Go, RustSec) y la configuración generada de Psalm se copian
  a un directorio temporal del usuario y se montan desde ahí; el directorio de
  datos de la CLI no siempre está compartido con el daemon. El staging se
  elimina al terminar.
- Cada lenguaje usa un volumen `cgc-scan-toolchain-*` propio del usuario con
  módulos y paquetes descargados; nunca contiene código del proyecto.
- La imagen base se resuelve por digest al construir y el digest efectivo queda
  en `tools.engines[].preparation[]`. No está en `manifest/trust.json` porque
  depende de la versión del proyecto.
- Un fallo de build o de descarga no se silencia: la unidad cae al toolchain del
  host o queda con `requirement_missing` y la ejecución es incompleta.

## Entorno de los motores

- Lista permitida, no lista de exclusión: `PATH` acotado, `HOME` y `TMPDIR`
  propios del motor, `LANG`, `TZ` y variables de proxy.
- No se heredan tokens, credenciales de nube, `DOCKER_HOST` ni configuraciones
  personales.
- Los grupos de procesos se terminan con el padre; hay timeout y tope de salida.
- El proyecto se abre con `os.Root`: los enlaces y `..` no escapan de la raíz.

## Secretos

- Nunca se emite el valor completo: tipo, ubicación y huella HMAC truncada con
  una sal por instalación.
- Los reportes, salidas originales y bases se guardan con permisos 0600/0700.
- `--report-out` es atómico, privado y se excluye del escaneo.
- La remediación de un secreto incluye **revocar y rotar**; borrarlo del código
  no basta.

## Repositorio hostil

- La política `cgc-scan.toml` se lee como dato no confiable: claves prohibidas
  ignoradas, solo agrega exclusiones, solo endurece el umbral, excepciones con
  vencimiento obligatorio.
- No se cargan configuraciones ejecutables ni plugins del proyecto: ESLint usa
  `--no-config-lookup` con configuración propia; Psalm usa configuración
  generada; Trivy recibe flags explícitos.
- Los hooks, scripts de instalación y dependencias del proyecto no se ejecutan.

## Ley 21.719

El análisis de datos personales está en [`legal.md`](legal.md). Cualquier
funcionalidad futura de telemetría, cuentas o reporte en línea exige repetir la
revisión antes de implementarse.
