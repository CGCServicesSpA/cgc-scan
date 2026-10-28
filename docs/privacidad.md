# Privacidad y seguridad de la ejecución

## Local primero

CGC Scan no envía código, inventarios, secretos ni resultados a CGC Services ni
a terceros. No hay telemetría, cuentas ni licenciamiento en línea en v1. La
preparación descarga imágenes, binarios y bases desde fuentes públicas, sin
adjuntar datos del proyecto.

El agente que invoca la CLI puede enviar el reporte a su proveedor; eso queda
fuera del control de la CLI. La configuración de ese agente determina el
tratamiento posterior.

## Fases separadas

1. **Preparación**: se permite red para descargar motores, imágenes y bases.
   Nunca se monta ni se lee el proyecto en esta fase.
2. **Escaneo**: el proyecto se monta en solo lectura. El runner global usa un
   proxy inválido y variables de entorno mínimas; el runner Docker usa
   `--network none`. No hay `clone`, `fetch`, `pull` ni `checkout` del proyecto.

## Aislamiento

| Nivel | Cómo se logra | Garantía |
| --- | --- | --- |
| `enforced` | Contenedor con `--network none` | El sistema impide la salida de red |
| `configured` | Opciones offline, telemetría y versión desactivadas, HOME aislado, proxy cerrado | Ningún motor soportado intenta conectarse; no es un sandbox |

El reporte declara el nivel efectivo y `verified_by`. Nunca declara `enforced` sin
haberlo logrado. `--require-isolation enforced` falla antes de analizar si algún
motor del proyecto solo ofrece `configured`.

La verificación por versión fijada se ejecuta con `strace` y falla ante cualquier
`connect` no local (`.github/workflows/isolation.yml`).

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
