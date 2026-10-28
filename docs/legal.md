# Licencias y datos personales

> Este documento describe decisiones de ingeniería, no es asesoría legal.

## Licencia de CGC Scan

Apache-2.0. Ver [`LICENSE`](../LICENSE). La licencia incluye una concesión
explícita de patentes y es compatible con todas las dependencias directas.

## Motores y reglas

| Componente | Versión fijada | Licencia | Distribución |
| --- | --- | --- | --- |
| Trivy | 0.76.1 | Apache-2.0 | Descarga del release oficial; no se empaqueta |
| govulncheck (`golang.org/x/vuln`) | 1.9.0 | BSD-3-Clause | Enlazado como biblioteca |
| ESLint | 10.13.0 | MIT | Instalado con npm, sin scripts |
| eslint-plugin-security | 4.2.0 | Apache-2.0 | Ídem |
| @typescript-eslint/parser | 8.72.1 | MIT | Ídem |
| Psalm | 6.20.3 | MIT | Phar oficial verificado |
| cargo-audit | 0.22.2 | MIT OR Apache-2.0 | Binario del release verificado |
| Bandit | 1.9.4 | Apache-2.0 | Ruedas de PyPI con hashes |
| Semgrep CE | 1.157.0 | LGPL-2.1 | Imagen o binario externo; no se enlaza |
| Reglas propias CGC | 1.0.0 | Apache-2.0 | Empaquetadas |

Semgrep es un proceso externo: la CLI no enlaza su código, por lo que LGPL-2.1 no
se propaga al binario. No se descargan ni redistribuyen reglas del registro
público de Semgrep.

Las dependencias Go directas y sus licencias están en
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## Ley 21.719 (protección de datos personales)

- **CGC no recibe datos.** No hay telemetría, cuentas ni servicios propios en v1.
- **Tratamiento local.** Los reportes pueden contener rutas, fragmentos de
  código y, eventualmente, datos personales del proyecto. Permanecen en el
  equipo del usuario con permisos 0600/0700 y los secretos se enmascaran.
- **Transferencias durante la preparación.** Se descargan imágenes, binarios y
  bases de fuentes públicas sin adjuntar datos del proyecto. No hay transferencia
  de datos personales hacia CGC.
- **Rol de CGC.** En v1 CGC no actúa como responsable ni encargado del
  tratamiento de los datos del proyecto: la herramienta es local.
- **Cambios de alcance.** Si se agrega telemetría, licenciamiento en línea,
  cuentas o un servicio de reportes, hay que repetir el análisis antes de
  implementarlo (vigencia plena: 1 de diciembre de 2026).

## Marca

La búsqueda de marca «CGC Scan»/«cgc-scan» en INAPI requiere reCAPTCHA y no es
automatizable. Paquetes y dominios están libres (D-03). La verificación manual en
las clases 9 y 42 queda registrada como gate legal de H7-06; no bloquea el
desarrollo ni el uso interno, pero debe completarse antes de publicar v1.0.0.

## Obligaciones del release

- Incluir `LICENSE`, `SECURITY.md` y `THIRD_PARTY_NOTICES.md`.
- Publicar SBOM CycloneDX y checksums firmados.
- Mantener el manifiesto de motores con su licencia y procedencia.
- Revisar cada nueva dependencia directa y registrarla en `design.md` §2.
