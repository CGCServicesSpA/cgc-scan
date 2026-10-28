# Soporte y triage

## Canales

- **Errores reproducibles y dudas de uso:** issues de GitHub con la plantilla.
- **Vulnerabilidades de CGC Scan:** GitHub Security Advisories o
  `seguridad@cgcservices.cl` (canal privado, ver [`SECURITY.md`](../SECURITY.md)).
- **Vulnerabilidades de un motor externo:** repórtalas al proyecto del motor;
  CGC Scan coordina si el impacto afecta a la CLI.

## Qué incluir en un reporte

1. `cgc-scan --version` (incluye esquema y motores fijados).
2. Sistema operativo, arquitectura y modalidad (`docker` o `global`).
3. Comando exacto y código de salida.
4. `--log-format json` si es posible (sin secretos).
5. Reporte mínimo con `--report-out`, revisado para no incluir datos sensibles.
6. Si el problema es de un proyecto concreto, un fixture mínimo reproducible.

Nunca adjuntes valores reales de secretos. Usa cadenas ficticias y enmascaradas.

## Triage

| Severidad | Ejemplo | Primera respuesta | Objetivo de corrección |
| --- | --- | --- | --- |
| Crítica | Ejecución de código, fuga de secretos, escape de sandbox | 1 día hábil | 7 días |
| Alta | Resultado limpio con cobertura incompleta, bypass de política | 3 días hábiles | 30 días |
| Media | Fallo de un adaptador con workaround, reporte incorrecto | 10 días hábiles | 90 días |
| Baja | Mensaje confuso, documentación | 10 días hábiles | siguiente release |

Etiquetas recomendadas: `bug`, `adapter:<motor>`, `coverage`, `isolation`,
`policy`, `prompt`, `docs`, `security`.

## Criterios de cierre

- Reproducción con un fixture o pasos mínimos.
- Prueba de regresión en el repositorio.
- Documentación actualizada si cambia el contrato.
- Nota en el changelog y, si aplica, aviso de seguridad.

## Divulgación

Por defecto, 90 días desde la evaluación o antes si hay parche y acuerdo. Se
publica un GitHub Security Advisory y un release parcheado. Si el problema
involucra a un motor externo, se coordina con su proyecto y se indica en el aviso.
