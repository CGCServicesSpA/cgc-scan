# Política de seguridad

CGC Scan es una herramienta de seguridad que se ejecuta con acceso de lectura al código de los usuarios. Tratamos los reportes de vulnerabilidad con prioridad.

## Cómo reportar

- Usa **GitHub Security Advisories** del repositorio (`Security` → `Report a vulnerability`). Es un canal privado.
- Si no puedes usar GitHub, escribe a `seguridad@cgcservices.cl` con el asunto `[cgc-scan]`.
- No abras un issue público para una vulnerabilidad explotable.

Incluye, si es posible: versión de la CLI (`cgc-scan --version`), sistema operativo y arquitectura, versión del motor implicado, pasos mínimos de reproducción y el impacto que estimas. **No adjuntes secretos reales**: usa valores ficticios y enmascarados.

## Plazos de respuesta

| Etapa | Objetivo |
| --- | --- |
| Acuse de recibo | 3 días hábiles |
| Evaluación inicial y severidad | 10 días hábiles |
| Corrección o mitigación | 90 días desde la evaluación, según severidad |
| Divulgación coordinada | Acordada con quien reporta; por defecto 90 días |

Publicamos un aviso en GitHub Security Advisories y un release parcheado. Si el problema afecta a un motor externo (Trivy, ESLint, Psalm, cargo-audit, Bandit, Semgrep), coordinamos con su proyecto y lo indicamos en el aviso.

## Alcance

Dentro del alcance: la CLI, el esquema del reporte, el aprovisionamiento y verificación de motores, el aislamiento de red, el enmascarado de secretos y la cadena de suministro de los releases.

Fuera del alcance: vulnerabilidades del proyecto escaneado, del daemon Docker o de los motores externos por sí solos (repórtalas a su proyecto), y ataques que requieran control físico del equipo o privilegios de root preexistentes.

## Versiones soportadas

Solo la última versión menor publicada recibe parches de seguridad. Las versiones anteriores se documentan en el aviso correspondiente.

## Compromiso

No tomamos represalias contra quien reporta de buena fe y respeta la confidencialidad hasta la divulgación coordinada.
