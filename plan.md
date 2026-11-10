Plan: CGC Scan más inteligente y eficiente

1. Situación actual
   Hoy scan hace siempre todo el trabajo:

- Prepara el motor, actualiza bases, descubre unidades y ejecuta todos los adaptadores aplicables.
- Entrega hallazgos individuales. El agente tiene que deducir solo qué actualizar, en qué orden y con qué comando.
- Para verificar un parche hay que repetir el escaneo completo.
- No guarda memoria del último resultado: compare exige rutas a dos reportes.
- La salida completa es grande. En proyectos medianos, muchas referencias y descripciones consumen tokens que el agente no necesita al principio.
  El objetivo tiene dos partes:

1. Un comando one-shot que entregue todo lo que el agente necesita para actuar.
2. Comandos baratos y específicos para iterar sin repetir ese costo.
3. Modelo de comandos propuesto
   Comando Costo Para qué
   cgc-scan agent [ruta] Alto, una vez One-shot: escaneo, plan de remediación, recetas, comparación con la línea base y próximas acciones
   cgc-scan scan [ruta] Alto Se mantiene como está: reporte canónico completo
   cgc-scan status [ruta] Casi nulo Último resultado guardado, sin escanear
   cgc-scan plan [ruta] Nulo Plan de remediación desde el último reporte, sin escanear
   cgc-scan explain <fingerprint> Nulo Detalle completo de un hallazgo (descripción, referencias, evidencia)
   cgc-scan verify <fingerprint|grupo> Bajo Reescaneo solo del motor y la unidad afectados, más la comparación
   cgc-scan scan --only deps|secrets|code|config Medio Escaneo parcial por categoría
   cgc-scan scan --changed Bajo o medio Solo las unidades con cambios desde la línea base
   cgc-scan compare --baseline Nulo Compara contra la última línea base guardada, sin pasar rutas
   Flujo típico de un agente:
   cgc-scan agent . ← una vez al empezar (o si el proyecto cambió mucho)
   cgc-scan explain <fp> ← solo cuando necesita profundizar en un hallazgo
   (aplica parche, ejecuta test/build de la receta)
   cgc-scan verify <grupo> ← rápido, solo lo afectado
   cgc-scan status ← resumen sin escanear
4. Features de inteligencia
   3.1 Grupos de remediación (la mejora de mayor valor)
   Hoy el ejemplo de golang.org/x/text produce 5 hallazgos con 5 versiones corregidas distintas: 0.3.3, 0.3.7, 0.3.8, 0.39.0 y 0.41.0. El agente necesita una sola acción: subir a 0.41.0.
   Propuesta: agrupar por componente y calcular la versión mínima que corrige todo.
   "remediation_groups": [{
   "id": "rg-go-golang.org/x/text",
   "kind": "dependency_upgrade",
   "unit": "root",
   "package": { "ecosystem": "Go", "name": "golang.org/x/text", "from": "v0.3.0", "to": "v0.41.0" },
   "fixes": ["0ba3...", "13cb...", "41bb...", "6c1f...", "8f2a..."],
   "max_severity": "high",
   "breaking_risk": "minor",
   "direct": true,
   "commands": {
   "apply": "go get golang.org/x/text@v0.41.0 && go mod tidy",
   "origin": "cgc-scan"
   },
   "verification": { "status": "ready", "recipes": [...], "verify": "cgc-scan verify rg-go-golang.org/x/text" }
   }]
   Reglas:

- Versión objetivo: la mayor de las versiones corregidas, sin cruzar de major si existe una alternativa dentro del mismo major.
- breaking_risk: patch, minor, major o unknown, calculado con semver por ecosistema (Go con el sufijo /vN, npm, PEP 440, Composer y Cargo).
- Comandos de aplicación por ecosistema: go get, npm install pkg@x, composer require, cargo update -p --precise, pip install. Se marcan origin: cgc-scan. Son sugerencias, no recetas de confianza, y la CLI no las ejecuta.
- Hallazgos de código: se agrupan por archivo y regla (por ejemplo, 9 ubicaciones de detect-object-injection en catalog-forms.mjs forman un grupo).
- Secretos: se agrupan por credencial, con la acción “revocar y rotar”.
  3.2 Dependencia directa o transitiva
  Trivy ya entrega Packages con relaciones, y los lockfiles permiten deducirlas. Si la vulnerable es transitiva, el plan dice qué dependencia directa hay que subir, o que corresponde un override (overrides en npm, replace en Go). Esto evita parches que no compilan.
  3.3 Prioridad calculada y explicable
  Puntuación determinista, con sus factores visibles:
- severidad normalizada;
- KEV y EPSS cuando existan;
- alcanzabilidad (govulncheck);
- corrección disponible;
- dependencia directa;
- contexto de ruta: producción frente a test/, fixtures/ o examples/ (se baja la prioridad, pero el hallazgo no se oculta).
  "priority": { "score": 87, "rank": 1, "factors": ["high", "reachable", "fix_available", "direct"] }
  3.4 Próximas acciones (next_actions)
  Una lista ordenada y determinista que el agente puede seguir sin razonar desde cero:
  "next_actions": [
  { "action": "confirm_recipes", "unit": "backoffice", "command": "cgc-scan scan backoffice --confirm-recipes", "reason": "validación bloqueada" },
  { "action": "apply_group", "group": "rg-go-golang.org/x/text", "fixes": 5 },
  { "action": "revoke_secret", "fingerprint": "...", "user_required": true },
  { "action": "install_toolchain", "tool": "composer install", "unit": "phpapp", "reason": "Psalm omitido" }
  ]
  También cubre los motivos de ejecución incompleta (requirement_missing) con su acción concreta.
  3.5 Reducción de ruido
- Consolidar el mismo hallazgo en varias líneas en una entrada con un recuento de ubicaciones (en parte ya existe).
- Línea base: hallazgos aceptados o preexistentes marcados como baseline para que el agente se concentre en lo nuevo.
- --min-severity como filtro de vista: no cambia la política ni oculta nada del JSON canónico.

4. Features de eficiencia
   4.1 Estado local por proyecto
   Se guarda fuera del proyecto, en la caché:
   <cache>/cgc-scan/projects/<local_id>/
   latest.json último reporte canónico
   baseline.json línea base (manual o la primera ejecución)
   units/<unit>.json resultado por unidad y motor, con su clave de caché
   index.json fingerprints → grupo/unidad/motor
   Esto habilita status, plan, explain, verify y compare --baseline sin repetir el escaneo ni pasar rutas. Se aplican los mismos permisos 0600/0700 y la misma escritura atómica.
   4.2 Caché incremental por unidad y motor
   Clave de caché:
   hash(versión del motor, versión/fecha de la base, configuración efectiva,
   contenido de los manifiestos y lockfiles, hash del árbol fuente de la unidad)

- Si la clave no cambió, se reutiliza el resultado.
- Los motores de dependencias (Trivy vuln, govulncheck, cargo-audit) dependen sobre todo de los lockfiles: se invalidan poco.
- Los motores de código (ESLint, Psalm, Bandit, Semgrep) se invalidan con el árbol fuente de la unidad.
- El reporte declara el origen de cada resultado (cache: hit|miss) para no perder trazabilidad.
- --no-cache fuerza la ejecución completa.
  4.3 Bases sin actualizar en cada escaneo
  Hoy cada escaneo online actualiza las bases. Propuesta: db.refresh_after (por ejemplo 12 h). Dentro de ese plazo se reutiliza la base sin consultar la red, y el reporte muestra su antigüedad. update-db sigue forzando la actualización.
  4.4 Alcance reducido
- --only deps|secrets|code|config y --engines trivy,eslint.
- --changed: usa los metadatos locales de Git (sin operaciones remotas) para elegir solo las unidades con cambios. Lo que queda fuera aparece como not_evaluated frente a la línea base, nunca como resuelto.
- verify elige automáticamente el motor y la unidad de cada fingerprint o grupo.
  4.5 Costes fijos
- Semgrep en Docker: un contenedor por escaneo en lugar de uno por unidad.
- Trivy: en Docker, reutilizar el contenedor entre fases cuando sea posible, y medir el costo de --skip-dirs.
- govulncheck: espejo incremental de la base. Hoy la descarga inicial completa tarda unos 1 min 44 s; con un índice basado en modified solo se bajan los avisos que cambiaron.
- Concurrencia ajustada con benchmarks reales (H7-01 sigue parcial).
  4.6 Salida eficiente en tokens
- --format agent: JSON compacto con resumen, grupos, next_actions y fingerprints. Sin descripciones largas ni referencias; esas se piden con explain.
- --max-groups N y lotes, sin truncar en silencio.
- El JSON canónico (scan) se mantiene completo y sin cambios incompatibles.

5. El one-shot: cgc-scan agent
   Hace en una sola ejecución:
1. Prepara motores y bases (respetando refresh_after).
1. Escanea con la caché incremental.
1. Confirma recetas si se pasa --confirm-recipes.
1. Construye grupos, prioridades y next_actions.
1. Compara con la línea base (o la crea si no existe).
1. Guarda latest.json e índices.
1. Emite un documento agent con:

- summary (estado, cobertura, código de salida, recuentos);
- remediation_groups ordenados;
- next_actions;
- delta frente a la línea base (new, persistent, resolved, not_evaluated);
- blocked (recetas faltantes, toolchains, motores omitidos);
- report_path al JSON completo.
  Los códigos de salida son los mismos de scan. Que el one-shot sea lento la primera vez es aceptable; con la caché y las bases vigentes, una repetición sin cambios debería costar pocos segundos.

6. Contrato y compatibilidad

- Esquema 1.1.0, aditivo: remediation_groups, next_actions, priority.score/factors, dependency.direct, cache por motor y delta. Los consumidores de 1.0.0 no se rompen.
- Esquema separado agent-1.0.0 para --format agent.
- Se actualizan PRD, design y la skill en el mismo cambio, como exige el workload.

7. Fases propuestas
   Fase Contenido Valor Riesgo
   A Estado por proyecto + status, explain, plan, compare --baseline Iteración sin reescanear Bajo
   B Grupos de remediación, semver/breaking_risk, comandos por ecosistema, prioridad La mayor ganancia de inteligencia Medio (semver por ecosistema)
   C next_actions + cgc-scan agent + --format agent One-shot completo Bajo, sobre A y B
   D verify focalizado, --only, --engines, --changed Iteración rápida Medio
   E Caché incremental por unidad/motor + db.refresh_after Eficiencia en repeticiones Medio (invalidación correcta)
   F Directo/transitivo y overrides sugeridos Parches que sí compilan Medio
   G Costes fijos: Semgrep en un contenedor, espejo incremental de Go Menor latencia Bajo
   H Skill 1.1, documentación, benchmarks antes y después Adopción y medición Bajo
   Orden recomendado: A → B → C (el one-shot útil sale pronto), después D → E (eficiencia) y por último F → G → H.
   Pruebas por fase: tablas para semver y agrupación, fixtures reales (el caso x/text debe dar un solo grupo con destino 0.41.0), pruebas de invalidación de caché, comparaciones contra la línea base y golden files del formato agent.
8. Decisiones que necesito que confirmes
9. Nombre del one-shot: ¿cgc-scan agent, o scan --agent?
10. ¿La CLI ejecuta las recetas? El PRD (§6.6) dice que la CLI no ejecuta tests ni build. Propongo mantenerlo: verify reescanea y muestra los comandos, pero no los ejecuta. La alternativa sería un --run-recipes explícito, lo que exige cambiar el PRD.
11. Comandos de aplicación (go get …, npm install …): propongo emitirlos como sugerencias origin: cgc-scan, sin ejecutarlos. ¿De acuerdo?
12. Línea base automática: ¿la primera ejecución de agent crea la línea base, o se fija solo con un cgc-scan baseline set explícito?
13. db.refresh_after por defecto: ¿12 h, 24 h u otro valor?
14. Contexto de ruta: ¿bajar la prioridad de los hallazgos en test/, fixtures/ y examples/, sin ocultarlos?
    Con esas respuestas puedo convertir esto en tareas numeradas para workload.md con estimaciones, o empezar por la fase A cuando cambies al agente de construcción.
