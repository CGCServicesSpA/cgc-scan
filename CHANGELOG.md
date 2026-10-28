# Changelog

## 0.1.0-rc.3 — 2026-10-28

- Salida enriquecida: por hallazgo se muestran versión corregida, descripción,
  severidad original y de otras fuentes, CVSS, alcanzabilidad, remediación y
  referencias.
- Receta de verificación por hallazgo (`verification`): recetas confirmadas de
  test/build de su unidad, candidatos detectados como no confiables, recetas
  faltantes y comando de reescaneo con la modalidad y el modo offline originales.
- Los secretos no se declaran listos para validar: exigen revocación y rotación.
- Actualización a Go 1.27.3 y dependencias (`x/text`, `x/telemetry`, `pflag`).
- Instalador local `install.sh` con compilación, empaquetado, instalación
  atómica, respaldo, instalación desde artefacto y desinstalación.
- El paquete local incluye `INSTALL.txt`, licencia, avisos de terceros y el
  instalador para máquinas sin Go.

## 0.1.0-rc.2 — 2026-10-28

- SBOM CycloneDX 1.6, firma cosign y atestación de procedencia verificadas.
- Fórmula Homebrew con checksums reales.

## 0.1.0-rc.1 — 2026-10-27

- Primer release candidate firmado con checksums y SBOM.
