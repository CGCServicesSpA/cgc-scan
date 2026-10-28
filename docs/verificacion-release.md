# Verificación de artefactos de release

Cada release de CGC Scan publica:

- `cgc-scan_<versión>_<os>_<arch>.tar.gz` para linux/darwin × amd64/arm64.
- `checksums.txt` con SHA-256 de cada archivo.
- `checksums.txt.sigstore.json`: firma sin clave de Sigstore sobre los checksums.
- `<archivo>.sbom.json` en CycloneDX 1.6.
- La atestación de procedencia SLSA cuando el flujo de release la produzca.

## Antes de etiquetar

1. Actualiza `VERSION` y `CHANGELOG.md`.
2. Ejecuta `./install.sh --package` y prueba el paquete en un prefijo temporal.
3. Crea el tag `v<VERSION>`; el flujo de release usa ese tag para GoReleaser.

## 1. Verificar la firma de los checksums

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/CGCServicesSpA/cgc-scan/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

El comando debe responder `Verified OK`. La identidad esperada es el workflow de
release del repositorio; no se acepta cualquier certificado de Sigstore.

## 2. Verificar el artefacto

```bash
sha256sum --check --ignore-missing checksums.txt
tar -xzf cgc-scan_<versión>_darwin_arm64.tar.gz
./cgc-scan --version
```

`--version` debe coincidir con la versión publicada y mostrar el esquema y los
motores fijados.

## 3. Revisar el SBOM

```bash
syft convert <archivo>.sbom.json -o table
```

El SBOM enumera las dependencias Go y sus licencias. El release incluye también
`LICENSE`, `SECURITY.md` y las notas de la versión.

## 4. Procedencia

El release publica atestaciones de procedencia de compilación de GitHub
(SLSA build provenance). Se verifican con:

```bash
gh attestation verify cgc-scan_<versión>_<os>_<arch>.tar.gz \
  --repo CGCServicesSpA/cgc-scan
```

La verificación se ejecutó sobre `v0.1.0-rc.1` y `v0.1.0-rc.2`: firma
`Verified OK`, checksums correctos, SBOM CycloneDX 1.6 y procedencia verificada.

## 5. Reportar un problema

Si una verificación falla, no instales el artefacto y sigue
[`SECURITY.md`](../SECURITY.md). No abras un issue con el binario adjunto.
