package platform

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashBytes devuelve el hash sha256 (hex) de data. Es el helper reutilizable
// de hash: ninguna otra implementación debe duplicarlo.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashFile devuelve el hash sha256 (hex) del contenido de un archivo regular.
// Los archivos que superan limit se rechazan; el llamador decide el tope.
func HashFile(path string, limit int64) (string, error) {
	data, err := ReadFileBounded(path, limit)
	if err != nil {
		return "", err
	}
	return HashBytes(data), nil
}
