package report

import "io"

// EmitRaw escribe contenido ya renderizado por otro paquete de dominio. Se usa
// en `compare`, donde el render no puede vivir en report por el ciclo de
// dependencias; la escritura a stdout sigue concentrada aquí.
func EmitRaw(w io.Writer, data []byte) error {
	_, err := w.Write(data)
	return err
}
