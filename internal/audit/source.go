package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// Modos de fuente de una corrida. La representación es explícita: o la
// corrida describe el snapshot de una revisión de Git con el árbol limpio al
// iniciar, o describe el árbol actual de trabajo.
const (
	SourceModeRevision = "revision"
	SourceModeWorktree = "worktree"
)

// Roles de sello de fuente: los registros presentables —el escalado y el
// final— registran el hash de su fuente al crearse.
const (
	SourceRoleEscalated = "escalated"
	SourceRoleFinal     = "final"
)

// SourceInfo declara el modo de fuente de la corrida. Vive en el estado
// interno (state.json): el contrato público del ledger no cambia.
type SourceInfo struct {
	Mode     string `json:"mode"`
	Revision string `json:"revision,omitempty"`
	Dirty    bool   `json:"dirty,omitempty"`
}

// gitTimeout acota cada invocación local de git.
const gitTimeout = 10 * time.Second

// sourceReadLimit es el límite de lectura de un archivo fuente citado.
const sourceReadLimit = 32 << 20

// Source es el resolvedor local de fuentes: en modo revisión lee blobs de Git
// del snapshot declarado; en modo worktree lee el árbol actual. Nunca accede
// a la red y nunca sustituye una revisión ausente por el árbol actual.
type Source struct {
	Info SourceInfo
	root string
	// resolvedRoot es la raíz con enlaces simbólicos resueltos: la
	// contención de las citas se compara contra ella.
	resolvedRoot string
}

// DeriveSourceInfo deriva el modo de fuente de un ledger sin declaración
// explícita (estados anteriores a state.json): revisión solo si hay una
// revisión declarada y el árbol estaba limpio.
func DeriveSourceInfo(l *Ledger) SourceInfo {
	ref := strings.TrimSpace(l.Run.SourceRef)
	if ref != "" && ref != "worktree" && !l.Run.Dirty {
		return SourceInfo{Mode: SourceModeRevision, Revision: ref}
	}
	return SourceInfo{Mode: SourceModeWorktree, Dirty: l.Run.Dirty}
}

// ResolveSource determina el modo de fuente de una corrida nueva a partir de
// la referencia y la suciedad declaradas.
func ResolveSource(root, sourceRef string, dirty bool) (*Source, error) {
	l := &Ledger{Run: Run{SourceRef: sourceRef, Dirty: dirty}}
	return SourceFrom(root, DeriveSourceInfo(l))
}

// SourceFrom comprueba que el modo y la revisión declarados sean resolubles
// localmente y devuelve el resolvedor. Una revisión no disponible es un
// bloqueo explícito, no un fallback al árbol actual.
func SourceFrom(root string, info SourceInfo) (*Source, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("auditoría: falta la raíz de la fuente")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if infoStat, statErr := os.Stat(abs); statErr != nil || !infoStat.IsDir() {
		return nil, fmt.Errorf("auditoría: la raíz de la fuente %s no existe o no es un directorio", abs)
	}
	switch info.Mode {
	case SourceModeRevision:
		if strings.TrimSpace(info.Revision) == "" {
			return nil, errors.New("auditoría: el modo revisión exige una revisión declarada")
		}
		if err := gitVerifyRevision(abs, info.Revision); err != nil {
			return nil, fmt.Errorf("auditoría: la revisión %q no es resoluble en el repositorio local: %w", info.Revision, err)
		}
	case SourceModeWorktree:
	default:
		return nil, fmt.Errorf("auditoría: modo de fuente desconocido: %q", info.Mode)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("auditoría: resolver la raíz %s: %w", abs, err)
	}
	return &Source{Info: info, root: abs, resolvedRoot: resolved}, nil
}

// ResolveLine comprueba que el archivo citado exista en la fuente declarada y
// que la línea esté dentro del conteo. Devuelve el hash de la fuente del
// archivo: el oid del blob en modo revisión o el sha256 del contenido del
// árbol en modo worktree.
func (s *Source) ResolveLine(rel string, line int) (string, error) {
	if !ValidRepoPath(rel) {
		return "", fmt.Errorf("la cita %q no es una ruta relativa al repositorio", rel)
	}
	if line < 1 {
		return "", fmt.Errorf("la cita %q declara la línea %d; debe ser positiva", rel, line)
	}
	if s.Info.Mode == SourceModeRevision {
		return s.resolveRevisionLine(rel, line)
	}
	return s.resolveWorktreeLine(rel, line)
}

// HashFile devuelve el hash de la fuente del archivo sin comprobar líneas.
func (s *Source) HashFile(rel string) (string, error) {
	if !ValidRepoPath(rel) {
		return "", fmt.Errorf("la cita %q no es una ruta relativa al repositorio", rel)
	}
	if s.Info.Mode == SourceModeRevision {
		return gitBlobOID(s.root, s.Info.Revision+":"+rel)
	}
	full, err := s.safePath(rel)
	if err != nil {
		return "", err
	}
	return hashLocalFile(full)
}

func (s *Source) resolveRevisionLine(rel string, line int) (string, error) {
	spec := s.Info.Revision + ":" + rel
	data, err := gitBlob(s.root, spec)
	if err != nil {
		return "", fmt.Errorf("la cita %q no existe en la revisión %s", rel, s.Info.Revision)
	}
	if line > countLines(data) {
		return "", fmt.Errorf("la cita %q declara la línea %d y el snapshot tiene %d líneas", rel, line, countLines(data))
	}
	return gitBlobOID(s.root, spec)
}

func (s *Source) resolveWorktreeLine(rel string, line int) (string, error) {
	full, err := s.safePath(rel)
	if err != nil {
		return "", err
	}
	data, err := platform.ReadFileBounded(full, sourceReadLimit)
	if err != nil {
		return "", fmt.Errorf("la cita %q no se puede leer del árbol: %w", rel, err)
	}
	if line > countLines(data) {
		return "", fmt.Errorf("la cita %q declara la línea %d y el archivo tiene %d líneas", rel, line, countLines(data))
	}
	return hashBytes(data), nil
}

// safePath resuelve la cita dentro de la raíz y rechaza las rutas que
// escapan de ella, incluso mediante enlaces simbólicos.
func (s *Source) safePath(rel string) (string, error) {
	joined := filepath.Join(s.root, filepath.FromSlash(rel))
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", fmt.Errorf("la cita %q no existe en el árbol", rel)
	}
	if resolved != s.resolvedRoot && !strings.HasPrefix(resolved, s.resolvedRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("la cita %q escapa de la raíz del repositorio", rel)
	}
	return resolved, nil
}

// ValidateRecord comprueba cada cita de un registro —traza y evidencia—
// contra la fuente declarada. Los errores identifican el archivo y la línea.
func (s *Source) ValidateRecord(where string, r *Record) error {
	var is Issues
	for i := range r.Trace {
		if _, err := s.ResolveLine(r.Trace[i].File, r.Trace[i].Line); err != nil {
			is.addf("%s trace[%d]: %v", where, i, err)
		}
	}
	for i := range r.Evidence {
		if _, err := s.ResolveLine(r.Evidence[i].File, r.Evidence[i].Line); err != nil {
			is.addf("%s evidence[%d]: %v", where, i, err)
		}
	}
	return is.err()
}

// CitedFiles devuelve, sin duplicados y en orden determinista, los archivos
// citados por la traza y la evidencia de un registro.
func CitedFiles(r *Record) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(r.Trace)+len(r.Evidence))
	for _, step := range r.Trace {
		if !seen[step.File] {
			seen[step.File] = true
			out = append(out, step.File)
		}
	}
	for _, ev := range r.Evidence {
		if !seen[ev.File] {
			seen[ev.File] = true
			out = append(out, ev.File)
		}
	}
	sort.Strings(out)
	return out
}

// SourceStamper valida las citas de un registro y devuelve el hash de la
// fuente de cada archivo citado, tomado en el momento del registro. El broker
// la invoca durante la fase de validación de una entrega; no hace E/S.
type SourceStamper func(fingerprint, role string, record *Record) (map[string]string, error)

// mergeSourceStamps asocia al candidato los hashes devueltos por el stamper
// bajo el rol dado, con claves "<role>:<file>".
func mergeSourceStamps(cand *Candidate, role string, hashes map[string]string) {
	if len(hashes) == 0 {
		return
	}
	if cand.SourceHashes == nil {
		cand.SourceHashes = map[string]string{}
	}
	for file, hash := range hashes {
		cand.SourceHashes[role+":"+file] = hash
	}
}

// inheritSourceStamps re-prefija los sellos del rol origen como rol destino:
// un final que es exactamente el registro escalado presenta la fuente con la
// que ese registro se creó.
func inheritSourceStamps(cand *Candidate, from, to string) {
	for key, hash := range cand.SourceHashes {
		if file, ok := strings.CutPrefix(key, from+":"); ok {
			cand.SourceHashes[to+":"+file] = hash
		}
	}
}

// SourceDivergence declara un archivo citado por un registro final cuyo
// contenido cambió desde que el registro se creó.
type SourceDivergence struct {
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Recorded    string `json:"recorded_hash"`
	Current     string `json:"current_hash"`
}

// CheckDivergence compara los sellos de los registros finales con la fuente
// actual. Solo exige vigencia actual en modo worktree: en modo revisión la
// cita es histórica y permanece válida aunque cambie el árbol. Un archivo
// citado que desapareció es una divergencia, no un error de operación.
func (src *Source) CheckDivergence(c *Candidates) ([]SourceDivergence, error) {
	if src.Info.Mode != SourceModeWorktree {
		return nil, nil
	}
	var out []SourceDivergence
	for i := range c.Items {
		cand := &c.Items[i]
		if cand.State != CandidateDecided || cand.Final == nil {
			continue
		}
		for _, file := range CitedFiles(cand.Final) {
			recorded, ok := cand.SourceHashes[SourceRoleFinal+":"+file]
			if !ok {
				// Un registro sin sello (estado anterior a los sellos) no
				// permite afirmar ni negar la vigencia: no se declara cambio.
				continue
			}
			current, err := src.HashFile(file)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no existe") {
					return nil, fmt.Errorf("candidato %s: comprobar vigencia de %q: %w", cand.Fingerprint, file, err)
				}
				current = ""
			}
			if current != recorded {
				out = append(out, SourceDivergence{
					Fingerprint: cand.Fingerprint, File: file,
					Recorded: recorded, Current: current,
				})
			}
		}
	}
	return out, nil
}

func gitVerifyRevision(root, rev string) error {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git rev-parse %q: %w", rev, err)
	}
	return nil
}

func gitBlobOID(root, spec string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--verify", "--quiet", spec)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolver %q en el repositorio local: %w", spec, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func gitBlob(root, spec string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", root, "cat-file", "blob", spec)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("leer %q del repositorio local: %w", spec, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(pipe, sourceReadLimit+1))
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("leer %q: %w", spec, readErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("leer %q del repositorio local: %w", spec, waitErr)
	}
	if len(data) > sourceReadLimit {
		return nil, fmt.Errorf("%q supera el límite de lectura de fuente (%d bytes)", spec, sourceReadLimit)
	}
	return data, nil
}

func hashLocalFile(path string) (string, error) {
	data, err := platform.ReadFileBounded(path, sourceReadLimit)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

// dirtiness declara si la fuente de la corrida es un árbol con cambios.
func (s *Source) dirtiness() bool { return s.Info.Dirty }

// sourceRef es la referencia declarada: el oid de la revisión o "worktree".
func (s *Source) sourceRef() string {
	if s.Info.Mode == SourceModeRevision {
		return s.Info.Revision
	}
	return "worktree"
}

func hashBytes(data []byte) string {
	return "sha256:" + platform.HashBytes(data)
}

// countLines cuenta las líneas de una fuente: un archivo vacío tiene 0
// líneas y la última línea sin salto final cuenta como línea.
func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}
