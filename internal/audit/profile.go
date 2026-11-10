package audit

import (
	"errors"
	"fmt"
)

// Fases obligatorias del protocolo. El vocabulario es versionado: una fase
// declarada obligatoria por el perfil debe completarse antes de que la corrida
// pueda declararse completa.
const (
	PhaseHunt          = "hunt"
	PhaseVerification  = "verification"
	PhaseFinalCritique = "final-critique"
	PhasePriorRework   = "prior-rework"
)

// ProfilePolicy separa la política del perfil de la construcción y selección
// de unidades: define granularidad, fases obligatorias y condiciones de
// cierre. Los datos vienen del catálogo versionado; este tipo los expone.
type ProfilePolicy struct {
	Profile            string
	Granularity        string
	VerificationPasses int
	Critique           string
	PriorRework        bool
}

// ProfilePolicyFor resuelve la política de un perfil desde el catálogo.
func ProfilePolicyFor(profile string, cat *Catalog) (*ProfilePolicy, error) {
	if cat == nil {
		return nil, errors.New("auditoría: falta el catálogo para resolver la política de perfil")
	}
	meta, ok := cat.Profiles[profile]
	if !ok {
		return nil, fmt.Errorf("auditoría: el catálogo no declara el perfil %q", profile)
	}
	return &ProfilePolicy{
		Profile:            profile,
		Granularity:        meta.Granularity,
		VerificationPasses: meta.VerificationPasses,
		Critique:           meta.Critique,
		PriorRework:        meta.PriorRework,
	}, nil
}

// MandatoryPhases declara, en orden, las fases que el perfil exige para
// declarar la corrida completa.
func (p *ProfilePolicy) MandatoryPhases() []string {
	phases := []string{PhaseHunt, PhaseVerification}
	if p.Critique == CritiqueWaveAndFinal {
		phases = append(phases, PhaseFinalCritique)
	}
	if p.PriorRework {
		phases = append(phases, PhasePriorRework)
	}
	return phases
}

// UnimplementedPhases declara las fases obligatorias del perfil que esta
// versión del motor todavía no implementa. Una corrida con un perfil que
// exige una fase no implementada nunca se declara completa.
func (p *ProfilePolicy) UnimplementedPhases() []string {
	var out []string
	for _, phase := range p.MandatoryPhases() {
		switch phase {
		case PhaseHunt, PhaseVerification:
			// Implementadas.
		case PhaseFinalCritique:
			// La crítica de cobertura llega con P1-2.
			out = append(out, phase)
		case PhasePriorRework:
			// La revalidación de corridas anteriores llega con P1-6.
			out = append(out, phase)
		}
	}
	return out
}

// ImplementedPhases son las fases obligatorias con comportamiento entregado.
func (p *ProfilePolicy) ImplementedPhases() []string {
	var out []string
	for _, phase := range p.MandatoryPhases() {
		unimplemented := false
		for _, missing := range p.UnimplementedPhases() {
			if missing == phase {
				unimplemented = true
				break
			}
		}
		if !unimplemented {
			out = append(out, phase)
		}
	}
	return out
}

// FirstUnimplementedPhase devuelve la primera fase obligatoria sin
// implementación, o "" si todas están implementadas.
func (p *ProfilePolicy) FirstUnimplementedPhase() string {
	for _, phase := range p.UnimplementedPhases() {
		return phase
	}
	return ""
}

// GranularityLabel describe la granularidad del perfil en texto legible.
func (p *ProfilePolicy) GranularityLabel() string {
	switch p.Granularity {
	case GranularitySubsystemDomain:
		return "subsistema × dominio"
	case GranularitySubsystemClass:
		return "subsistema × frontera × clase"
	case GranularitySubsystemLifecycle:
		return "subsistema × ciclo de vida"
	default:
		return p.Granularity
	}
}

// ValidateUnimplementedPhases informa si el perfil exige fases que el motor
// todavía no implementa, con el nombre de la primera.
func ValidateUnimplementedPhases(p *ProfilePolicy) (string, bool) {
	phase := p.FirstUnimplementedPhase()
	return phase, phase != ""
}
