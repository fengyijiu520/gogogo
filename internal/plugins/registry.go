package plugins

import "context"

import "strings"

type ScannerFactory func() Scanner

type PluginRegistration struct {
	ID          string
	Name        string
	Version     string
	Description string
	Type        PluginType
	Factory     ScannerFactory
}

type Provider interface {
	Registrations() []PluginRegistration
}

type Registry struct {
	plugins []PluginRegistration
}

func NewRegistry() *Registry {
	return &Registry{plugins: make([]PluginRegistration, 0, 8)}
}

func (r *Registry) Register(item PluginRegistration) {
	if r == nil || item.Factory == nil {
		return
	}
	if item.ID == "" {
		return
	}
	if strings.TrimSpace(item.Name) == "" {
		item.Name = item.ID
	}
	if item.Type == "" {
		item.Type = PluginTypeDetector
	}
	for _, existing := range r.plugins {
		if existing.ID == item.ID {
			return
		}
	}
	r.plugins = append(r.plugins, item)
}

func (r *Registry) RegisterProvider(provider Provider) {
	if r == nil || provider == nil {
		return
	}
	for _, item := range provider.Registrations() {
		r.Register(item)
	}
}

func (r *Registry) Build() []Scanner {
	return r.BuildWithFilter(nil, nil)
}

func (r *Registry) BuildWithFilter(enabledIDs, disabledIDs []string) []Scanner {
	if r == nil || len(r.plugins) == 0 {
		return nil
	}
	enabled := make(map[string]struct{}, len(enabledIDs))
	for _, item := range enabledIDs {
		item = normalizePluginID(item)
		if item == "" {
			continue
		}
		enabled[item] = struct{}{}
	}
	disabled := make(map[string]struct{}, len(disabledIDs))
	for _, item := range disabledIDs {
		item = normalizePluginID(item)
		if item == "" {
			continue
		}
		disabled[item] = struct{}{}
	}
	useAllowList := len(enabled) > 0
	out := make([]Scanner, 0, len(r.plugins))
	for _, item := range r.plugins {
		id := normalizePluginID(item.ID)
		if useAllowList {
			if _, ok := enabled[id]; !ok {
				continue
			}
		}
		if _, blocked := disabled[id]; blocked {
			continue
		}
		out = append(out, item.Factory())
	}
	return out
}

func (r *Registry) Metadata() []PluginRegistration {
	if r == nil || len(r.plugins) == 0 {
		return nil
	}
	out := make([]PluginRegistration, 0, len(r.plugins))
	out = append(out, r.plugins...)
	return out
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(PluginRegistration{ID: "skill-audit", Name: "SkillAuditDetector", Description: "Skill 声明与行为一致性检测", Type: PluginTypeDetector, Factory: func() Scanner { return NewSkillAuditDetector() }})
	r.Register(PluginRegistration{ID: "secret", Name: "SecretDetector", Description: "硬编码凭据检测", Type: PluginTypeDetector, Factory: func() Scanner { return NewSecretDetector() }})
	r.Register(PluginRegistration{ID: "dangerous", Name: "DangerousCallDetector", Description: "危险调用检测", Type: PluginTypeDetector, Factory: func() Scanner { return NewDangerousCallDetector() }})
	return r
}

func ExecuteAll(ctx context.Context, scanPath string, registered []Scanner) []Finding {
	if len(registered) == 0 {
		return nil
	}
	out := make([]Finding, 0, 16)
	req := ExecuteRequest{ScanPath: scanPath}
	for _, p := range registered {
		result, err := p.Execute(ctx, req)
		if err != nil {
			continue
		}
		out = append(out, result.Findings...)
	}
	return out
}

func normalizePluginID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
