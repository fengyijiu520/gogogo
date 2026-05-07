package plugins

import "context"

import "strings"

type PluginFactory func() Plugin

type PluginRegistration struct {
	ID          string
	Version     string
	Description string
	Factory     PluginFactory
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
	for _, existing := range r.plugins {
		if existing.ID == item.ID {
			return
		}
	}
	r.plugins = append(r.plugins, item)
}

func (r *Registry) Build() []Plugin {
	return r.BuildWithFilter(nil, nil)
}

func (r *Registry) BuildWithFilter(enabledIDs, disabledIDs []string) []Plugin {
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
	out := make([]Plugin, 0, len(r.plugins))
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
	r.Register(PluginRegistration{ID: "skill-audit", Version: "1.0.0", Description: "Skill 声明与行为一致性检测", Factory: func() Plugin { return NewSkillAuditDetector() }})
	r.Register(PluginRegistration{ID: "secret", Version: "1.0.0", Description: "硬编码凭据检测", Factory: func() Plugin { return NewSecretDetector() }})
	r.Register(PluginRegistration{ID: "dangerous", Version: "1.0.0", Description: "危险调用检测", Factory: func() Plugin { return NewDangerousCallDetector() }})
	return r
}

func ExecuteAll(ctx context.Context, scanPath string, registered []Plugin) []Finding {
	if len(registered) == 0 {
		return nil
	}
	out := make([]Finding, 0, 16)
	for _, p := range registered {
		items, err := p.Execute(ctx, scanPath)
		if err != nil {
			continue
		}
		out = append(out, items...)
	}
	return out
}

func normalizePluginID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
