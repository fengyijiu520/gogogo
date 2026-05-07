package plugins

import "testing"

func TestBuildWithFilterAllowAndDeny(t *testing.T) {
	r := NewRegistry()
	r.Register(PluginRegistration{ID: "skill-audit", Factory: func() Plugin { return NewSkillAuditDetector() }})
	r.Register(PluginRegistration{ID: "secret", Factory: func() Plugin { return NewSecretDetector() }})
	r.Register(PluginRegistration{ID: "dangerous", Factory: func() Plugin { return NewDangerousCallDetector() }})

	all := r.BuildWithFilter(nil, nil)
	if len(all) != 3 {
		t.Fatalf("expected all plugins when no filter is set, got %d", len(all))
	}

	enabledOnly := r.BuildWithFilter([]string{"secret", "dangerous"}, nil)
	if len(enabledOnly) != 2 {
		t.Fatalf("expected 2 plugins in allow list, got %d", len(enabledOnly))
	}

	withDeny := r.BuildWithFilter([]string{"secret", "dangerous"}, []string{"dangerous"})
	if len(withDeny) != 1 {
		t.Fatalf("expected deny list to remove dangerous plugin, got %d", len(withDeny))
	}
}
