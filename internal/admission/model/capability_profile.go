package model

import "strings"

type CapabilityProfile struct {
	SkillID             string   `json:"skill_id"`
	NetworkAccess       bool     `json:"network_access"`
	FileRead            bool     `json:"file_read"`
	FileWrite           bool     `json:"file_write"`
	CommandExec         bool     `json:"command_exec"`
	SensitiveDataAccess bool     `json:"sensitive_data_access"`
	ExternalFetch       bool     `json:"external_fetch"`
	DataCollection      bool     `json:"data_collection"`
	Persistence         bool     `json:"persistence"`
	PrivilegeUse        bool     `json:"privilege_use"`
	ToolInvocation      bool     `json:"tool_invocation"`
	Tags                []string `json:"tags"`
	Evidence            []string `json:"evidence"`
}

func (p *CapabilityProfile) Normalize() {
	if p == nil {
		return
	}
	p.SkillID = strings.TrimSpace(p.SkillID)
	p.Tags = normalizeStringSlice(p.Tags)
	p.Evidence = normalizeStringSlice(p.Evidence)
}

func (p *CapabilityProfile) Validate() error {
	return nil
}

func (p *CapabilityProfile) ToDetectedCapabilities() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, 10)
	appendIf := func(enabled bool, value string) {
		if enabled {
			out = append(out, value)
		}
	}
	appendIf(p.NetworkAccess, "network_access")
	appendIf(p.FileRead, "file_read")
	appendIf(p.FileWrite, "file_write")
	appendIf(p.CommandExec, "command_exec")
	appendIf(p.SensitiveDataAccess, "sensitive_data_access")
	appendIf(p.ExternalFetch, "external_fetch")
	appendIf(p.DataCollection, "data_collection")
	appendIf(p.Persistence, "persistence")
	appendIf(p.PrivilegeUse, "privilege_use")
	appendIf(p.ToolInvocation, "tool_invocation")
	return out
}
