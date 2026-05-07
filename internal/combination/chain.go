package combination

import (
	"strings"

	admissionmodel "skill-scanner/internal/admission/model"
)

type InferredChain struct {
	ID              string
	Title           string
	Level           string
	Summary         string
	Recommendation  string
	Evidence        []string
	AttackPath      []string
	MITRETechniques []string
	SourceSkills    []RiskSourceSkill
}

type chainRule struct {
	ID             string
	Title          string
	Level          string
	Summary        string
	Recommendation string
	Capabilities   []string
	Required       func(*admissionmodel.CapabilityProfile) bool
	Priority       int
	FoldWhen       []string
}

var chainRules = []chainRule{
	{
		ID:             "sensitive-exfiltration",
		Title:          "潜在敏感数据外发链",
		Level:          "high",
		Summary:        "组合中同时出现敏感数据访问与外联能力，存在将敏感内容发送到外部目标的动态链路风险。",
		Recommendation: "建议优先收敛凭据读取范围、外联白名单和可传输字段。",
		Capabilities:   []string{"sensitive_data_access", "network_access"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.NetworkAccess && profile.SensitiveDataAccess
		},
		Priority: 80,
		FoldWhen: []string{"full-attack-chain"},
	},
	{
		ID:             "write-exec-chain",
		Title:          "潜在落地执行链",
		Level:          "high",
		Summary:        "组合中同时出现文件写入与命令执行能力，存在落地文件后触发执行的动态链路风险。",
		Recommendation: "建议限制落地目录、禁用 shell 拼接，并校验可执行入口。",
		Capabilities:   []string{"file_write", "command_exec"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.CommandExec && profile.FileWrite
		},
		Priority: 60,
	},
	{
		ID:             "remote-command-chain",
		Title:          "潜在远程指令执行链",
		Level:          "high",
		Summary:        "组合中同时出现外联与命令执行能力，存在接收远程输入后驱动本地执行的动态链路风险。",
		Recommendation: "建议检查远程输入到执行参数之间的边界，阻断动态命令拼接。",
		Capabilities:   []string{"network_access", "command_exec"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.NetworkAccess && profile.CommandExec
		},
		Priority: 70,
		FoldWhen: []string{"full-attack-chain"},
	},
	{
		ID:             "full-attack-chain",
		Title:          "潜在完整攻击链",
		Level:          "high",
		Summary:        "组合中同时具备敏感访问、外联和执行能力，已形成较完整的高危动态行为链。",
		Recommendation: "建议暂停组合准入，并逐项拆分验证最小权限、最小外联与最小执行面。",
		Capabilities:   []string{"sensitive_data_access", "network_access", "command_exec"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.NetworkAccess && profile.CommandExec && profile.SensitiveDataAccess
		},
		Priority: 100,
	},
}

func inferChains(selected []selectedSignal, profile *admissionmodel.CapabilityProfile) []InferredChain {
	if len(selected) == 0 || profile == nil {
		return nil
	}
	sources := selectedToSources(selected)
	chains := make([]InferredChain, 0, len(chainRules))
	for _, rule := range chainRules {
		if rule.Required != nil && !rule.Required(profile) {
			continue
		}
		evidence := collectChainEvidence(selected, chainEvidenceKeywords(rule.Capabilities...), append([]string(nil), rule.Capabilities...))
		if !hasChainSupport(selected, evidence, rule.Capabilities...) {
			continue
		}
		chains = append(chains, InferredChain{
			ID:              rule.ID,
			Title:           rule.Title,
			Level:           rule.Level,
			Summary:         rule.Summary,
			Recommendation:  rule.Recommendation,
			Evidence:        evidence,
			AttackPath:      buildAttackPath(rule.Capabilities),
			MITRETechniques: buildMITRETechniques(rule.Capabilities),
			SourceSkills:    sources,
		})
	}
	return chains
}

func buildAttackPath(capabilities []string) []string {
	if len(capabilities) == 0 {
		return nil
	}
	path := make([]string, 0, len(capabilities))
	for _, cap := range capabilities {
		switch cap {
		case "sensitive_data_access":
			path = append(path, "Collect sensitive data")
		case "file_write":
			path = append(path, "Drop payload or intermediate file")
		case "network_access":
			path = append(path, "Exfiltrate or receive remote command")
		case "command_exec":
			path = append(path, "Execute local command")
		default:
			path = append(path, cap)
		}
	}
	return path
}

func buildMITRETechniques(capabilities []string) []string {
	if len(capabilities) == 0 {
		return nil
	}
	out := make([]string, 0, 4)
	for _, cap := range capabilities {
		switch cap {
		case "sensitive_data_access":
			out = append(out, "TA0009 Collection", "T1005 Data from Local System")
		case "file_write":
			out = append(out, "TA0003 Persistence", "T1105 Ingress Tool Transfer")
		case "network_access":
			out = append(out, "TA0011 Command and Control", "T1071 Application Layer Protocol")
		case "command_exec":
			out = append(out, "TA0002 Execution", "T1059 Command and Scripting Interpreter")
		}
	}
	return normalizeStrings(out)
}

func prioritizeInferredChains(chains []InferredChain) []InferredChain {
	if len(chains) <= 1 {
		return chains
	}
	priority := chainPriorityMap()
	kept := make([]InferredChain, 0, len(chains))
	seen := map[string]bool{}
	present := make(map[string]bool, len(chains))
	for _, item := range chains {
		present[item.ID] = true
	}
	for _, item := range chains {
		if seen[item.ID] {
			continue
		}
		if shouldFoldChain(item.ID, present) {
			continue
		}
		seen[item.ID] = true
		kept = append(kept, item)
	}
	for i := 0; i < len(kept); i++ {
		for j := i + 1; j < len(kept); j++ {
			left := priority[kept[i].ID]
			right := priority[kept[j].ID]
			if right > left {
				kept[i], kept[j] = kept[j], kept[i]
			}
		}
	}
	return kept
}

func chainPriorityMap() map[string]int {
	out := make(map[string]int, len(chainRules))
	for _, rule := range chainRules {
		out[rule.ID] = rule.Priority
	}
	return out
}

func shouldFoldChain(chainID string, present map[string]bool) bool {
	for _, rule := range chainRules {
		if rule.ID != chainID {
			continue
		}
		for _, parent := range rule.FoldWhen {
			if present[parent] {
				return true
			}
		}
		return false
	}
	return false
}

func buildConclusion(selected []SkillOption, profile *admissionmodel.CapabilityProfile, risks []CombinedRisk, chains []InferredChain) Conclusion {
	conclusion := Conclusion{
		RiskLevel:          "low",
		RiskLabel:          "低风险",
		Recommendation:     "可继续保持人工复核，并关注后续能力变更。",
		SelectedSkillCount: len(selected),
	}
	if profile != nil {
		conclusion.CapabilityCount = len(profile.ToDetectedCapabilities())
		if profile.NetworkAccess {
			conclusion.SensitiveSignalCount++
		}
		if profile.CommandExec {
			conclusion.SensitiveSignalCount++
		}
		if profile.SensitiveDataAccess {
			conclusion.SensitiveSignalCount++
		}
		if profile.PrivilegeUse {
			conclusion.SensitiveSignalCount++
		}
	}
	for _, item := range risks {
		switch strings.ToLower(strings.TrimSpace(item.Risk.Level)) {
		case "high":
			conclusion.HighRiskCount++
		case "medium":
			conclusion.MediumRiskCount++
		case "low":
			conclusion.LowRiskCount++
		}
	}
	for _, item := range chains {
		if isHighConfidenceChain(item) {
			conclusion.HighConfidenceChains++
		}
	}
	switch {
	case conclusion.HighRiskCount > 0 || conclusion.HighConfidenceChains > 0:
		conclusion.RiskLevel = "high"
		conclusion.RiskLabel = "高风险"
		conclusion.Recommendation = "建议暂停组合准入，优先收敛命令执行、敏感访问或外联链路后再复核。"
	case conclusion.MediumRiskCount > 0 || conclusion.SensitiveSignalCount >= 3 || (conclusion.SensitiveSignalCount >= 2 && len(chains) > 0):
		conclusion.RiskLevel = "medium"
		conclusion.RiskLabel = "中风险"
		conclusion.Recommendation = "建议补充组合场景限制条件，并对白名单、输入边界和数据流向做二次确认。"
	}
	if conclusion.SelectedSkillCount == 0 {
		conclusion.RiskLevel = "low"
		conclusion.RiskLabel = "待分析"
		conclusion.Recommendation = "请选择两个或以上技能查看组合风险结论。"
	}
	return conclusion
}

func isHighConfidenceChain(chain InferredChain) bool {
	if strings.ToLower(strings.TrimSpace(chain.Level)) != "high" {
		return false
	}
	if len(chain.SourceSkills) < 2 {
		return false
	}
	if len(chain.Evidence) < 2 {
		return false
	}
	return true
}

func hasChainSupport(selected []selectedSignal, evidence []string, capabilities ...string) bool {
	if len(selected) < 2 || len(evidence) == 0 || len(capabilities) < 2 {
		return false
	}
	coveredCaps := 0
	for _, capability := range capabilities {
		if capabilitySupportedByDistinctSkill(selected, capability) {
			coveredCaps++
		}
	}
	if coveredCaps < 2 {
		return false
	}
	if countEvidenceBackedSkills(selected, evidence) >= 2 {
		return true
	}
	for _, item := range selected {
		if item.Profile == nil {
			continue
		}
		if profileCapabilityCoverage(item.Profile, capabilities...) >= 2 && profileEvidenceCoverage(item.Profile, evidence) >= 2 {
			return true
		}
	}
	return false
}

func capabilitySupportedByDistinctSkill(selected []selectedSignal, capability string) bool {
	for _, item := range selected {
		if item.Profile != nil && profileHasCapability(item.Profile, capability) {
			return true
		}
	}
	return false
}

func countEvidenceBackedSkills(selected []selectedSignal, evidence []string) int {
	count := 0
	for _, item := range selected {
		if item.Profile == nil || len(item.Profile.Evidence) == 0 {
			continue
		}
		if profileContainsAnyEvidence(item.Profile, evidence) {
			count++
		}
	}
	return count
}

func profileContainsAnyEvidence(profile *admissionmodel.CapabilityProfile, evidence []string) bool {
	return profileEvidenceCoverage(profile, evidence) > 0
}

func profileEvidenceCoverage(profile *admissionmodel.CapabilityProfile, evidence []string) int {
	if profile == nil {
		return 0
	}
	count := 0
	for _, profileEvidence := range profile.Evidence {
		candidate := strings.TrimSpace(profileEvidence)
		if candidate == "" {
			continue
		}
		for _, item := range evidence {
			if candidate == strings.TrimSpace(item) {
				count++
				break
			}
		}
	}
	return count
}

func profileCapabilityCoverage(profile *admissionmodel.CapabilityProfile, capabilities ...string) int {
	count := 0
	for _, capability := range capabilities {
		if profileHasCapability(profile, capability) {
			count++
		}
	}
	return count
}

func profileHasCapability(profile *admissionmodel.CapabilityProfile, capability string) bool {
	if profile == nil {
		return false
	}
	switch capability {
	case "network_access":
		return profile.NetworkAccess
	case "command_exec":
		return profile.CommandExec
	case "sensitive_data_access":
		return profile.SensitiveDataAccess
	case "file_write":
		return profile.FileWrite
	default:
		return false
	}
}

func chainEvidenceKeywords(capabilities ...string) []string {
	out := make([]string, 0, len(capabilities)*3)
	for _, capability := range capabilities {
		switch capability {
		case "network_access":
			out = append(out, "http", "https://", "outbound", "api")
		case "command_exec":
			out = append(out, "exec", "command", "shell")
		case "sensitive_data_access":
			out = append(out, "/root/.netrc", "credential", "token", "secret")
		case "file_write":
			out = append(out, "drop", "write", "file")
		}
	}
	return normalizeStrings(out)
}
