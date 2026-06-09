package combination

import (
	"fmt"
	"sort"
	"strings"

	admissionmodel "skill-scanner/internal/admission/model"
	"skill-scanner/internal/config"
)

func inferSemanticChains(selected []selectedSignal, profile *admissionmodel.CapabilityProfile, known []InferredChain) []InferredChain {
	minSkills := config.SemanticChainMinSkills()
	minPhases := config.SemanticChainMinPhases()
	minEvidence := config.SemanticChainMinEvidence()
	if len(selected) < minSkills || profile == nil {
		return nil
	}
	phaseSkills := map[string]map[string]struct{}{}
	phaseEvidence := map[string][]string{}
	for _, item := range selected {
		if item.Profile == nil {
			continue
		}
		skillID := strings.TrimSpace(item.Option.SkillID)
		if skillID == "" {
			continue
		}
		phases := inferEvidencePhases(item.Profile)
		for phase, examples := range phases {
			if phaseSkills[phase] == nil {
				phaseSkills[phase] = map[string]struct{}{}
			}
			phaseSkills[phase][skillID] = struct{}{}
			phaseEvidence[phase] = append(phaseEvidence[phase], examples...)
		}
	}
	for phase, items := range phaseEvidence {
		phaseEvidence[phase] = normalizeStrings(items)
	}

	if len(phaseSkills) < minPhases {
		return nil
	}
	skillUniverse := map[string]struct{}{}
	for _, owners := range phaseSkills {
		for skillID := range owners {
			skillUniverse[skillID] = struct{}{}
		}
	}
	if len(skillUniverse) < minSkills {
		return nil
	}

	out := make([]InferredChain, 0, 2)
	knownIndex := map[string]struct{}{}
	for _, item := range known {
		knownIndex[item.ID] = struct{}{}
	}

	if _, exists := knownIndex["adaptive-multi-skill-chain"]; !exists {
		if hasPhase(phaseSkills, "collect") && hasPhase(phaseSkills, "stage") && (hasPhase(phaseSkills, "exfil") || hasPhase(phaseSkills, "execute")) {
			candidate := buildAdaptiveMultiSkillChain(selected, phaseSkills, phaseEvidence)
			if len(candidate.Evidence) >= minEvidence {
				out = append(out, candidate)
			}
		}
	}

	if _, exists := knownIndex["semantic-context-chain"]; !exists {
		if profile.HasCapabilityScope("file_read", "sensitive_system_file") && profile.HasCapabilityScope("network_access", "internet") && profileHasCapability(profile, "command_exec") {
			candidate := buildSemanticContextChain(selected, phaseEvidence)
			if len(candidate.Evidence) >= minEvidence {
				out = append(out, candidate)
			}
		}
	}
	return out
}

func inferEvidencePhases(profile *admissionmodel.CapabilityProfile) map[string][]string {
	out := map[string][]string{}
	for _, raw := range profile.Evidence {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "collect") || strings.Contains(lower, "harvest") || strings.Contains(lower, "credential") || strings.Contains(lower, "/etc/"):
			out["collect"] = append(out["collect"], line)
		case strings.Contains(lower, "write") || strings.Contains(lower, "drop") || strings.Contains(lower, "payload") || strings.Contains(lower, "tmp"):
			out["stage"] = append(out["stage"], line)
		case strings.Contains(lower, "http") || strings.Contains(lower, "upload") || strings.Contains(lower, "post") || strings.Contains(lower, "outbound"):
			out["exfil"] = append(out["exfil"], line)
		case strings.Contains(lower, "exec") || strings.Contains(lower, "shell") || strings.Contains(lower, "subprocess"):
			out["execute"] = append(out["execute"], line)
		case strings.Contains(lower, "cron") || strings.Contains(lower, "startup") || strings.Contains(lower, "autorun"):
			out["persist"] = append(out["persist"], line)
		case strings.Contains(lower, "obfus") || strings.Contains(lower, "base64") || strings.Contains(lower, "decode"):
			out["evasion"] = append(out["evasion"], line)
		}
	}
	for phase, items := range out {
		out[phase] = normalizeStrings(items)
	}
	return out
}

func hasPhase(phaseSkills map[string]map[string]struct{}, phase string) bool {
	owners, ok := phaseSkills[phase]
	return ok && len(owners) > 0
}

func buildAdaptiveMultiSkillChain(selected []selectedSignal, phaseSkills map[string]map[string]struct{}, phaseEvidence map[string][]string) InferredChain {
	evidence := make([]string, 0, 8)
	for _, phase := range []string{"collect", "stage", "exfil", "execute", "persist"} {
		for _, item := range phaseEvidence[phase] {
			evidence = append(evidence, fmt.Sprintf("[%s] %s", phase, item))
			if len(evidence) >= 8 {
				break
			}
		}
		if len(evidence) >= 8 {
			break
		}
	}
	if len(evidence) == 0 {
		evidence = []string{"语义推理发现多阶段能力组合（采集/落地/外发或执行）"}
	}
	return InferredChain{
		ID:             "adaptive-multi-skill-chain",
		Title:          "语义推理发现多技能自适应利用链",
		Level:          "high",
		Summary:        "规则库外识别到跨 3 个以上技能的多阶段能力拼接（采集→落地→外发/执行），属于未知组合模式。",
		Recommendation: "建议按调用图拆分技能职责，阻断跨技能参数传递并增加上下文白名单约束。",
		Evidence:       normalizeStrings(evidence),
		AttackPath:     []string{"Collect contextual data", "Stage intermediate payload", "Exfiltrate or execute through chained context"},
		MITRETechniques: []string{
			"TA0009 Collection",
			"TA0002 Execution",
			"TA0011 Command and Control",
		},
		SourceSkills: selectedToSources(selected),
	}
}

func buildSemanticContextChain(selected []selectedSignal, phaseEvidence map[string][]string) InferredChain {
	evidence := normalizeStrings(append([]string{}, append(phaseEvidence["collect"], phaseEvidence["exfil"]...)...))
	if len(evidence) > 6 {
		evidence = evidence[:6]
	}
	if len(evidence) == 0 {
		evidence = []string{"能力 scope 命中：sensitive_system_file + internet + command_exec"}
	}
	return InferredChain{
		ID:             "semantic-context-chain",
		Title:          "语义上下文高危联动链",
		Level:          "high",
		Summary:        "发现敏感系统读取、互联网外联和执行能力的上下文级联动，可能绕过既有固定规则。",
		Recommendation: "建议收敛高敏文件读取范围，禁止外联携带高敏上下文，并移除动态执行桥接。",
		Evidence:       evidence,
		AttackPath:     []string{"Read sensitive system context", "Bridge into outbound channel", "Trigger execution with contextual payload"},
		MITRETechniques: []string{
			"TA0009 Collection",
			"TA0011 Command and Control",
			"TA0002 Execution",
		},
		SourceSkills: selectedToSources(selected),
	}
}

func mergeAndSortChains(base, extra []InferredChain) []InferredChain {
	if len(extra) == 0 {
		return base
	}
	seen := map[string]struct{}{}
	out := make([]InferredChain, 0, len(base)+len(extra))
	for _, item := range base {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		seen[item.ID] = struct{}{}
		out = append(out, item)
	}
	for _, item := range extra {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		if _, ok := seen[item.ID]; ok {
			continue
		}
		seen[item.ID] = struct{}{}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(out[i].Level))
		right := strings.ToLower(strings.TrimSpace(out[j].Level))
		if left == right {
			return out[i].ID < out[j].ID
		}
		return left == "high"
	})
	return out
}
