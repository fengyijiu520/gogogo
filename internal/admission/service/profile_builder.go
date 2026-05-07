package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	admissionmodel "skill-scanner/internal/admission/model"
	"skill-scanner/internal/models"
	"skill-scanner/internal/review"
)

type ProfileBuildInput struct {
	Report          *models.Report
	ReviewResult    *review.Result
	DescriptionHint string
}

type ProfileBuildOutput struct {
	PurposeSummary string
	Profile        *admissionmodel.CapabilityProfile
	Risks          []admissionmodel.ResidualRisk
	RiskTags       []string
	DeclaredCaps   []string
	DetectedCaps   []string
}

type ProfileBuilder struct{}

func NewProfileBuilder() *ProfileBuilder {
	return &ProfileBuilder{}
}

func (b *ProfileBuilder) Build(in ProfileBuildInput) (*ProfileBuildOutput, error) {
	profile := b.buildCapabilityProfile(in)
	risks := b.buildResidualRisks(in, profile)
	tags := b.buildRiskTags(profile, risks)
	purpose := b.buildPurposeSummary(in, profile)
	declared := inferDeclaredCapabilities(in.DescriptionHint)
	return &ProfileBuildOutput{
		PurposeSummary: purpose,
		Profile:        profile,
		Risks:          risks,
		RiskTags:       tags,
		DeclaredCaps:   declared,
		DetectedCaps:   profile.ToDetectedCapabilities(),
	}, nil
}

func (b *ProfileBuilder) buildPurposeSummary(in ProfileBuildInput, profile *admissionmodel.CapabilityProfile) string {
	if desc := strings.TrimSpace(in.DescriptionHint); desc != "" {
		return desc
	}
	if profile == nil {
		return "基于扫描报告导入的准入技能"
	}
	parts := make([]string, 0, 4)
	if profile.NetworkAccess {
		parts = append(parts, "具备网络访问能力")
	}
	if profile.FileRead || profile.FileWrite {
		parts = append(parts, "涉及文件处理")
	}
	if profile.CommandExec {
		parts = append(parts, "涉及命令执行")
	}
	if len(parts) == 0 {
		return "基于扫描报告导入的准入技能"
	}
	return strings.Join(parts, "，")
}

func (b *ProfileBuilder) buildCapabilityProfile(in ProfileBuildInput) *admissionmodel.CapabilityProfile {
	profile := &admissionmodel.CapabilityProfile{}
	result := b.loadReviewResult(in)
	if result == nil {
		return profile
	}
	behavior := result.Behavior
	profile.NetworkAccess = len(behavior.NetworkTargets) > 0 || len(behavior.OutboundIOCs) > 0 || len(behavior.C2BeaconIOCs) > 0
	profile.FileRead = len(behavior.FileTargets) > 0 || len(behavior.CredentialIOCs) > 0
	profile.FileWrite = len(behavior.DropIOCs) > 0 || len(behavior.PersistenceIOCs) > 0
	profile.CommandExec = len(behavior.ExecTargets) > 0 || len(behavior.ExecuteIOCs) > 0
	profile.SensitiveDataAccess = len(behavior.CredentialIOCs) > 0
	profile.ExternalFetch = len(behavior.DownloadIOCs) > 0 || len(behavior.OutboundIOCs) > 0
	profile.DataCollection = len(behavior.CollectionIOCs) > 0
	profile.Persistence = len(behavior.PersistenceIOCs) > 0
	profile.PrivilegeUse = len(behavior.PrivEscIOCs) > 0
	profile.ToolInvocation = profile.CommandExec
	profile.Tags = admissionmodelNormalizeCapabilities(profile)
	profile.Evidence = collectEvidence(behavior)
	profile.Normalize()
	return profile
}

func (b *ProfileBuilder) buildResidualRisks(in ProfileBuildInput, profile *admissionmodel.CapabilityProfile) []admissionmodel.ResidualRisk {
	result := b.loadReviewResult(in)
	risks := make([]admissionmodel.ResidualRisk, 0)
	addRisk := func(id, category, level, title, desc, mitigation string) {
		risks = append(risks, admissionmodel.ResidualRisk{
			ID:          id,
			Category:    category,
			Level:       level,
			Title:       title,
			Description: desc,
			Mitigation:  mitigation,
		})
	}
	if profile != nil && profile.NetworkAccess {
		addRisk("network-access", "网络访问", "medium", "存在外联能力", "技能具备网络访问或外联能力，后续组合使用时可能参与数据外发链路。", "收敛目标白名单并限制传输字段。")
	}
	if profile != nil && profile.CommandExec {
		addRisk("command-exec", "命令执行", "high", "存在命令执行能力", "技能具备命令执行能力，后续组合使用时可能放大执行风险。", "移除 shell 拼接并限制可执行指令集合。")
	}
	if profile != nil && profile.SensitiveDataAccess {
		addRisk("sensitive-access", "敏感数据访问", "high", "存在敏感数据访问能力", "技能具备凭据或敏感文件访问能力，组合使用时需重点关注外发链路。", "收敛访问范围并隔离凭据读取路径。")
	}
	if result != nil {
		if len(result.Behavior.BehaviorChains) > 0 {
			addRisk("behavior-chain", "行为链", "high", "存在高风险行为链摘要", "扫描报告中已识别下载、执行、外联等高风险行为链信号。", "按链路逐项收敛能力，并复扫确认。")
		}
		if len(result.Behavior.SequenceAlerts) > 0 {
			addRisk("sequence-alert", "时序告警", "medium", "存在高风险时序告警", "扫描报告中识别出高风险行为时序。", "核对触发前提并补充限制条件。")
		}
	}
	return dedupeRisks(risks)
}

func (b *ProfileBuilder) buildRiskTags(profile *admissionmodel.CapabilityProfile, risks []admissionmodel.ResidualRisk) []string {
	tags := make([]string, 0, len(risks)+4)
	if profile != nil {
		if profile.NetworkAccess {
			tags = append(tags, "outbound_network")
		}
		if profile.CommandExec {
			tags = append(tags, "command_execution")
		}
		if profile.SensitiveDataAccess {
			tags = append(tags, "sensitive_access")
		}
	}
	for _, risk := range risks {
		if strings.TrimSpace(risk.Category) != "" {
			tags = append(tags, strings.ToLower(strings.ReplaceAll(risk.Category, " ", "_")))
		}
	}
	return normalizeStrings(tags)
}

func (b *ProfileBuilder) loadReviewResult(in ProfileBuildInput) *review.Result {
	if in.ReviewResult != nil {
		return in.ReviewResult
	}
	if in.Report == nil || strings.TrimSpace(in.Report.JSONPath) == "" {
		return nil
	}
	jsonPath := in.Report.JSONPath
	if !filepath.IsAbs(jsonPath) {
		reportDir := filepath.Dir(strings.TrimSpace(in.Report.FilePath))
		if reportDir == "." || reportDir == "" {
			return nil
		}
		jsonPath = filepath.Join(reportDir, jsonPath)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil
	}
	var payload struct {
		Result review.Result `json:"result"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	return &payload.Result
}

func inferDeclaredCapabilities(desc string) []string {
	return normalizeStrings(capabilitiesFromText(desc))
}

func capabilitiesFromText(desc string) []string {
	lower := strings.ToLower(strings.TrimSpace(desc))
	if lower == "" {
		return nil
	}
	out := make([]string, 0, 6)
	if strings.Contains(lower, "网络") || strings.Contains(lower, "http") || strings.Contains(lower, "api") {
		out = append(out, "network_access")
	}
	if strings.Contains(lower, "文件") || strings.Contains(lower, "上传") || strings.Contains(lower, "解析") {
		out = append(out, "file_read")
	}
	if strings.Contains(lower, "命令") || strings.Contains(lower, "shell") || strings.Contains(lower, "执行") {
		out = append(out, "command_exec")
	}
	return out
}

func collectEvidence(behavior review.BehaviorProfile) []string {
	out := make([]string, 0, 16)
	out = append(out, limitList(behavior.NetworkTargets, 2)...)
	out = append(out, limitList(behavior.OutboundIOCs, 2)...)
	out = append(out, limitList(behavior.FileTargets, 2)...)
	out = append(out, limitList(behavior.CredentialIOCs, 2)...)
	out = append(out, limitList(behavior.ExecTargets, 2)...)
	out = append(out, limitList(behavior.ExecuteIOCs, 2)...)
	out = append(out, limitList(behavior.PersistenceIOCs, 2)...)
	out = append(out, limitList(behavior.BehaviorChains, 2)...)
	out = append(out, limitList(behavior.SequenceAlerts, 2)...)
	return normalizeStrings(out)
}

func admissionmodelNormalizeCapabilities(profile *admissionmodel.CapabilityProfile) []string {
	if profile == nil {
		return nil
	}
	return normalizeStrings(profile.ToDetectedCapabilities())
}

func normalizeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupeRisks(in []admissionmodel.ResidualRisk) []admissionmodel.ResidualRisk {
	seen := map[string]struct{}{}
	out := make([]admissionmodel.ResidualRisk, 0, len(in))
	for _, item := range in {
		item.Normalize()
		key := item.ID + ":" + item.Title
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func limitList(in []string, max int) []string {
	if len(in) == 0 || max <= 0 {
		return nil
	}
	if len(in) <= max {
		return append([]string(nil), in...)
	}
	return append([]string(nil), in[:max]...)
}
