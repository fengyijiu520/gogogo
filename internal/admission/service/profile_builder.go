package service

import (
	"encoding/json"
	"math"
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
	ReportsDir      string
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
	profile.CapabilityLevels = b.buildCapabilityLevels(behavior, profile)
	profile.CapabilityScopes = buildCapabilityScopes(behavior, profile)
	profile.Tags = admissionmodelNormalizeCapabilities(profile)
	profile.Evidence = collectEvidence(behavior)
	profile.Normalize()
	return profile
}

func buildCapabilityScopes(behavior review.BehaviorProfile, profile *admissionmodel.CapabilityProfile) map[string][]string {
	scopes := map[string][]string{}
	appendScope := func(capability, scope string) {
		capability = strings.TrimSpace(capability)
		scope = strings.TrimSpace(scope)
		if capability == "" || scope == "" {
			return
		}
		scopes[capability] = normalizeStrings(append(scopes[capability], scope))
	}
	for _, target := range append([]string{}, append(behavior.NetworkTargets, behavior.OutboundIOCs...)...) {
		lower := strings.ToLower(strings.TrimSpace(target))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "0.0.0.0") || strings.Contains(lower, "::1") {
			appendScope("network_access", "loopback")
			continue
		}
		if strings.Contains(lower, ".svc") || strings.Contains(lower, "internal") || strings.Contains(lower, "k8s") {
			appendScope("network_access", "internal_api")
			continue
		}
		appendScope("network_access", "internet")
	}
	for _, item := range behavior.C2BeaconIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("network_access", "c2_like")
		}
	}
	for _, item := range behavior.FileTargets {
		lower := strings.ToLower(strings.TrimSpace(item))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "/etc/shadow") || strings.Contains(lower, "/etc/passwd") || strings.Contains(lower, "/root/") {
			appendScope("file_read", "sensitive_system_file")
			continue
		}
		if strings.Contains(lower, ".env") || strings.Contains(lower, "config") || strings.Contains(lower, "credential") || strings.Contains(lower, "token") {
			appendScope("file_read", "config_file")
			continue
		}
		appendScope("file_read", "workspace_file")
	}
	for _, item := range behavior.CredentialIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("file_read", "credential_store")
		}
	}
	for _, item := range behavior.DownloadIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("external_fetch", "internet_payload")
		}
	}
	for _, item := range behavior.ExecTargets {
		lower := strings.ToLower(strings.TrimSpace(item))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "bash") || strings.Contains(lower, "sh ") || strings.Contains(lower, "powershell") || strings.Contains(lower, "cmd.exe") {
			appendScope("command_exec", "shell_exec")
		} else {
			appendScope("command_exec", "program_exec")
		}
	}
	for _, item := range behavior.PersistenceIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("persistence", "autostart")
		}
	}
	if profile != nil {
		if profile.NetworkAccess && len(scopes["network_access"]) == 0 {
			appendScope("network_access", "unspecified")
		}
		if profile.FileRead && len(scopes["file_read"]) == 0 {
			appendScope("file_read", "unspecified")
		}
	}
	return scopes
}

func (b *ProfileBuilder) buildCapabilityLevels(behavior review.BehaviorProfile, profile *admissionmodel.CapabilityProfile) map[string]float64 {
	levels := map[string]float64{}
	compute := func(enabled bool, indicators ...int) float64 {
		if !enabled {
			return 0
		}
		total := 0
		for _, n := range indicators {
			total += n
		}
		score := float64(total) * 0.35
		if score < 0.1 {
			score = 0.1
		}
		if score > 1 {
			score = 1
		}
		return math.Round(score*100) / 100
	}
	levels["network_access"] = compute(profile.NetworkAccess, len(behavior.NetworkTargets), len(behavior.OutboundIOCs), len(behavior.C2BeaconIOCs))
	levels["file_read"] = compute(profile.FileRead, len(behavior.FileTargets), len(behavior.CredentialIOCs), len(behavior.CollectionIOCs))
	levels["file_write"] = compute(profile.FileWrite, len(behavior.DropIOCs), len(behavior.PersistenceIOCs), len(behavior.ExecuteIOCs))
	levels["command_exec"] = compute(profile.CommandExec, len(behavior.ExecTargets), len(behavior.ExecuteIOCs))
	levels["sensitive_data_access"] = compute(profile.SensitiveDataAccess, len(behavior.CredentialIOCs), len(behavior.CollectionIOCs))
	levels["external_fetch"] = compute(profile.ExternalFetch, len(behavior.DownloadIOCs), len(behavior.OutboundIOCs), len(behavior.NetworkTargets))
	levels["data_collection"] = compute(profile.DataCollection, len(behavior.CollectionIOCs))
	levels["persistence"] = compute(profile.Persistence, len(behavior.PersistenceIOCs))
	levels["privilege_use"] = compute(profile.PrivilegeUse, len(behavior.PrivEscIOCs))
	levels["tool_invocation"] = compute(profile.ToolInvocation, len(behavior.ExecTargets), len(behavior.ExecuteIOCs), len(behavior.NetworkTargets))
	return levels
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
		reportsDir := strings.TrimSpace(in.ReportsDir)
		if reportsDir != "" {
			jsonPath = filepath.Join(reportsDir, jsonPath)
		} else {
			reportDir := filepath.Dir(strings.TrimSpace(in.Report.FilePath))
			if reportDir == "." || reportDir == "" {
				return nil
			}
			jsonPath = filepath.Join(reportDir, jsonPath)
		}
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil
	}
	var payload struct {
		Result           review.Result                      `json:"result"`
		ReviewTrace      *review.ReviewTrace                `json:"review_trace"`
		ReviewAgentStats []review.ReviewAgentExecutionStats `json:"review_agent_stats"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	if payload.ReviewTrace != nil {
		payload.Result.ReviewTrace = payload.ReviewTrace
	}
	if len(payload.ReviewAgentStats) > 0 {
		payload.Result.ReviewAgentStats = append([]review.ReviewAgentExecutionStats(nil), payload.ReviewAgentStats...)
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
