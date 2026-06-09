package report

import (
	"fmt"
	"strings"

	"skill-scanner/internal/review"
)

func StructuredFindingSourceLabels(finding review.StructuredFinding, finalReview string, reviewDepth int) []string {
	labels := make([]string, 0, 8)
	source := strings.ToLower(strings.TrimSpace(finding.Source))
	basisText := strings.ToLower(strings.Join(finding.CalibrationBasis, " "))
	if source == "" || strings.Contains(source, "static") || strings.Contains(source, "securityengine") || strings.Contains(source, "rule") || strings.Contains(source, "coverage") {
		labels = append(labels, "规则静态")
	}
	if strings.Contains(source, "intent") || strings.Contains(source, "semantic") || strings.Contains(basisText, "声明与实际行为差异") {
		labels = append(labels, "语义静态")
	}
	if strings.Contains(source, "intent") || strings.Contains(source, "llm") || strings.Contains(basisText, "llm") {
		labels = append(labels, "LLM静态")
	}
	if hasSandboxDynamicEvidenceForFinding(finding) {
		labels = append(labels, "沙箱动态")
	}
	if strings.Contains(source, "threatintel") || strings.Contains(basisText, "信誉信息") || strings.Contains(basisText, "外联目标") {
		labels = append(labels, "情报关联")
	}
	if len(labels) == 0 {
		labels = append(labels, "规则静态")
	}
	labels = append(labels, reviewStatusLabels(finalReview, reviewDepth)...)
	return uniqueNonEmptyStrings(labels)
}

func CapabilitySourceLabels(item review.CapabilityConsistency, finalReview string, reviewDepth int) []string {
	labels := make([]string, 0, 8)
	if item.StaticDetected {
		labels = append(labels, "规则静态")
	}
	if item.Declared {
		labels = append(labels, "语义静态")
	}
	if item.LLMDetected {
		labels = append(labels, "LLM静态")
	}
	if item.SandboxDetected {
		labels = append(labels, "沙箱动态")
	}
	if item.TIObserved {
		labels = append(labels, "情报关联")
	}
	labels = append(labels, reviewStatusLabels(finalReview, reviewDepth)...)
	if len(labels) == 0 {
		labels = append(labels, "待验证")
	}
	return uniqueNonEmptyStrings(labels)
}

func ReviewVerdictCountByFinding(items []review.ReviewAgentVerdict) map[string]int {
	out := make(map[string]int, len(items))
	for _, item := range items {
		out[item.FindingID]++
	}
	return out
}

func SeverityClassSuffix(severity string) string {
	switch strings.TrimSpace(severity) {
	case "高风险":
		return "high"
	case "中风险":
		return "medium"
	default:
		return "low"
	}
}

func RuleExplanationByID(items []review.RuleExplanation) map[string]review.RuleExplanation {
	out := make(map[string]review.RuleExplanation, len(items))
	for _, item := range items {
		out[item.RuleID] = item
	}
	return out
}

func FalsePositiveReviewByID(items []review.FalsePositiveReview) map[string]review.FalsePositiveReview {
	out := make(map[string]review.FalsePositiveReview, len(items))
	for _, item := range items {
		out[item.FindingID] = item
	}
	return out
}

func CapabilityItemsForFinding(finding review.StructuredFinding, items []review.CapabilityConsistency) []review.CapabilityConsistency {
	out := make([]review.CapabilityConsistency, 0, len(items))
	for _, item := range items {
		if CapabilityMatchesFinding(item.Capability, finding) {
			out = append(out, item)
		}
	}
	return out
}

func CapabilityEvidenceForFinding(finding review.StructuredFinding, matrix []review.CapabilityConsistency, inventory []review.EvidenceInventory, behavior review.BehaviorProfile) []string {
	lines := make([]string, 0)
	seen := make(map[string]struct{})
	capabilities := CapabilityItemsForFinding(finding, matrix)
	hasEvidenceLine := false
	for _, line := range findingScopedEvidenceLines(finding) {
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
		hasEvidenceLine = true
	}
	for _, item := range capabilities {
		for _, line := range capabilityInventorySummaryForFinding(item.Capability, finding, inventory, behavior) {
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			lines = append(lines, line)
			if strings.HasPrefix(strings.TrimSpace(line), "证据:") {
				hasEvidenceLine = true
			}
		}
	}
	if !hasEvidenceLine {
		for _, item := range capabilities {
			for _, evidence := range item.Evidence {
				evidence = strings.TrimSpace(evidence)
				if evidence == "" || !capabilityEvidenceMatchesFinding(evidence, finding) {
					continue
				}
				line := "能力证据: " + evidence
				if _, ok := seen[line]; ok {
					continue
				}
				seen[line] = struct{}{}
				lines = append(lines, line)
				hasEvidenceLine = true
			}
		}
	}
	return lines
}

func CapabilityPrimaryEvidenceForFinding(finding review.StructuredFinding, item review.CapabilityConsistency, inventory []review.EvidenceInventory, behavior review.BehaviorProfile) string {
	for _, evidence := range item.Evidence {
		evidence = strings.TrimSpace(evidence)
		if evidence != "" && capabilityEvidenceMatchesFinding(evidence, finding) {
			return evidence
		}
	}
	for _, line := range capabilityInventorySummaryForFinding(item.Capability, finding, inventory, behavior) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "能力证据: ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "能力证据: "))
		}
		if strings.HasPrefix(trimmed, "证据: ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "证据: "))
		}
		if strings.HasPrefix(trimmed, "链路: ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "链路: "))
		}
	}
	for _, line := range findingScopedEvidenceLines(finding) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "证据: ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "证据: "))
		}
		if strings.HasPrefix(trimmed, "链路: ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "链路: "))
		}
	}
	return ""
}

func hasSandboxDynamicEvidenceForFinding(finding review.StructuredFinding) bool {
	joined := strings.ToLower(strings.Join(append(append([]string{finding.Source, finding.AttackPath}, finding.Evidence...), finding.CalibrationBasis...), " "))
	if strings.Contains(joined, "[sandbox]") || strings.Contains(joined, "隔离容器探针") || strings.Contains(joined, "沙箱已记录") || strings.Contains(joined, "差分执行") {
		return true
	}
	source := strings.ToLower(strings.TrimSpace(finding.Source))
	if strings.Contains(source, "behaviorguard") || strings.Contains(source, "sandbox") || strings.Contains(source, "runtime") {
		return true
	}
	for _, item := range finding.Evidence {
		lower := strings.ToLower(strings.TrimSpace(item))
		if strings.Contains(lower, "[sandbox]") || strings.Contains(lower, "sandbox") || strings.Contains(lower, "runtime") {
			return true
		}
	}
	return false
}

func reviewStatusLabels(finalReview string, reviewDepth int) []string {
	text := strings.ToLower(strings.TrimSpace(finalReview))
	if text == "" {
		return []string{"待验证"}
	}
	labels := make([]string, 0, 2)
	if strings.Contains(text, "confirmed") || strings.Contains(text, "已确认") || strings.Contains(text, "确认风险") {
		labels = append(labels, "已验证")
	} else if strings.Contains(text, "false") || strings.Contains(text, "误报") {
		labels = append(labels, "复核疑似误报")
	} else {
		labels = append(labels, "待验证")
	}
	if strings.Contains(text, "manual") || strings.Contains(text, "人工") || strings.Contains(text, "复核") {
		labels = append(labels, "需人工复核")
	}
	if reviewDepth > 1 {
		labels = append(labels, "二次验证")
	}
	return uniqueNonEmptyStrings(labels)
}

func buildCapabilityEvidenceDebugLine(capabilities []string, inventory []review.EvidenceInventory, behavior review.BehaviorProfile, finding review.StructuredFinding) string {
	invCount := 0
	invExamples := 0
	for _, item := range inventory {
		for _, capability := range capabilities {
			if !InventoryMatchesCapability(capability, item.Category) {
				continue
			}
			invCount += item.Count
			invExamples += len(item.Examples)
			break
		}
	}
	behaviorCount := 0
	for _, capability := range capabilities {
		behaviorCount += behaviorEvidenceCountForCapability(capability, behavior)
	}
	return fmt.Sprintf("能力=%s；行为证据条数=%d；目录计数=%d；目录示例条数=%d；关键证据条数=%d", strings.Join(capabilities, ","), behaviorCount, invCount, invExamples, len(finding.Evidence))
}

func behaviorEvidenceCountForCapability(capability string, behavior review.BehaviorProfile) int {
	capability = strings.ToLower(strings.TrimSpace(capability))
	switch {
	case strings.Contains(capability, "外联"):
		return len(behavior.OutboundIOCs)
	case strings.Contains(capability, "命令执行"):
		return len(behavior.ExecuteIOCs)
	case strings.Contains(capability, "文件读写"):
		return len(behavior.DownloadIOCs) + len(behavior.DropIOCs)
	case strings.Contains(capability, "凭据访问"):
		return len(behavior.CredentialIOCs)
	case strings.Contains(capability, "持久化"):
		return len(behavior.PersistenceIOCs)
	case strings.Contains(capability, "提权") || strings.Contains(capability, "逃逸"):
		return len(behavior.PrivEscIOCs) + len(behavior.DefenseEvasionIOCs)
	case strings.Contains(capability, "数据收集"):
		return len(behavior.CollectionIOCs)
	default:
		return 0
	}
}

func CapabilityMatchesFinding(capability string, finding review.StructuredFinding) bool {
	return InventoryMatchesCapability(capability, finding.Category)
}

func capabilityInventorySummary(capability string, items []review.EvidenceInventory, behavior review.BehaviorProfile) []string {
	matched := make([]string, 0, 6)
	seen := make(map[string]struct{})
	add := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		if _, ok := seen[line]; ok {
			return
		}
		seen[line] = struct{}{}
		matched = append(matched, line)
	}
	for _, item := range items {
		if !InventoryMatchesCapability(capability, item.Category) {
			continue
		}
		add(fmt.Sprintf("%s: %d 条", item.Category, item.Count))
		if strings.TrimSpace(item.Meaning) != "" {
			add("意义: " + item.Meaning)
		}
		for _, evidence := range inventoryEvidenceByCategory(item.Category, behavior, item.Examples) {
			add("证据: " + evidence)
		}
	}
	return matched
}

func capabilityInventorySummaryForFinding(capability string, finding review.StructuredFinding, items []review.EvidenceInventory, behavior review.BehaviorProfile) []string {
	matched := make([]string, 0, 8)
	seen := make(map[string]struct{})
	add := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		if _, ok := seen[line]; ok {
			return
		}
		seen[line] = struct{}{}
		matched = append(matched, line)
	}
	for _, item := range items {
		if !InventoryMatchesCapability(capability, item.Category) {
			continue
		}
		relevantEvidence := make([]string, 0, len(item.Examples))
		for _, evidence := range inventoryEvidenceByCategory(item.Category, behavior, item.Examples) {
			if capabilityEvidenceMatchesFinding(evidence, finding) {
				relevantEvidence = append(relevantEvidence, evidence)
			}
		}
		if len(relevantEvidence) == 0 {
			continue
		}
		add(fmt.Sprintf("%s: %d 条", item.Category, len(relevantEvidence)))
		if strings.TrimSpace(item.Meaning) != "" {
			add("意义: " + item.Meaning)
		}
		for _, evidence := range relevantEvidence {
			add("证据: " + evidence)
		}
	}
	return matched
}

func findingScopedEvidenceLines(finding review.StructuredFinding) []string {
	lines := make([]string, 0, len(finding.Evidence)+len(finding.ChainSummaries))
	for _, evidence := range finding.Evidence {
		evidence = strings.TrimSpace(evidence)
		if evidence != "" {
			lines = append(lines, "证据: "+evidence)
		}
	}
	for _, chain := range finding.ChainSummaries {
		chain = strings.TrimSpace(chain)
		if chain != "" {
			lines = append(lines, "链路: "+chain)
		}
	}
	return lines
}

func capabilityEvidenceMatchesFinding(evidence string, finding review.StructuredFinding) bool {
	evidenceText := strings.ToLower(strings.TrimSpace(evidence))
	if evidenceText == "" {
		return false
	}
	findingText := strings.ToLower(strings.Join(append(append([]string{finding.RuleID, finding.Title, finding.Category, finding.AttackPath}, finding.Evidence...), finding.ChainSummaries...), " "))
	if strings.TrimSpace(finding.RuleID) != "" && strings.Contains(evidenceText, strings.ToLower(strings.TrimSpace(finding.RuleID))) {
		return true
	}
	if strings.TrimSpace(finding.Title) != "" && strings.Contains(evidenceText, strings.ToLower(strings.TrimSpace(finding.Title))) {
		return true
	}
	for _, path := range findingSourcePaths(finding) {
		if strings.Contains(evidenceText, path) {
			return true
		}
	}
	for _, item := range append(append([]string{}, finding.Evidence...), finding.ChainSummaries...) {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if strings.Contains(evidenceText, item) || strings.Contains(item, evidenceText) {
			return true
		}
	}
	return strings.Contains(findingText, evidenceText)
}

func findingSourcePaths(finding review.StructuredFinding) []string {
	paths := make([]string, 0, len(finding.Chains)+len(finding.Evidence)+1)
	seen := make(map[string]struct{})
	add := func(path string) {
		path = strings.ToLower(strings.TrimSpace(path))
		if path == "" {
			return
		}
		if idx := strings.Index(path, ":"); idx > 0 {
			path = path[:idx]
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for _, chain := range finding.Chains {
		add(chain.Path)
		add(chain.Source)
	}
	for _, evidence := range finding.Evidence {
		add(evidence)
	}
	add(finding.AttackPath)
	return paths
}

func inventoryEvidenceByCategory(category string, behavior review.BehaviorProfile, fallback []string) []string {
	clean := func(items []string) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	}
	prefer := func(primary []string) []string {
		if len(primary) > 0 {
			return primary
		}
		return clean(fallback)
	}
	switch {
	case strings.Contains(category, "外联"):
		return prefer(clean(behavior.OutboundIOCs))
	case strings.Contains(category, "下载"):
		return prefer(clean(behavior.DownloadIOCs))
	case strings.Contains(category, "落地"):
		return prefer(clean(behavior.DropIOCs))
	case strings.Contains(category, "执行"):
		return prefer(clean(behavior.ExecuteIOCs))
	case strings.Contains(category, "持久"):
		return prefer(clean(behavior.PersistenceIOCs))
	case strings.Contains(category, "提权"):
		return prefer(clean(behavior.PrivEscIOCs))
	case strings.Contains(category, "凭据"):
		return prefer(clean(behavior.CredentialIOCs))
	case strings.Contains(category, "防御规避"):
		return prefer(clean(behavior.DefenseEvasionIOCs))
	case strings.Contains(category, "横向"):
		return prefer(clean(behavior.LateralMoveIOCs))
	case strings.Contains(category, "收集"):
		return prefer(clean(behavior.CollectionIOCs))
	case strings.Contains(category, "信标"):
		return prefer(clean(behavior.C2BeaconIOCs))
	case strings.Contains(category, "时序"):
		return prefer(clean(behavior.BehaviorTimelines))
	default:
		return clean(fallback)
	}
}

func InventoryMatchesCapability(capability, category string) bool {
	capability = strings.ToLower(strings.TrimSpace(capability))
	category = strings.ToLower(strings.TrimSpace(category))
	switch {
	case strings.Contains(capability, "外联"):
		return strings.Contains(category, "外联") || strings.Contains(category, "网络") || strings.Contains(category, "情报")
	case strings.Contains(capability, "命令执行"):
		return strings.Contains(category, "执行") || strings.Contains(category, "命令")
	case strings.Contains(capability, "文件读写"):
		return strings.Contains(category, "文件") || strings.Contains(category, "落地") || strings.Contains(category, "下载")
	case strings.Contains(capability, "凭据访问"):
		return strings.Contains(category, "凭据")
	case strings.Contains(capability, "持久化"):
		return strings.Contains(category, "持久化")
	case strings.Contains(capability, "提权") || strings.Contains(capability, "逃逸"):
		return strings.Contains(category, "提权") || strings.Contains(category, "逃逸") || strings.Contains(category, "规避")
	case strings.Contains(capability, "数据收集"):
		return strings.Contains(category, "收集") || strings.Contains(category, "打包")
	default:
		return false
	}
}

func uniqueNonEmptyStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
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
	return out
}

func UniqueNonEmptyStrings(items []string) []string {
	return uniqueNonEmptyStrings(items)
}
