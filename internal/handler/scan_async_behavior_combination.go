package handler

import (
	"fmt"
	"html"
	"path/filepath"
	"strconv"
	"strings"

	combinationservice "skill-scanner/internal/combination"
	"skill-scanner/internal/config"
	"skill-scanner/internal/review"
)

func buildSingleSkillBehaviorCombination(refined review.Result) combinationservice.SingleSkillBehaviorAnalysis {
	profile := buildCapabilityProfileFromBehavior(refined.Behavior)
	risks := buildResidualRisksFromBehavior(refined.Behavior, profile)
	analysis := combinationservice.AnalyzeSingleSkillBehavior(profile, risks)
	return applyBehaviorCombinationVerificationPolicy(analysis, refined)
}

func applyBehaviorCombinationVerificationPolicy(analysis combinationservice.SingleSkillBehaviorAnalysis, refined review.Result) combinationservice.SingleSkillBehaviorAnalysis {
	highThreshold, mediumThreshold := behaviorChainVerificationThresholds()
	if len(analysis.InferredChains) == 0 {
		if strings.EqualFold(strings.TrimSpace(analysis.Conclusion.RiskLevel), "high") {
			analysis.Conclusion.RiskLevel = "medium"
			analysis.Conclusion.RiskLabel = localizeRiskLevel(analysis.Conclusion.RiskLevel)
			analysis.Conclusion.Recommendation = "当前未推断出高置信度行为组合链路，建议先按中风险处置并补充可复现实验链路后再确认是否升级风险。"
		}
		return analysis
	}
	artifacts := collectBehaviorVerificationArtifacts(refined.Behavior)
	strongVerifiedCount := 0
	partialVerifiedCount := 0
	for _, chain := range analysis.InferredChains {
		ctx := inferChainVerificationContext(chain, refined, artifacts)
		if ctx.Score >= highThreshold {
			strongVerifiedCount++
		} else if ctx.Score >= mediumThreshold {
			partialVerifiedCount++
		}
	}
	if strongVerifiedCount > 0 {
		analysis.Conclusion.RiskLevel = "high"
		analysis.Conclusion.RiskLabel = localizeRiskLevel(analysis.Conclusion.RiskLevel)
		analysis.Conclusion.Recommendation = "已形成确定性组合链路（审计 + 沙箱 + LLM 复核），建议按高风险立即处置并阻断链路。"
		return analysis
	}
	if partialVerifiedCount > 0 {
		analysis.Conclusion.RiskLevel = "medium"
		analysis.Conclusion.RiskLabel = localizeRiskLevel(analysis.Conclusion.RiskLevel)
		analysis.Conclusion.Recommendation = "组合链路已被部分验证（多源证据不完整），建议补齐缺失验证源后再确认是否升级为高风险。"
		return analysis
	}
	analysis.Conclusion.RiskLevel = downgradeRiskLevel(analysis.Conclusion.RiskLevel)
	analysis.Conclusion.RiskLabel = localizeRiskLevel(analysis.Conclusion.RiskLevel)
	analysis.Conclusion.Recommendation = "当前行为组合链路尚缺少确定性验证闭环（审计/沙箱/LLM），建议按链路补充触发样例与运行证据后再确认最终风险结论。"
	return analysis
}

func behaviorChainVerificationThresholds() (int, int) {
	high := config.BehaviorChainVerifyHighThreshold()
	medium := config.BehaviorChainVerifyMediumThreshold()
	if medium > high {
		medium = high
	}
	if high < 1 {
		high = 1
	}
	if medium < 1 {
		medium = 1
	}
	return high, medium
}

func downgradeRiskLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return "low"
	}
}

func renderSingleSkillBehaviorCombinationSection(refined review.Result) string {
	analysis := buildSingleSkillBehaviorCombination(refined)
	artifacts := collectBehaviorVerificationArtifacts(refined.Behavior)
	highThreshold, mediumThreshold := behaviorChainVerificationThresholds()
	var b strings.Builder
	b.WriteString("<div id=\"behavior-combination\" class=\"card\"><div class=\"section-head\"><h2>单技能行为组合分析</h2><span class=\"hint\">基于组合规则引擎复用，对当前技能的行为能力联动进行链路化研判。</span></div>")
	b.WriteString("<p class=\"hint\"><strong>TL;DR:</strong> " + html.EscapeString(buildBehaviorCombinationTLDR(analysis, refined.Behavior)) + "</p>")
	b.WriteString("<p class=\"hint\"><strong>判定门槛:</strong> 高风险需验证来源分值 ≥ " + strconv.Itoa(highThreshold) + "；部分确定需验证来源分值 ≥ " + strconv.Itoa(mediumThreshold) + "（来源: 审计/沙箱/LLM，各记 1 分）。</p>")
	riskClass := "risk-low"
	switch strings.ToLower(strings.TrimSpace(analysis.Conclusion.RiskLevel)) {
	case "high":
		riskClass = "risk-high"
	case "medium":
		riskClass = "risk-medium"
	}
	b.WriteString("<div class=\"grid-two\">")
	b.WriteString("<div class=\"finding-section\">")
	b.WriteString("<h3>结论与建议</h3>")
	if analysis.Conclusion.CacheReused {
		b.WriteString("<p><strong>增量分析:</strong> 命中缓存复用（本次未执行全量组合重算）</p>")
	} else {
		b.WriteString("<p><strong>增量分析:</strong> 未命中缓存（本次执行全量组合分析）</p>")
	}
	b.WriteString("<p><strong>组合结论:</strong> <span class=\"" + riskClass + "\">" + html.EscapeString(defaultIfEmpty(analysis.Conclusion.RiskLabel, "低风险")) + "</span></p>")
	if strings.TrimSpace(analysis.Conclusion.Recommendation) != "" {
		b.WriteString("<p><strong>处置建议:</strong> " + html.EscapeString(analysis.Conclusion.Recommendation) + "</p>")
	} else {
		b.WriteString("<p class=\"muted\"><strong>处置建议:</strong> 暂无额外建议。</p>")
	}
	b.WriteString("</div>")
	b.WriteString("<div class=\"finding-section\">")
	b.WriteString("<h3>情报与配置信号</h3>")
	b.WriteString(fmt.Sprintf("<p><strong>TI 摘要:</strong> 目标 %d · 高威胁 %d · 可疑 %d · 调整分 %.2f</p>", analysis.Conclusion.TITargetCount, analysis.Conclusion.TIThreatCount, analysis.Conclusion.TISuspiciousCount, analysis.Conclusion.TIAdjustmentScore))
	if strings.TrimSpace(analysis.Conclusion.RuleConfigWarning) != "" {
		color := "#b54708"
		if strings.EqualFold(strings.TrimSpace(analysis.Conclusion.RuleConfigWarnLevel), "error") {
			color = "#b42318"
		}
		b.WriteString("<p style=\"color:" + color + "\"><strong>规则配置告警:</strong> " + html.EscapeString(analysis.Conclusion.RuleConfigWarning) + "</p>")
	} else {
		b.WriteString("<p class=\"muted\"><strong>规则配置告警:</strong> 无</p>")
	}
	b.WriteString("</div>")
	b.WriteString("</div>")
	b.WriteString(renderHTMLLabeledList("能力画像", analysis.Capabilities, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("风险标签", analysis.CombinedTags, 0, "未检出"))
	if len(analysis.InferredChains) > 0 {
		limit := len(analysis.InferredChains)
		if limit > 2 {
			limit = 2
		}
		renderChainTable := func(items []combinationservice.InferredChain) {
			b.WriteString("<div class=\"table-wrap\"><table><tr><th>链路标题</th><th>等级</th><th>验证状态</th><th>验证来源</th><th>摘要</th><th>风险定位</th><th>关键代码</th></tr>")
			for _, chain := range items {
				levelClass := "risk-low"
				switch strings.ToLower(strings.TrimSpace(chain.Level)) {
				case "high":
					levelClass = "risk-high"
				case "medium":
					levelClass = "risk-medium"
				}
				ctx := inferChainVerificationContext(chain, refined, artifacts)
				verified := ctx.Verified
				statusText := ctx.Status
				statusClass := "risk-medium"
				if verified {
					statusClass = "risk-high"
				}
				location, snippet := selectArtifactForChain(chain, artifacts)
				b.WriteString("<tr><td>" + html.EscapeString(defaultIfEmpty(chain.Title, "-")) + "</td><td><span class=\"" + levelClass + "\">" + html.EscapeString(defaultIfEmpty(chain.Level, "-")) + "</span></td><td><span class=\"" + statusClass + "\">" + html.EscapeString(statusText) + "</span></td><td>" + html.EscapeString(defaultIfEmpty(strings.Join(ctx.Sources, " + "), "-")) + "</td><td>" + html.EscapeString(defaultIfEmpty(chain.Summary, "-")) + "</td><td>" + html.EscapeString(defaultIfEmpty(location, "未定位")) + "</td><td><pre class=\"code-box\">" + html.EscapeString(defaultIfEmpty(snippet, strings.Join(chain.Evidence, "；"))) + "</pre></td></tr>")
			}
			b.WriteString("</table></div>")
		}
		renderChainTable(analysis.InferredChains[:limit])
		if len(analysis.InferredChains) > limit {
			b.WriteString("<details class=\"appendix-details\"><summary>展开更多链路（" + strconv.Itoa(len(analysis.InferredChains)-limit) + " 条）</summary><div class=\"appendix-body\">")
			renderChainTable(analysis.InferredChains[limit:])
			b.WriteString("</div></details>")
		}
	} else {
		b.WriteString("<p class=\"muted\">当前未推断出高置信度行为组合链路。</p>")
	}
	b.WriteString("</div>")
	return b.String()
}

type behaviorVerificationArtifact struct {
	Location string
	Snippet  string
}

func collectBehaviorVerificationArtifacts(behavior review.BehaviorProfile) []behaviorVerificationArtifact {
	items := make([]string, 0, 32)
	items = append(items, behavior.ExecuteIOCs...)
	items = append(items, behavior.OutboundIOCs...)
	items = append(items, behavior.CredentialIOCs...)
	items = append(items, behavior.DownloadIOCs...)
	items = append(items, behavior.DropIOCs...)
	items = append(items, behavior.PersistenceIOCs...)
	items = append(items, behavior.BehaviorChains...)
	items = append(items, behavior.SequenceAlerts...)
	seen := map[string]struct{}{}
	out := make([]behaviorVerificationArtifact, 0, len(items))
	for _, raw := range items {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		location := ""
		if p, l, ok := parseSourceLocation(line); ok {
			location = filepath.ToSlash(strings.TrimSpace(p)) + ":" + strconv.Itoa(l)
		} else if pipe := strings.Index(line, "|"); pipe > 0 {
			head := strings.TrimSpace(line[:pipe])
			if p, l, ok := parseSourceLocation(head); ok {
				location = filepath.ToSlash(strings.TrimSpace(p)) + ":" + strconv.Itoa(l)
			}
		}
		key := location + "\x00" + line
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, behaviorVerificationArtifact{Location: location, Snippet: line})
	}
	return out
}

func inferChainVerificationStatus(chain combinationservice.InferredChain, behavior review.BehaviorProfile, artifacts []behaviorVerificationArtifact) (bool, string) {
	if len(artifacts) == 0 {
		return false, "待验证"
	}
	if chainTitleMatchesBehaviorText(chain.Title, joinedBehaviorSupportText(behavior)) || hasAnyBehaviorSupport(behavior) {
		return true, "已验证"
	}
	return false, "待验证"
}

type chainVerificationContext struct {
	Verified bool
	Status   string
	Sources  []string
	Score    int
}

func inferChainVerificationContext(chain combinationservice.InferredChain, refined review.Result, artifacts []behaviorVerificationArtifact) chainVerificationContext {
	ctx := chainVerificationContext{Verified: false, Status: "待验证", Sources: []string{}, Score: 0}
	if verified, _ := inferChainVerificationStatus(chain, refined.Behavior, artifacts); verified {
		ctx.Sources = append(ctx.Sources, "沙箱")
		ctx.Score++
	}
	if chainHasAuditSupport(chain, refined.Behavior) {
		ctx.Sources = append(ctx.Sources, "审计")
		ctx.Score++
	}
	if chainHasLLMSupport(chain, refined) {
		ctx.Sources = append(ctx.Sources, "LLM")
		ctx.Score++
	}
	if ctx.Score >= 3 {
		ctx.Verified = true
		ctx.Status = "已确定"
	} else if ctx.Score == 2 {
		ctx.Verified = true
		ctx.Status = "部分确定"
	} else {
		ctx.Verified = false
		ctx.Status = "待验证"
	}
	return ctx
}

func chainHasAuditSupport(chain combinationservice.InferredChain, behavior review.BehaviorProfile) bool {
	return chainTitleMatchesBehaviorText(chain.Title, joinedBehaviorSupportText(behavior)) || hasAnyBehaviorSupport(behavior)
}

func chainHasLLMSupport(chain combinationservice.InferredChain, refined review.Result) bool {
	ctx := newReviewedFindingContext(refined)
	if len(ctx.verdicts) == 0 {
		return false
	}
	title := strings.ToLower(strings.TrimSpace(chain.Title))
	for _, finding := range refined.StructuredFindings {
		fv := ctx.finalVerdict(finding.ID)
		if normalizedReviewVerdict(fv.Verdict) != "confirmed" {
			continue
		}
		joined := normalizedJoinedText([]string{finding.Title, finding.Category, finding.AttackPath})
		if chainTitleMatchesFindingSummary(title, joined) {
			return true
		}
	}
	return false
}

func selectArtifactForChain(chain combinationservice.InferredChain, artifacts []behaviorVerificationArtifact) (string, string) {
	if len(artifacts) == 0 {
		return "", ""
	}
	for _, item := range artifacts {
		if chainTitleMatchesBehaviorText(chain.Title, strings.ToLower(item.Snippet)) {
			return item.Location, item.Snippet
		}
	}
	return artifacts[0].Location, artifacts[0].Snippet
}

func joinedBehaviorSupportText(behavior review.BehaviorProfile) string {
	return normalizedJoinedText(append(append([]string{}, behavior.BehaviorChains...), behavior.SequenceAlerts...))
}

func hasAnyBehaviorSupport(behavior review.BehaviorProfile) bool {
	return len(behavior.BehaviorChains) > 0 || len(behavior.SequenceAlerts) > 0
}

func chainTitleMatchesBehaviorText(title, text string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	switch {
	case strings.Contains(title, "执行"):
		return strings.Contains(text, "执行") || strings.Contains(text, "exec")
	case strings.Contains(title, "外联") || strings.Contains(title, "外发"):
		return strings.Contains(text, "外联") || strings.Contains(text, "http") || strings.Contains(text, "network")
	case strings.Contains(title, "敏感") || strings.Contains(title, "凭据"):
		return strings.Contains(text, "凭据") || strings.Contains(text, "credential") || strings.Contains(text, "token")
	default:
		return false
	}
}

func chainTitleMatchesFindingSummary(title, summary string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	switch {
	case strings.Contains(title, "执行"):
		return strings.Contains(summary, "执行") || strings.Contains(summary, "command")
	case strings.Contains(title, "外联") || strings.Contains(title, "外发"):
		return strings.Contains(summary, "外联") || strings.Contains(summary, "网络") || strings.Contains(summary, "情报")
	case strings.Contains(title, "凭据") || strings.Contains(title, "敏感"):
		return strings.Contains(summary, "凭据") || strings.Contains(summary, "敏感")
	default:
		return false
	}
}

func buildBehaviorCombinationTLDR(analysis combinationservice.SingleSkillBehaviorAnalysis, behavior review.BehaviorProfile) string {
	risk := defaultIfEmpty(strings.TrimSpace(analysis.Conclusion.RiskLabel), "低风险")
	verificationState := summarizeBehaviorCombinationVerificationState(analysis, behavior)
	reasons := make([]string, 0, 3)
	for _, chain := range analysis.InferredChains {
		title := strings.TrimSpace(chain.Title)
		if title == "" {
			continue
		}
		reasons = append(reasons, title)
		if len(reasons) == 2 {
			break
		}
	}
	if len(reasons) == 0 {
		if analysis.Conclusion.TIThreatCount > 0 || analysis.Conclusion.TISuspiciousCount > 0 {
			reasons = append(reasons, "存在 TI 风险信号")
		}
	}
	if len(reasons) == 0 && len(analysis.Capabilities) > 0 {
		reasons = append(reasons, "能力画像包含 "+strings.Join(analysis.Capabilities[:minInt(2, len(analysis.Capabilities))], " + "))
	}
	if len(reasons) == 0 {
		return "当前为" + risk + "（" + verificationState + "），未发现明显的高置信度行为联动链路。"
	}
	return "当前为" + risk + "（" + verificationState + "），主要因" + strings.Join(reasons, "；") + "。"
}

func summarizeBehaviorCombinationVerificationState(analysis combinationservice.SingleSkillBehaviorAnalysis, behavior review.BehaviorProfile) string {
	if len(analysis.InferredChains) == 0 {
		return "未发现可验证联动链路"
	}
	artifacts := collectBehaviorVerificationArtifacts(behavior)
	verifiedCount := 0
	for _, chain := range analysis.InferredChains {
		verified, _ := inferChainVerificationStatus(chain, behavior, artifacts)
		if verified {
			verifiedCount++
		}
	}
	if verifiedCount > 0 {
		return "链路已验证"
	}
	return "链路待验证"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
