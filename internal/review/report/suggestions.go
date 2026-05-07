package report

import (
	"fmt"
	"html"
	"strconv"
	"strings"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func BuildDynamicSuggestions(findings []plugins.Finding, refined review.Result) []string {
	out := make([]string, 0, 12)
	seen := make(map[string]struct{})

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	orderedFindings := SortFindingsBySeverity(findings)
	for _, f := range orderedFindings {
		severity := localizeSeverity(f.Severity)
		switch {
		case strings.HasPrefix(strings.ToUpper(strings.TrimSpace(f.RuleID)), "V7-00") || f.RuleID == "V7-010" || f.RuleID == "V7-011" || f.RuleID == "V7-012" || f.RuleID == "V7-013" || f.RuleID == "V7-014":
			add(fmt.Sprintf("针对规则 %s（%s）在 %s 执行强制修复：移除高危调用或增加显式权限校验，并补充单元测试覆盖该路径。", f.RuleID, f.Title, defaultIfEmpty(f.Location, "代码实现")))
		case f.RuleID == "V7-003":
			add(fmt.Sprintf("将外联目标 %s 收敛到受控白名单域名，禁止明文 HTTP，必要时增加签名校验与下载完整性校验。", defaultIfEmpty(f.Location, "未知目标")))
		case f.RuleID == "V7-019":
			add("检测到不可逆操作但缺少人工确认步骤，请为删除、支付、通知发送等路径增加人工审批或二次确认后再执行。")
		case f.RuleID == "V7-025":
			add("请对照“声明收集数据”与“实际收集数据”差异，删除非必要字段并补充最小化收集说明，再由人工完成隐私合规复核。")
		case f.RuleID == "V7-AUTO-COVERAGE":
			add("优先补齐 V7 中可自动评估但当前未接入的规则映射，确保系统评估覆盖全部自动项后再进行完整整改判断。")
		case f.RuleID == "V7-006":
			add("根据声明与行为偏差，更新技能设计说明与权限声明，确保行为路径与声明能力一一对应，并删除未声明能力代码。")
		default:
			switch severity {
			case "高风险":
				add(fmt.Sprintf("修复高风险项 %s：在 %s 增加输入校验、最小权限控制与异常处理，避免高危能力在无防护条件下执行。", defaultIfEmpty(f.Title, f.RuleID), defaultIfEmpty(f.Location, "相关模块")))
			case "中风险":
				add(fmt.Sprintf("修复中风险项 %s：在 %s 补充边界校验、权限收敛和日志审计，防止风险在特定条件下放大。", defaultIfEmpty(f.Title, f.RuleID), defaultIfEmpty(f.Location, "相关模块")))
			case "低风险":
				add(fmt.Sprintf("处理低风险项 %s：在 %s 完善配置与防护细节，并在下个迭代完成复测闭环。", defaultIfEmpty(f.Title, f.RuleID), defaultIfEmpty(f.Location, "相关模块")))
			}
		}
	}

	if len(refined.IntentDiffs) > 0 {
		add("对每条 Intent 差异建立“声明 -> 行为 -> 测试”对照表：先修正声明，再修正实现，最后新增回归用例防止偏离复发。")
	}

	for _, item := range refined.TIReputations {
		rep := strings.ToLower(strings.TrimSpace(item.Reputation))
		if rep == "suspicious" || rep == "malicious" || rep == "high-risk" {
			add(fmt.Sprintf("对可疑情报目标 %s 执行替换或下线，并在配置层加入 denylist；修复后重新扫描确认信誉已恢复。", item.Target))
			continue
		}
		if rep == "policy" {
			add(fmt.Sprintf("目标 %s 命中公司策略限制，请改为合规白名单服务或在准入流程中申请例外审批，不要按恶意外联处置。", item.Target))
		}
	}

	if len(refined.Behavior.ExecTargets) > 0 {
		add(fmt.Sprintf("当前检测到 %d 个命令执行行为，请在技能设计中显式列出允许命令并实施 allowlist 校验。", len(refined.Behavior.ExecTargets)))
	}
	if len(refined.Behavior.DownloadIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条下载证据，请对下载来源、文件类型、完整性校验和后续执行链路做闭环审计。", len(refined.Behavior.DownloadIOCs)))
	}
	if len(refined.Behavior.DropIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条文件落地证据，请核查落地目录、文件权限和持久化策略，避免写入高敏感路径。", len(refined.Behavior.DropIOCs)))
	}
	if len(refined.Behavior.ExecuteIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条执行证据，请核查是否存在脚本拼接执行、下载后执行或越权执行路径。", len(refined.Behavior.ExecuteIOCs)))
	}
	if len(refined.Behavior.OutboundIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条外联证据，请建立目标白名单并核验协议、域名信誉与数据最小化传输策略。", len(refined.Behavior.OutboundIOCs)))
	}
	if len(refined.Behavior.PersistenceIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条持久化证据，请核查启动项/计划任务/系统服务写入行为，确保无隐蔽自启动路径。", len(refined.Behavior.PersistenceIOCs)))
	}
	if len(refined.Behavior.PrivEscIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条提权证据，请移除 sudo/setuid 等高危提权路径，并增加最小权限与调用审计。", len(refined.Behavior.PrivEscIOCs)))
	}
	if len(refined.Behavior.CredentialIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条凭据访问证据，请移除对敏感凭据文件和密钥变量的直接读取，改为受控密钥管理接口。", len(refined.Behavior.CredentialIOCs)))
	}
	if len(refined.Behavior.DefenseEvasionIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条防御规避证据，请移除日志清理、监控禁用等逃逸逻辑，并补充安全审计日志。", len(refined.Behavior.DefenseEvasionIOCs)))
	}
	if len(refined.Behavior.LateralMoveIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条横向移动证据，请审计远程连接与共享访问行为，限制跨主机扩散路径并启用访问审批。", len(refined.Behavior.LateralMoveIOCs)))
	}
	if len(refined.Behavior.CollectionIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条数据收集/打包证据，请核查是否存在批量枚举与压缩导出，限制敏感数据聚合与批量导出。", len(refined.Behavior.CollectionIOCs)))
	}
	if len(refined.Behavior.C2BeaconIOCs) > 0 {
		add(fmt.Sprintf("检测到 %d 条C2信标证据，请重点核查心跳回连与命令拉取逻辑，必要时立即下线相关能力并离线分析。", len(refined.Behavior.C2BeaconIOCs)))
	}
	if len(refined.Behavior.BehaviorTimelines) > 0 {
		add(fmt.Sprintf("检测到 %d 条行为时序链路，请优先核查“先收集再外联”“先规避后执行”等高危时序是否存在业务必要性。", len(refined.Behavior.BehaviorTimelines)))
	}
	if len(refined.Behavior.SequenceAlerts) > 0 {
		add(fmt.Sprintf("命中 %d 条恶意时序告警，请按告警逐条确认触发条件并修复行为编排逻辑。", len(refined.Behavior.SequenceAlerts)))
	}
	if len(refined.Behavior.BehaviorChains) > 0 {
		add(fmt.Sprintf("检测到 %d 条高风险链路摘要（下载/落地/执行/外联关联），请按链路优先级逐条闭环处置并补充回归测试。", len(refined.Behavior.BehaviorChains)))
	}
	if len(refined.Behavior.ProbeWarnings) > 0 {
		add(fmt.Sprintf("沙箱探针存在 %d 条告警，请先修复探针可观测性问题（编码/权限/文件读取失败等）后再复扫，以避免漏检。", len(refined.Behavior.ProbeWarnings)))
	}
	if len(refined.Behavior.NetworkTargets) > 0 {
		add(fmt.Sprintf("当前检测到 %d 个网络目标，请按业务必要性逐条归因，删除无业务价值外联并增加出站白名单。", len(refined.Behavior.NetworkTargets)))
	}

	if refined.Summary.HighRisk > 0 {
		add("本次存在高风险项，建议按“先高风险、再中风险、后低风险”的顺序分批修复，并在每轮修复后全量复扫直至无高风险。")
	}

	add("修复完成后请重新上传同版本技能包复测，确认高风险、中风险、低风险数量同步改善，再进入发布流程。")

	if len(out) > 10 {
		return out[:10]
	}
	return out
}

func RemediationForHTMLFinding(f plugins.Finding) string {
	ruleID := strings.ToUpper(strings.TrimSpace(f.RuleID))
	if ruleID == "V7-003" {
		return "将外联目标收敛到白名单并启用 TLS，补充来源校验、数据最小化传输和完整性校验后复测。"
	}
	if ruleID == "V7-006" {
		return "同步修正技能声明与实现行为，确保权限声明、代码能力和测试用例保持一致。"
	}
	if strings.HasPrefix(ruleID, "V7-00") || ruleID == "V7-010" || ruleID == "V7-011" || ruleID == "V7-012" || ruleID == "V7-013" || ruleID == "V7-014" {
		return "优先移除高危调用或增加显式权限校验，补充对应单元测试后重新扫描确认风险清零。"
	}
	if ruleID == "V7-AUTO-COVERAGE" {
		return "补齐自动化覆盖或记录人工复核结论，避免规则盲区影响最终判断。"
	}
	if ruleID == "LLM-DETECT" {
		return "按模型提示定位具体路径，增加输入校验、最小权限控制与错误处理，再执行全量复扫。"
	}
	if strings.TrimSpace(f.Severity) == "高风险" {
		return "在问题位置补充输入校验、权限边界与异常处理，必要时下线相关能力后逐步恢复。"
	}
	if strings.TrimSpace(f.Severity) == "中风险" {
		return "补充边界校验、权限收敛和日志审计，防止该风险在特定条件下放大。"
	}
	return "结合规则说明修正代码与配置，修复完成后执行全量复扫并更新设计文档。"
}

func SortFindingsBySeverity(findings []plugins.Finding) []plugins.Finding {
	out := make([]plugins.Finding, 0, len(findings))
	appendByLevel := func(level string) {
		for _, f := range findings {
			if localizeSeverity(f.Severity) == level {
				out = append(out, f)
			}
		}
	}
	appendByLevel("高风险")
	appendByLevel("中风险")
	appendByLevel("低风险")
	if len(out) == len(findings) {
		return out
	}
	for _, f := range findings {
		if s := localizeSeverity(f.Severity); s != "高风险" && s != "中风险" && s != "低风险" {
			out = append(out, f)
		}
	}
	return out
}

func localizeSeverity(severity string) string {
	severity = strings.TrimSpace(severity)
	switch strings.ToLower(severity) {
	case "high", "critical":
		return "高风险"
	case "medium", "moderate":
		return "中风险"
	case "low", "info", "informational":
		return "低风险"
	default:
		if severity == "" {
			return "低风险"
		}
		return severity
	}
}

func defaultIfEmpty(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

type FindingDigestRenderOptions struct {
	FinalReviewSummary func(plugins.Finding) string
}

func RenderFindingDigestIntegratedCard(findings []plugins.Finding, orderedFindings []plugins.Finding, opts FindingDigestRenderOptions) string {
	if len(orderedFindings) == 0 {
		orderedFindings = findings
	}
	var b strings.Builder
	b.WriteString("<details class=\"finding-card\"><summary><div class=\"finding-summary-main\"><p><strong>补充规则命中明细</strong></p><p class=\"muted\">原“风险发现”独立区块已吸纳到综合研判，这里只保留规则级补充定位；详细明细继续放在折叠层内，避免主视图再次膨胀。</p></div><div class=\"finding-summary-side\"><p><strong>命中数</strong></p><p>" + strconv.Itoa(len(orderedFindings)) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section wide-list\" style=\"grid-column:1/-1\"><h3>规则命中摘要</h3><p class=\"muted\">用于补充结构化风险中未保留的规则级定位、证据片段与对应修复建议。</p><details class=\"mini-card\"><summary>展开规则命中明细</summary><div class=\"table-wrap\"><table><tr><th>规则</th><th>级别</th><th>标题</th><th>位置、关键证据与对应修复建议</th></tr>")
	for i, f := range orderedFindings {
		className := "risk-low"
		if f.Severity == "高风险" {
			className = "risk-high"
		} else if f.Severity == "中风险" {
			className = "risk-medium"
		}
		location := defaultIfEmpty(strings.TrimSpace(f.Location), "未提供定位")
		snippet := strings.TrimSpace(f.CodeSnippet)
		if snippet == "" {
			snippet = "关键证据: " + defaultIfEmpty(strings.TrimSpace(f.Description), "未提取到代码片段，建议根据规则ID和标题回溯技能声明或源码上下文。")
		}
		detailID := fmt.Sprintf("fd-%d", i)
		remediation := RemediationForHTMLFinding(f)
		finalReview := "无匹配结构化发现"
		if opts.FinalReviewSummary != nil {
			finalReview = defaultIfEmpty(opts.FinalReviewSummary(f), finalReview)
		}
		b.WriteString("<tr><td>" + html.EscapeString(f.RuleID) + "</td><td class=\"" + className + "\">" + html.EscapeString(f.Severity) + "</td><td>" + html.EscapeString(f.Title) + "</td><td><details id=\"" + detailID + "\"><summary>" + html.EscapeString(location) + "</summary><p class=\"hint\">描述: " + html.EscapeString(defaultIfEmpty(f.Description, "无")) + "</p><p class=\"hint\">最终复核: " + html.EscapeString(finalReview) + "</p><pre class=\"code-box\">" + html.EscapeString(snippet) + "</pre><p><strong>对应修复建议:</strong> " + html.EscapeString(remediation) + "</p></details></td></tr>")
	}
	b.WriteString("</table></div></details></div></div></details>")
	return b.String()
}
