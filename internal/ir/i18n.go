package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 国际化 (i18n)
//
// 支持报告输出的多语言：中文(zh)、英文(en)、日语(ja)
// =============================================================================

// Language 语言标识。
type Language string

const (
	LangZH Language = "zh" // 中文
	LangEN Language = "en" // English
	LangJA Language = "ja" // 日本語
)

// Translator 翻译器。
type Translator struct {
	lang Language
	langPack map[string]string
}

// NewTranslator 创建翻译器。
func NewTranslator(lang Language) *Translator {
	pack := getLangPack(lang)
	if pack == nil {
		pack = getLangPack(LangZH) // 默认中文
	}
	return &Translator{lang: lang, langPack: pack}
}

// T 翻译文本。
func (t *Translator) T(key string) string {
	if v, ok := t.langPack[key]; ok {
		return v
	}
	return key
}

// Tf 格式化翻译。
func (t *Translator) Tf(key string, args ...interface{}) string {
	tmpl := t.T(key)
	return fmt.Sprintf(tmpl, args...)
}

// getLangPack 获取语言包。
func getLangPack(lang Language) map[string]string {
	switch lang {
	case LangZH:
		return zhPack
	case LangEN:
		return enPack
	case LangJA:
		return jaPack
	default:
		return nil
	}
}

// =============================================================================
// 中文语言包
// =============================================================================

var zhPack = map[string]string{
	// 报告标题
	"report.title":          "技能安全审查报告",
	"report.summary":        "审查摘要",
	"report.findings":       "安全发现",
	"report.recommendation": "修复建议",
	"report.disclaimer":     "系统只提供声明、行为、意图、权限和证据链分析，不替用户最终判断是否可以使用。",
	"report.score_hint":     "评分与分值字段仅作辅助参考，优先以证据链、风险条目和复核结论作出处置判断。",
	"report.generated_at":   "生成时间",
	"report.declaration":    "提交声明",
	"report.file":           "文件",
	"report.decision":       "处置建议",
	"report.decision_hint":  "基于证据链给出的建议，不代替人工审批",
	"report.risk_level":     "风险等级",
	"report.risk_summary":   "风险汇总",
	"report.closure_summary": "闭环摘要",

	// 导航
	"nav.verification": "验证结论摘要",
	"nav.behavior":     "行为组合分析",
	"nav.profile":      "技能画像",
	"nav.findings":     "风险综合研判",
	"nav.trace":        "复核轨迹回放",
	"nav.mitre":        "MITRE 映射",
	"nav.appendix":     "附录与完整性",

	// 风险等级
	"risk.high":   "高风险",
	"risk.medium": "中风险",
	"risk.low":    "低风险",
	"risk.none":   "无风险",

	// 分析类型
	"analysis.taint":      "污点分析",
	"analysis.chain":      "能力链验证",
	"analysis.similarity": "代码相似性",
	"analysis.ir_rule":    "IR 规则检测",
	"analysis.agent":      "Agent 探索",

	// 污点分析
	"taint.source":        "数据来源",
	"taint.sink":          "数据汇聚",
	"taint.flow":          "数据流",
	"taint.description":   "污点数据从 %s 传播到 %s",
	"taint.confidence":    "置信度",

	// 能力链
	"chain.verified":      "已验证",
	"chain.unverified":    "未验证",
	"chain.description":   "能力链验证",
	"chain.gap":           "闭环缺口",
	"chain.evidence":      "证据",

	// 相似性
	"similarity.match":    "相似性匹配",
	"similarity.pattern":  "漏洞模式",
	"similarity.score":    "相似度",

	// Agent 探索
	"agent.task":          "探索任务",
	"agent.verify_taint":  "验证污点流",
	"agent.fill_gap":      "补充链证据",
	"agent.analyze_path":  "分析调用路径",
	"agent.poc":           "验证代码",

	// 修复建议
	"fix.sanitize_input":  "对输入做校验和消毒",
	"fix.use_params":      "使用参数化方式替代字符串拼接",
	"fix.whitelist":       "使用白名单限制允许的值",
	"fix.min_permission":  "遵循最小权限原则",
	"fix.audit_log":       "增加审计日志",
	"fix.remove_secret":   "移除硬编码的凭据",
	"fix.encrypt":         "对敏感数据加密",
	"fix.sandbox":         "在沙箱中执行不可信代码",

	// 统计
	"stats.files":         "文件数",
	"stats.functions":     "函数数",
	"stats.calls":         "调用数",
	"stats.findings":      "发现数",
	"stats.verified":      "已验证",
	"stats.unverified":    "未验证",

	// 置信度
	"confidence.high":     "高",
	"confidence.medium":   "中",
	"confidence.low":      "低",
	"confidence.unknown":  "未验证",
}

// =============================================================================
// 英文语言包
// =============================================================================

var enPack = map[string]string{
	"report.title":          "Skill Security Audit Report",
	"report.summary":        "Audit Summary",
	"report.findings":       "Security Findings",
	"report.recommendation": "Recommendations",
	"report.disclaimer":     "The system only provides analysis of declarations, behavior, intent, permissions, and evidence chains. It does not make the final decision on whether a skill can be used.",
	"report.score_hint":     "Scores are for reference only. Prioritize evidence chains, risk items, and review conclusions for decision-making.",
	"report.generated_at":   "Generated at",
	"report.declaration":    "Declaration",
	"report.file":           "File",
	"report.decision":       "Decision",
	"report.decision_hint":  "Recommendation based on evidence chain, does not replace manual approval",
	"report.risk_level":     "Risk Level",
	"report.risk_summary":   "Risk Summary",
	"report.closure_summary": "Closure Summary",

	"nav.verification": "Verification Summary",
	"nav.behavior":     "Behavior Analysis",
	"nav.profile":      "Skill Profile",
	"nav.findings":     "Risk Assessment",
	"nav.trace":        "Review Trace",
	"nav.mitre":        "MITRE Mapping",
	"nav.appendix":     "Appendix",

	"risk.high":   "High Risk",
	"risk.medium": "Medium Risk",
	"risk.low":    "Low Risk",
	"risk.none":   "No Risk",

	"analysis.taint":      "Taint Analysis",
	"analysis.chain":      "Capability Chain Verification",
	"analysis.similarity": "Code Similarity",
	"analysis.ir_rule":    "IR Rule Detection",
	"analysis.agent":      "Agent Exploration",

	"taint.source":        "Data Source",
	"taint.sink":          "Data Sink",
	"taint.flow":          "Data Flow",
	"taint.description":   "Taint data propagates from %s to %s",
	"taint.confidence":    "Confidence",

	"chain.verified":      "Verified",
	"chain.unverified":    "Unverified",
	"chain.description":   "Capability Chain Verification",
	"chain.gap":           "Closure Gap",
	"chain.evidence":      "Evidence",

	"similarity.match":    "Similarity Match",
	"similarity.pattern":  "Vulnerability Pattern",
	"similarity.score":    "Similarity Score",

	"agent.task":          "Exploration Task",
	"agent.verify_taint":  "Verify Taint Flow",
	"agent.fill_gap":      "Fill Chain Gap",
	"agent.analyze_path":  "Analyze Call Path",
	"agent.poc":           "Proof of Concept",

	"fix.sanitize_input":  "Validate and sanitize inputs",
	"fix.use_params":      "Use parameterized queries instead of string concatenation",
	"fix.whitelist":       "Use whitelists to restrict allowed values",
	"fix.min_permission":  "Follow the principle of least privilege",
	"fix.audit_log":       "Add audit logging",
	"fix.remove_secret":   "Remove hardcoded credentials",
	"fix.encrypt":         "Encrypt sensitive data",
	"fix.sandbox":         "Execute untrusted code in a sandbox",

	"stats.files":         "Files",
	"stats.functions":     "Functions",
	"stats.calls":         "Calls",
	"stats.findings":      "Findings",
	"stats.verified":      "Verified",
	"stats.unverified":    "Unverified",

	"confidence.high":     "High",
	"confidence.medium":   "Medium",
	"confidence.low":      "Low",
	"confidence.unknown":  "Unknown",
}

// =============================================================================
// 日语语言包
// =============================================================================

var jaPack = map[string]string{
	"report.title":          "スキルセキュリティ監査レポート",
	"report.summary":        "監査サマリー",
	"report.findings":       "セキュリティ検出事項",
	"report.recommendation": "推奨事項",
	"report.disclaimer":     "システムは宣言、動作、意図、権限、証拠チェーンの分析のみを提供します。スキルの使用可否の最終判断は行いません。",
	"report.score_hint":     "スコアは参考のみです。証拠チェーン、リスク項目、レビュー結論を優先して判断してください。",
	"report.generated_at":   "生成日時",
	"report.declaration":    "宣言",
	"report.file":           "ファイル",
	"report.decision":       "判断",
	"report.decision_hint":  "証拠チェーンに基づく推奨、手動承認の代わりではありません",
	"report.risk_level":     "リスクレベル",
	"report.risk_summary":   "リスクサマリー",
	"report.closure_summary": "クロージャサマリー",

	"nav.verification": "検証サマリー",
	"nav.behavior":     "動作分析",
	"nav.profile":      "スキルプロファイル",
	"nav.findings":     "リスク評価",
	"nav.trace":        "レビュートレース",
	"nav.mitre":        "MITRE マッピング",
	"nav.appendix":     "付録",

	"risk.high":   "高リスク",
	"risk.medium": "中リスク",
	"risk.low":    "低リスク",
	"risk.none":   "リスクなし",

	"analysis.taint":      "汚染分析",
	"analysis.chain":      "能力チェーン検証",
	"analysis.similarity": "コード類似性",
	"analysis.ir_rule":    "IR ルール検出",
	"analysis.agent":      "Agent 探索",

	"taint.source":        "データソース",
	"taint.sink":          "データシンク",
	"taint.flow":          "データフロー",
	"taint.description":   "汚染データが %s から %s に伝播",
	"taint.confidence":    "信頼度",

	"chain.verified":      "検証済み",
	"chain.unverified":    "未検証",
	"chain.description":   "能力チェーン検証",
	"chain.gap":           "クロージャギャップ",
	"chain.evidence":      "エビデンス",

	"similarity.match":    "類似性マッチ",
	"similarity.pattern":  "脆弱性パターン",
	"similarity.score":    "類似度スコア",

	"agent.task":          "探索タスク",
	"agent.verify_taint":  "汚染フロー検証",
	"agent.fill_gap":      "チェーンギャップ補完",
	"agent.analyze_path":  "コールパス分析",
	"agent.poc":           "概念実証",

	"fix.sanitize_input":  "入力の検証とサニタイズ",
	"fix.use_params":      "文字列連結ではなくパラメータ化クエリを使用",
	"fix.whitelist":       "ホワイトリストで許可値を制限",
	"fix.min_permission":  "最小権限の原則に従う",
	"fix.audit_log":       "監査ログを追加",
	"fix.remove_secret":   "ハードコードされた資格情報を削除",
	"fix.encrypt":         "機密データを暗号化",
	"fix.sandbox":         "サンドボックスで信頼できないコードを実行",

	"stats.files":         "ファイル数",
	"stats.functions":     "関数数",
	"stats.calls":         "呼び出し数",
	"stats.findings":      "検出数",
	"stats.verified":      "検証済み",
	"stats.unverified":    "未検証",

	"confidence.high":     "高",
	"confidence.medium":   "中",
	"confidence.low":      "低",
	"confidence.unknown":  "不明",
}

// =============================================================================
// 多语言报告生成
// =============================================================================

// I18nReport 多语言报告。
type I18nReport struct {
	lang      Language
	translator *Translator
}

// NewI18nReport 创建多语言报告生成器。
func NewI18nReport(lang Language) *I18nReport {
	return &I18nReport{
		lang:       lang,
		translator: NewTranslator(lang),
	}
}

// FormatAnalysis 格式化分析结果。
func (r *I18nReport) FormatAnalysis(analysis FullAnalysis) string {
	t := r.translator
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s\n\n", t.T("report.title")))

	// 统计
	sb.WriteString(fmt.Sprintf("## %s\n", t.T("report.summary")))
	sb.WriteString(fmt.Sprintf("- %s: %d\n", t.T("stats.files"), len(analysis.TaintFindings)))
	sb.WriteString(fmt.Sprintf("- %s: %d\n", t.T("stats.findings"), len(analysis.TaintFindings)+len(analysis.SimilarityMatches)))
	sb.WriteString("\n")

	// 污点分析
	if len(analysis.TaintFindings) > 0 {
		sb.WriteString(fmt.Sprintf("## %s\n", t.T("analysis.taint")))
		for i, tf := range analysis.TaintFindings {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, t.T("risk."+severityKey(tf.Severity)), tf.Description))
			sb.WriteString(fmt.Sprintf("   %s: %s → %s: %s\n", t.T("taint.source"), tf.Source.VarName, t.T("taint.sink"), tf.Sink.Call.FuncName))
		}
		sb.WriteString("\n")
	}

	// 链验证
	verified := 0
	for _, cr := range analysis.ChainResults {
		if cr.Verified {
			verified++
		}
	}
	if verified > 0 {
		sb.WriteString(fmt.Sprintf("## %s\n", t.T("analysis.chain")))
		for _, cr := range analysis.ChainResults {
			if cr.Verified {
				sb.WriteString(fmt.Sprintf("- ✅ %s (%s)\n", cr.Description, cr.Confidence))
			}
		}
		sb.WriteString("\n")
	}

	// 相似性匹配
	if len(analysis.SimilarityMatches) > 0 {
		sb.WriteString(fmt.Sprintf("## %s\n", t.T("analysis.similarity")))
		for _, m := range analysis.SimilarityMatches {
			sb.WriteString(fmt.Sprintf("- [%s] %s (%s: %.0f%%)\n", t.T("risk."+severityKey(m.Severity)), m.PatternName, t.T("similarity.score"), m.Similarity*100))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatTaintFinding 格式化单个污点发现。
func (r *I18nReport) FormatTaintFinding(tf TaintFinding) string {
	t := r.translator
	return t.Tf("taint.description", tf.Source.VarName, tf.Sink.Call.FuncName)
}

// FormatChainResult 格式化链验证结果。
func (r *I18nReport) FormatChainResult(cr ChainVerificationResult) string {
	t := r.translator
	status := t.T("chain.unverified")
	if cr.Verified {
		status = t.T("chain.verified")
	}
	return fmt.Sprintf("[%s] %s (%s)", status, cr.Description, cr.Confidence)
}

// FormatSimilarityMatch 格式化相似性匹配。
func (r *I18nReport) FormatSimilarityMatch(m SimilarityMatch) string {
	t := r.translator
	return fmt.Sprintf("[%s] %s (%s: %.0f%%)", t.T("risk."+severityKey(m.Severity)), m.PatternName, t.T("similarity.score"), m.Similarity*100)
}

// GetFixSuggestion 获取修复建议（多语言）。
func (r *I18nReport) GetFixSuggestion(category string) string {
	t := r.translator
	switch category {
	case "command_exec":
		return t.T("fix.sanitize_input")
	case "network_access":
		return t.T("fix.whitelist")
	case "file_read", "file_write":
		return t.T("fix.min_permission")
	case "env_access":
		return t.T("fix.remove_secret")
	case "unsafe":
		return t.T("fix.sandbox")
	default:
		return t.T("fix.audit_log")
	}
}

// severityKey 将严重性转为语言包 key。
func severityKey(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "高风险", "high":
		return "high"
	case "中风险", "medium":
		return "medium"
	case "低风险", "low":
		return "low"
	default:
		return "none"
	}
}

// SupportedI18nLanguages 返回支持的国际化语言列表。
func SupportedI18nLanguages() []Language {
	return []Language{LangZH, LangEN, LangJA}
}

// LanguageName 返回语言的显示名称。
func LanguageName(lang Language) string {
	switch lang {
	case LangZH:
		return "中文"
	case LangEN:
		return "English"
	case LangJA:
		return "日本語"
	default:
		return string(lang)
	}
}
