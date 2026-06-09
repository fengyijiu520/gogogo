package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/storage"
)

type rulesAugmentRequest struct {
	Description string            `json:"description"`
	CurrentRule rulesAugmentDraft `json:"current_rule"`
}

type rulesAugmentDraft struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Patterns []string `json:"patterns"`
	Reason   string   `json:"reason"`
}

type rulesAugmentTraceStep struct {
	Stage   string   `json:"stage"`
	Status  string   `json:"status"`
	Title   string   `json:"title"`
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
}

type rulesAugmentResponse struct {
	Draft rulesAugmentDraft       `json:"draft"`
	Trace []rulesAugmentTraceStep `json:"trace"`
}

func rulesAugment(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		var req rulesAugmentRequest
		if err := decodeStrictJSONBody(w, r, &req, 32<<10); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
			return
		}
		description := strings.TrimSpace(req.Description)
		if description == "" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请输入规则描述"})
			return
		}
		if len(description) > 4000 {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "规则描述过长"})
			return
		}

		trace := []rulesAugmentTraceStep{
			{
				Stage:   "intake",
				Status:  "completed",
				Title:   "接收规则意图",
				Summary: "已接收自然语言规则描述，准备生成结构化规则草案。",
				Details: []string{"描述长度: " + fmt.Sprintf("%d", len([]rune(description)))},
			},
		}

		userLLM := store.GetUserLLMConfig(sess.Username)
		provider, ok := resolveUserLLMProviderConfig(store, userLLM)
		if !ok {
			trace = append(trace, rulesAugmentTraceStep{
				Stage:   "llm",
				Status:  "failed",
				Title:   "加载 LLM 配置",
				Summary: "当前账号缺少可用 LLM 配置，无法生成智能规则草案。",
				Details: []string{"请先在个人中心完成 LLM 配置。"},
			})
			sendJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error": "当前账号未配置可用 LLM，无法使用智能补充规则",
				"trace": trace,
			})
			return
		}

		client, err := llm.NewClient(llm.ProviderConfig{Provider: provider.ID, Name: provider.Name, Protocol: provider.Protocol, BaseURL: provider.BaseURL, Model: provider.Model, APIKey: provider.APIKey})
		if err != nil {
			trace = append(trace, rulesAugmentTraceStep{
				Stage:   "llm",
				Status:  "failed",
				Title:   "初始化 LLM 客户端",
				Summary: "LLM 客户端初始化失败，当前无法生成规则草案。",
				Details: []string{err.Error()},
			})
			sendJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error": "LLM 客户端初始化失败",
				"trace": trace,
			})
			return
		}

		trace = append(trace,
			rulesAugmentTraceStep{
				Stage:   "llm",
				Status:  "completed",
				Title:   "加载 LLM 配置",
				Summary: "已加载当前账号可用的 LLM 配置。",
				Details: []string{"Provider: " + strings.TrimSpace(provider.Name), "Model: " + strings.TrimSpace(provider.Model)},
			},
			rulesAugmentTraceStep{
				Stage:   "reasoning",
				Status:  "running",
				Title:   "生成规则草案",
				Summary: "正在将规则描述映射为规则名称、风险等级、匹配模式和命中原因。",
				Details: []string{"输出仅包含结构化规则草案，不包含私有推理内容。"},
			},
		)

		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		responseText, err := client.Complete(ctx, rulesAugmentSystemPrompt(), rulesAugmentUserPrompt(description, req.CurrentRule))
		if err != nil {
			trace[len(trace)-1].Status = "failed"
			trace[len(trace)-1].Summary = "LLM 生成规则草案失败。"
			trace[len(trace)-1].Details = append(trace[len(trace)-1].Details, err.Error())
			sendJSON(w, http.StatusBadGateway, map[string]interface{}{
				"error": "LLM 生成规则草案失败",
				"trace": trace,
			})
			return
		}

		var draft rulesAugmentDraft
		if err := json.Unmarshal([]byte(llm.ExtractJSON(responseText)), &draft); err != nil {
			trace[len(trace)-1].Status = "failed"
			trace[len(trace)-1].Summary = "LLM 返回内容无法解析为规则草案。"
			trace[len(trace)-1].Details = append(trace[len(trace)-1].Details, err.Error())
			sendJSON(w, http.StatusBadGateway, map[string]interface{}{
				"error": "LLM 返回的规则草案无效",
				"trace": trace,
			})
			return
		}

		draft.Name = strings.TrimSpace(draft.Name)
		draft.Severity = normalizeRuleDraftSeverity(draft.Severity)
		draft.Reason = strings.TrimSpace(draft.Reason)
		patterns := make([]string, 0, len(draft.Patterns))
		for _, pattern := range draft.Patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			patterns = append(patterns, pattern)
		}
		draft.Patterns = patterns
		if draft.Name == "" || len(draft.Patterns) == 0 {
			trace[len(trace)-1].Status = "failed"
			trace[len(trace)-1].Summary = "LLM 草案缺少必要字段。"
			trace[len(trace)-1].Details = append(trace[len(trace)-1].Details, "需要同时生成 name 和 patterns")
			sendJSON(w, http.StatusBadGateway, map[string]interface{}{
				"error": "LLM 草案不完整，请重试或改用手动填写",
				"trace": trace,
			})
			return
		}

		trace[len(trace)-1].Status = "completed"
		trace[len(trace)-1].Summary = "已生成可确认的结构化规则草案。"
		trace[len(trace)-1].Details = append(trace[len(trace)-1].Details,
			"规则名称: "+draft.Name,
			"风险等级: "+draft.Severity,
			fmt.Sprintf("模式数量: %d", len(draft.Patterns)),
		)
		trace = append(trace, rulesAugmentTraceStep{
			Stage:   "confirm",
			Status:  "completed",
			Title:   "等待用户确认",
			Summary: "规则草案已生成，用户确认后可直接加入自定义规则列表。",
			Details: []string{"如需调整，可继续编辑名称、等级、匹配模式或命中原因。"},
		})

		sendJSON(w, http.StatusOK, rulesAugmentResponse{Draft: draft, Trace: trace})
	}
}

func rulesAugmentSystemPrompt() string {
	return strings.TrimSpace(`你是规则生成助手。你的任务是把用户提供的风险描述转换为一个技能扫描器自定义规则草案。

输出要求：
1. 只输出一个 JSON 对象。
2. 字段固定为 name、severity、patterns、reason。
3. severity 只能是 高风险、中风险、低风险 之一。
4. patterns 必须是字符串数组，内容为可直接用于正则匹配的模式。
5. 规则名称要简洁明确，命中原因要说明该规则想拦截什么风险。
6. 生成结果必须以用户的自然语言需求为最高优先级，已填写规则只作为可选参考。
7. 不要输出 Markdown，不要输出解释性文字。`)
}

func rulesAugmentUserPrompt(description string, current rulesAugmentDraft) string {
	var b strings.Builder
	b.WriteString("请根据以下用户需求生成规则草案，必须优先满足用户需求。\n")
	b.WriteString("用户需求：\n")
	b.WriteString(strings.TrimSpace(description))
	b.WriteString("\n")
	current.Name = strings.TrimSpace(current.Name)
	current.Severity = normalizeRuleDraftSeverity(current.Severity)
	current.Reason = strings.TrimSpace(current.Reason)
	patterns := make([]string, 0, len(current.Patterns))
	for _, pattern := range current.Patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern != "" {
			patterns = append(patterns, pattern)
		}
	}
	if current.Name != "" || current.Reason != "" || len(patterns) > 0 {
		b.WriteString("\n用户已填写的规则草案，可作为参考：\n")
		if current.Name != "" {
			b.WriteString("名称：")
			b.WriteString(current.Name)
			b.WriteString("\n")
		}
		b.WriteString("风险等级：")
		b.WriteString(current.Severity)
		b.WriteString("\n")
		if len(patterns) > 0 {
			b.WriteString("匹配模式：")
			b.WriteString(strings.Join(patterns, "；"))
			b.WriteString("\n")
		}
		if current.Reason != "" {
			b.WriteString("命中原因：")
			b.WriteString(current.Reason)
			b.WriteString("\n")
		}
	}
	return strings.TrimSpace(b.String())
}

func normalizeRuleDraftSeverity(value string) string {
	switch strings.TrimSpace(value) {
	case "高风险", "high", "High", "HIGH":
		return "高风险"
	case "低风险", "low", "Low", "LOW":
		return "低风险"
	default:
		return "中风险"
	}
}
