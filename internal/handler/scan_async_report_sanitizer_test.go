package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/review"
)

func TestIncrementalCacheTraceDetailBoundaries(t *testing.T) {
	enabledZero := incrementalCacheStats{Enabled: true, Candidate: 0, Hit: 0, Miss: 0}
	hitRate := incrementalCacheHitRate(enabledZero)
	event := newAnalysisTraceEvent("incremental_cache", "completed", "增量扫描缓存统计", "")
	event.Detail = "模式:增量 候选:0 命中:0 未命中:0 命中率:" + "0.0%"
	if hitRate != 0.0 || !strings.Contains(event.Detail, "命中率:0.0%") {
		t.Fatalf("expected zero candidate detail with 0.0%%, hitRate=%v detail=%q", hitRate, event.Detail)
	}
}

func TestIncrementalCacheHitRateFunction(t *testing.T) {
	if got := incrementalCacheHitRate(incrementalCacheStats{Candidate: 0, Hit: 0}); got != 0 {
		t.Fatalf("expected zero candidate hit rate 0, got %v", got)
	}
	if got := incrementalCacheHitRate(incrementalCacheStats{Candidate: 10, Hit: 0}); got != 0 {
		t.Fatalf("expected zero hit rate 0, got %v", got)
	}
	if got := incrementalCacheHitRate(incrementalCacheStats{Candidate: 8, Hit: 6}); got < 74.9 || got > 75.1 {
		t.Fatalf("expected 75%% hit rate, got %v", got)
	}
}

func TestSanitizeReportResultRemovesInternalPathsAndCacheArtifacts(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:         "SF-001",
			RuleID:     "V7-003",
			Title:      "敏感数据外发与隐蔽通道",
			Severity:   "高风险",
			Category:   "外联与情报",
			AttackPath: "/home/admini/gogogo/data/tasks/e23d21cb72fb539e6f4d2df765cbec50/.scan-cache.json:1 | 外联=9；/home/admini/gogogo/data/tasks/e23d21cb72fb539e6f4d2df765cbec50/polymarket.py:23 | requests.post(url)",
			Evidence: []string{
				"证据引用: /home/admini/gogogo/data/tasks/e23d21cb72fb539e6f4d2df765cbec50/SKILL.md",
				"/home/admini/gogogo/data/tasks/e23d21cb72fb539e6f4d2df765cbec50/.scan-cache.json:1 | 行为证据摘要",
			},
		}},
	}
	cleaned := sanitizeReportResult(refined, "/home/admini/gogogo/data/tasks/e23d21cb72fb539e6f4d2df765cbec50")
	joined := cleaned.StructuredFindings[0].AttackPath + "\n" + strings.Join(cleaned.StructuredFindings[0].Evidence, "\n")
	if strings.Contains(joined, "/home/admini") || strings.Contains(joined, ".scan-cache.json") {
		t.Fatalf("expected internal paths and scan cache artifacts removed, got %q", joined)
	}
	if !strings.Contains(joined, "polymarket.py:23") || !strings.Contains(joined, "SKILL.md") {
		t.Fatalf("expected relative source evidence retained, got %q", joined)
	}
}

func TestBuildJSONReportPayloadSanitizesCachePathAndIncludesIntegritySummary(t *testing.T) {
	base := baseScanOutput{}
	base.cacheStats = incrementalCacheStats{Enabled: true, Candidate: 3, Hit: 2, Miss: 1, CacheFilePath: "/home/demo/tasks/abc/.scan-cache.json"}
	payload := buildJSONReportPayload("<html></html>", "text", nil, base, review.Result{})
	coverage, ok := payload["coverage"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected coverage object, got %#v", payload["coverage"])
	}
	cachePart, ok := coverage["incremental_cache"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected incremental_cache in coverage, got %#v", coverage["incremental_cache"])
	}
	if got := strings.TrimSpace(cachePart["cache_file"].(string)); got != ".scan-cache.json" {
		t.Fatalf("expected sanitized cache file path, got %q", got)
	}
	integrity, ok := coverage["report_integrity"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected report_integrity in coverage, got %#v", coverage["report_integrity"])
	}
	if strings.TrimSpace(integrity["status"].(string)) == "" {
		t.Fatalf("expected integrity status, got %#v", integrity)
	}
}
