package handler

import (
	"testing"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/review"
)

func TestBuildTraceMetadataSummaryIncludesCrossFileConsolidation(t *testing.T) {
	base := baseScanOutput{taskID: "task-1"}
	refined := review.Result{
		CrossFileConsolidation: &llm.CrossFileConsolidation{
			Summary:           "跨文件链路研判: 已识别 source-sink-runtime 组合信号，建议优先检查跨文件调用链。",
			RelatedCategories: []string{"外联与情报"},
		},
	}
	summary := buildTraceMetadataSummary(base, refined, map[string]int{"high": 1, "medium": 0, "low": 0})
	if summary == nil {
		t.Fatal("expected trace metadata summary")
	}
	value, ok := summary["cross_file_consolidation"].(*llm.CrossFileConsolidation)
	if !ok || value == nil || value.Summary == "" {
		t.Fatalf("expected cross-file consolidation in trace metadata, got %+v", summary["cross_file_consolidation"])
	}
}
