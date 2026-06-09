package config

import "testing"

func TestLoadReviewPolicy(t *testing.T) {
	cfg, err := LoadReviewPolicy("../../config/review_policies.yaml")
	if err != nil {
		t.Fatalf("expected review policy load success, got %v", err)
	}
	if cfg.Version == "" {
		t.Fatalf("expected version populated")
	}
	if len(cfg.ThreatSignals) == 0 {
		t.Fatalf("expected threat signals populated")
	}
	if len(cfg.FalsePositive.EvidenceIntentMismatchMarkers) == 0 {
		t.Fatalf("expected mismatch markers populated")
	}
	if len(cfg.EffectiveWeakStaticTitles()) == 0 {
		t.Fatalf("expected effective weak static titles populated")
	}
	if len(cfg.EffectiveOpenWeakTitles()) == 0 {
		t.Fatalf("expected effective open weak titles populated")
	}
	if len(cfg.EffectiveEvidenceIntentMismatchMarkers()) == 0 {
		t.Fatalf("expected effective mismatch markers populated")
	}
	if len(cfg.RefutedPrimaryClaimMarkers("资源耗尽与级联失败-无限循环/无超时")) == 0 {
		t.Fatalf("expected refuted primary claim index populated")
	}
	if len(cfg.CategoryRefutationMarkers("隐私合规与数据最小化")) == 0 {
		t.Fatalf("expected category refutation index populated")
	}
	if len(cfg.ScanAsync.DirectConfirmation.SSRF.RequestCall) == 0 {
		t.Fatalf("expected scan_async ssrf policy populated")
	}
	if cfg.RequiresRuntimeClosure("外联与情报", true, []string{"外联与情报", "凭据访问", "凭据暴露"}) {
		t.Fatalf("expected runtime closure override populated")
	}
	if len(cfg.EffectiveRuntimeClosureCategoriesWithoutRuntime()) == 0 {
		t.Fatalf("expected effective runtime closure categories populated")
	}
	if threshold, ok := cfg.WeakStaticThreshold("静态规则发现"); !ok || threshold.MissingThreshold != 3 || !threshold.RequireOpenClosure {
		t.Fatalf("expected weak static threshold populated")
	}
	if !cfg.IsOpenWeakCategory("声明与行为差异", []string{"环境与构建风险"}) {
		t.Fatalf("expected open weak category populated")
	}
	if !cfg.IsEvidenceIntentMismatchCategory("静态规则发现", []string{"环境与构建风险"}) {
		t.Fatalf("expected evidence intent mismatch categories populated")
	}
	if len(cfg.CategoryRefutationMarkers("暴露面与未鉴权服务")) == 0 {
		t.Fatalf("expected exposure refutation markers populated")
	}
	if len(cfg.ClosureSignals("外联与情报").Sink) == 0 {
		t.Fatalf("expected closure signal index populated")
	}
}
