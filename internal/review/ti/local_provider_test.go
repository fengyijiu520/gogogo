package ti

import (
	"context"
	"testing"
)

type stubPolicyBlacklistProvider struct{ items []string }

func (s stubPolicyBlacklistProvider) ListPolicyBlacklist() []string { return s.items }

func TestLocalProviderFlagsPolymarketAsPolicyRisk(t *testing.T) {
	SetPolicyBlacklistProvider(stubPolicyBlacklistProvider{items: []string{"polymarket.com"}})
	defer SetPolicyBlacklistProvider(nil)
	provider := newLocalProvider()
	reps, err := provider.Query(context.Background(), []string{"https://clob.polymarket.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation != "policy" || reps[0].Confidence < 0.85 {
		t.Fatalf("expected high-confidence policy risk, got %+v", reps[0])
	}
	if reps[0].Reason == "" {
		t.Fatalf("expected policy reason")
	}
	if reps[0].Source != "local" {
		t.Fatalf("expected source local, got %+v", reps[0])
	}
}

func TestLocalProviderFlagsUSDCAddressAsPolicyRisk(t *testing.T) {
	SetPolicyBlacklistProvider(stubPolicyBlacklistProvider{items: []string{"0x2791bca1f2de4661ed88a30c99a7a9449aa84174"}})
	defer SetPolicyBlacklistProvider(nil)
	provider := newLocalProvider()
	reps, err := provider.Query(context.Background(), []string{"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation != "policy" || reps[0].Confidence < 0.85 {
		t.Fatalf("expected high-confidence policy risk, got %+v", reps[0])
	}
}

func TestLocalProviderNoBlacklistMeansNoPolicyFallback(t *testing.T) {
	SetPolicyBlacklistProvider(stubPolicyBlacklistProvider{items: []string{}})
	defer SetPolicyBlacklistProvider(nil)
	provider := newLocalProvider()
	reps, err := provider.Query(context.Background(), []string{"https://clob.polymarket.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation == "policy" {
		t.Fatalf("expected no policy fallback when blacklist is empty, got %+v", reps[0])
	}
}

func TestLocalProviderTreatsLocalhostAsInternal(t *testing.T) {
	provider := newLocalProvider()
	reps, err := provider.Query(context.Background(), []string{"http://localhost:3000/api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation != "internal" {
		t.Fatalf("expected localhost to be internal, got %+v", reps[0])
	}
}

func TestLocalProviderTreatsPlainHTTPAsNonThreat(t *testing.T) {
	provider := newLocalProvider()
	reps, err := provider.Query(context.Background(), []string{"http://example.com/api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation != "benign" {
		t.Fatalf("expected plain http to be non-threat hygiene signal, got %+v", reps[0])
	}
}

func TestLocalProviderFlagsKnownThreatInfra(t *testing.T) {
	provider := newLocalProvider()
	reps, err := provider.Query(context.Background(), []string{"https://c2.evilginx-phish.example/login"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation != "malicious" || reps[0].Confidence < 0.9 {
		t.Fatalf("expected malicious threat infra, got %+v", reps[0])
	}
}

func TestLocalProviderFlagsKnownMalwareHash(t *testing.T) {
	provider := newLocalProvider()
	h := "44d88612fea8a8f36de82e1278abb02f9a5f7f1b7f0bcd8ea4f0f9a5f6d2e6e3"
	reps, err := provider.Query(context.Background(), []string{h})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected one reputation, got %d", len(reps))
	}
	if reps[0].Reputation != "malicious" || reps[0].Confidence < 0.95 {
		t.Fatalf("expected malicious hash hit, got %+v", reps[0])
	}
}
