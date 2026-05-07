package ti

import (
	"context"
	"testing"
)

func TestLocalProviderFlagsPolymarketAsPolicyRisk(t *testing.T) {
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
}

func TestLocalProviderFlagsUSDCAddressAsPolicyRisk(t *testing.T) {
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
