package ti

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	"skill-scanner/internal/review"
)

type stubProvider struct {
	name string
	data []review.TIReputation
}

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Query(_ context.Context, _ []string) ([]review.TIReputation, error) {
	return s.data, nil
}

func TestNormalizeTargetsExpandsURLAndHashVariants(t *testing.T) {
	in := []string{
		"https://Example.com/path?a=1",
		"44D88612FEA8A8F36DE82E1278ABB02F9A5F7F1B7F0BCD8EA4F0F9A5F6D2E6E3",
	}
	out := normalizeTargets(in)
	if len(out) < 4 {
		t.Fatalf("expected expanded targets, got %v", out)
	}
	assertContains := func(want string) {
		for _, item := range out {
			if item == want {
				return
			}
		}
		t.Fatalf("expected target %q in %v", want, out)
	}
	assertContains("https://example.com/path?a=1")
	assertContains("example.com")
	assertContains("example.com/path")
	assertContains("44d88612fea8a8f36de82e1278abb02f9a5f7f1b7f0bcd8ea4f0f9a5f6d2e6e3")
}

func TestAdapterAddsSourceWithoutPollutingReason(t *testing.T) {
	a := &Adapter{
		providers: []Provider{stubProvider{name: "misp", data: []review.TIReputation{{
			Target:     "example.com",
			Reputation: "suspicious",
			Confidence: 0.9,
			Reason:     "命中测试规则",
		}}}},
		timeout:  100,
		cacheTTL: 0,
		cache:    map[string]cachedReputation{},
	}
	out, _, _ := a.Query([]string{"example.com"})
	if len(out) != 1 {
		t.Fatalf("expected one result, got %d", len(out))
	}
	if out[0].Source != "misp" {
		t.Fatalf("expected source misp, got %q", out[0].Source)
	}
	if out[0].Reason != "命中测试规则" {
		t.Fatalf("expected clean reason, got %q", out[0].Reason)
	}
}

func TestThreatIntelProvidersForceTLS12OrHigher(t *testing.T) {
	providers := []Provider{
		newMISPProvider("https://misp.example.com", "token", false),
		newOpenCTIProvider("https://opencti.example.com", "token", false),
	}
	for _, provider := range providers {
		switch p := provider.(type) {
		case *mispProvider:
			cfg := p.client.Transport.(*http.Transport).TLSClientConfig
			if cfg == nil || cfg.MinVersion < tls.VersionTLS12 {
				t.Fatalf("expected misp provider to enforce tls1.2+, got %+v", cfg)
			}
		case *openCTIProvider:
			cfg := p.client.Transport.(*http.Transport).TLSClientConfig
			if cfg == nil || cfg.MinVersion < tls.VersionTLS12 {
				t.Fatalf("expected opencti provider to enforce tls1.2+, got %+v", cfg)
			}
		}
	}
}
