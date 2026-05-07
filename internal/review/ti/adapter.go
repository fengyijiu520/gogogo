package ti

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"skill-scanner/internal/review"
)

type Adapter struct {
	providers []Provider
	timeout   time.Duration
}

func NewAdapter() *Adapter {
	timeout := readTimeoutFromEnv("REVIEW_TI_TIMEOUT_MS", 2500)
	verifyTLS := readBoolFromEnv("REVIEW_TI_VERIFY_TLS", true)

	providers := make([]Provider, 0, 3)
	for _, name := range readProviderOrder() {
		switch name {
		case "misp":
			baseURL := strings.TrimSpace(os.Getenv("REVIEW_TI_MISP_URL"))
			apiKey := strings.TrimSpace(os.Getenv("REVIEW_TI_MISP_API_KEY"))
			if baseURL != "" && apiKey != "" {
				providers = append(providers, newMISPProvider(baseURL, apiKey, verifyTLS))
			}
		case "opencti":
			baseURL := strings.TrimSpace(os.Getenv("REVIEW_TI_OPENCTI_URL"))
			token := strings.TrimSpace(os.Getenv("REVIEW_TI_OPENCTI_TOKEN"))
			if baseURL != "" && token != "" {
				providers = append(providers, newOpenCTIProvider(baseURL, token, verifyTLS))
			}
		case "local":
			providers = append(providers, newLocalProvider())
		}
	}

	if len(providers) == 0 {
		providers = append(providers, newLocalProvider())
	}

	return &Adapter{
		providers: providers,
		timeout:   timeout,
	}
}

func (a *Adapter) Query(targets []string) ([]review.TIReputation, bool, float64) {
	normalized := normalizeTargets(targets)
	if len(normalized) == 0 {
		return nil, false, 0
	}

	merged := make(map[string]review.TIReputation, len(normalized))
	success := false

	for _, p := range a.providers {
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		reputations, err := p.Query(ctx, normalized)
		cancel()
		if err != nil {
			continue
		}
		success = true
		mergeReputations(merged, reputations)
	}

	if !success {
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		reputations, err := newLocalProvider().Query(ctx, normalized)
		cancel()
		if err == nil {
			mergeReputations(merged, reputations)
		}
	}

	if len(merged) == 0 {
		return nil, false, 0
	}

	out := make([]review.TIReputation, 0, len(normalized))
	malicious := false
	adjustment := 0.0

	for _, target := range normalized {
		rep, ok := merged[target]
		if !ok {
			rep = review.TIReputation{
				Target:     target,
				Reputation: "unknown",
				Confidence: 0.4,
				Reason:     "未获得有效情报结果",
			}
		}

		adjustment += scoreAdjustment(rep)
		if isThreatReputation(rep.Reputation) && rep.Confidence >= 0.85 {
			malicious = true
		}
		out = append(out, rep)
	}

	if adjustment < -30 {
		adjustment = -30
	}
	if adjustment > 10 {
		adjustment = 10
	}

	return out, malicious, adjustment
}

func readProviderOrder() []string {
	raw := strings.TrimSpace(os.Getenv("REVIEW_TI_PROVIDERS"))
	if raw == "" {
		return []string{"misp", "opencti", "local"}
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		name := strings.ToLower(strings.TrimSpace(p))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return []string{"local"}
	}
	return out
}

func readTimeoutFromEnv(key string, fallbackMs int) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return time.Duration(fallbackMs) * time.Millisecond
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return time.Duration(fallbackMs) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

func readBoolFromEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func normalizeTargets(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func mergeReputations(merged map[string]review.TIReputation, items []review.TIReputation) {
	for _, item := range items {
		item.Target = strings.TrimSpace(item.Target)
		if item.Target == "" {
			continue
		}
		if item.Confidence < 0 {
			item.Confidence = 0
		}
		if item.Confidence > 1 {
			item.Confidence = 1
		}

		current, ok := merged[item.Target]
		if !ok || compareReputation(item, current) > 0 {
			merged[item.Target] = item
		}
	}
}

func compareReputation(a, b review.TIReputation) int {
	aRank := reputationRank(a.Reputation)
	bRank := reputationRank(b.Reputation)
	if aRank != bRank {
		if aRank > bRank {
			return 1
		}
		return -1
	}
	if a.Confidence > b.Confidence {
		return 1
	}
	if a.Confidence < b.Confidence {
		return -1
	}
	return 0
}

func reputationRank(rep string) int {
	switch strings.ToLower(strings.TrimSpace(rep)) {
	case "malicious", "high-risk":
		return 6
	case "suspicious":
		return 5
	case "policy":
		return 4
	case "unknown":
		return 3
	case "internal":
		return 2
	case "trusted", "benign":
		return 1
	default:
		return 0
	}
}

func scoreAdjustment(rep review.TIReputation) float64 {
	conf := rep.Confidence
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}

	switch strings.ToLower(strings.TrimSpace(rep.Reputation)) {
	case "malicious", "high-risk":
		return -10 * conf
	case "suspicious":
		return -8 * conf
	case "policy":
		return -3 * conf
	case "unknown":
		return -1
	case "trusted", "internal", "benign":
		return 2 * conf
	default:
		return 0
	}
}

func isThreatReputation(rep string) bool {
	switch strings.ToLower(strings.TrimSpace(rep)) {
	case "malicious", "high-risk", "suspicious":
		return true
	default:
		return false
	}
}
