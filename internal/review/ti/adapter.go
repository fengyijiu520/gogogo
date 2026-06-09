package ti

import (
	"context"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"skill-scanner/internal/review"
)

type Adapter struct {
	providers []Provider
	timeout   time.Duration
	cacheTTL  time.Duration
	cacheMu   sync.Mutex
	cache     map[string]cachedReputation
}

type cachedReputation struct {
	Item      review.TIReputation
	ExpiredAt time.Time
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
		case "virustotal":
			apiKey := strings.TrimSpace(os.Getenv("REVIEW_TI_VT_API_KEY"))
			if apiKey != "" {
				providers = append(providers, newVirusTotalProvider(apiKey, timeout, verifyTLS))
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
		cacheTTL:  readTimeoutFromEnv("REVIEW_TI_CACHE_TTL_MS", 300000),
		cache:     map[string]cachedReputation{},
	}
}

func (a *Adapter) Query(targets []string) ([]review.TIReputation, bool, float64) {
	normalized := normalizeTargets(targets)
	if len(normalized) == 0 {
		return nil, false, 0
	}

	merged := make(map[string]review.TIReputation, len(normalized))
	remaining := make([]string, 0, len(normalized))
	now := time.Now()
	for _, target := range normalized {
		if item, ok := a.getCachedReputation(target, now); ok {
			merged[target] = item
			continue
		}
		remaining = append(remaining, target)
	}
	success := false

	for _, p := range a.providers {
		if len(remaining) == 0 {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		reputations, err := p.Query(ctx, remaining)
		cancel()
		if err != nil {
			continue
		}
		success = true
		for i := range reputations {
			reason := strings.TrimSpace(reputations[i].Reason)
			if reason == "" {
				reason = "无说明"
			}
			reputations[i].Reason = reason
			if strings.TrimSpace(reputations[i].Source) == "" {
				reputations[i].Source = p.Name()
			}
		}
		mergeReputations(merged, reputations)
	}

	if !success {
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		reputations, err := newLocalProvider().Query(ctx, remaining)
		cancel()
		if err == nil {
			for i := range reputations {
				reason := strings.TrimSpace(reputations[i].Reason)
				if reason == "" {
					reason = "无说明"
				}
				reputations[i].Reason = reason
				if strings.TrimSpace(reputations[i].Source) == "" {
					reputations[i].Source = "local-fallback"
				}
			}
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
				Source:     "unresolved",
				Reason:     "未获得有效情报结果",
			}
		}

		adjustment += scoreAdjustment(rep)
		if isThreatReputation(rep.Reputation) && rep.Confidence >= 0.85 {
			malicious = true
		}
		a.setCachedReputation(target, rep, now)
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

func (a *Adapter) getCachedReputation(target string, now time.Time) (review.TIReputation, bool) {
	if a == nil || a.cacheTTL <= 0 {
		return review.TIReputation{}, false
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	item, ok := a.cache[target]
	if !ok || now.After(item.ExpiredAt) {
		if ok {
			delete(a.cache, target)
		}
		return review.TIReputation{}, false
	}
	return item.Item, true
}

func (a *Adapter) setCachedReputation(target string, rep review.TIReputation, now time.Time) {
	if a == nil || a.cacheTTL <= 0 {
		return
	}
	a.cacheMu.Lock()
	a.cache[target] = cachedReputation{Item: rep, ExpiredAt: now.Add(a.cacheTTL)}
	a.cacheMu.Unlock()
}

func readProviderOrder() []string {
	raw := strings.TrimSpace(os.Getenv("REVIEW_TI_PROVIDERS"))
	if raw == "" {
		return []string{"misp", "opencti", "virustotal", "local"}
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
	seen := make(map[string]struct{}, len(targets)*2)
	out := make([]string, 0, len(targets)*2)
	appendUnique := func(item string) {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			return
		}
		if _, ok := seen[item]; ok {
			return
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}

	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		appendUnique(raw)
		for _, item := range expandIOCVariants(raw) {
			appendUnique(item)
		}
	}
	return out
}

func expandIOCVariants(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	variants := make([]string, 0, 4)
	if u, err := url.Parse(target); err == nil && strings.TrimSpace(u.Host) != "" {
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host != "" {
			variants = append(variants, host)
		}
		if ip := net.ParseIP(host); ip != nil {
			variants = append(variants, ip.String())
		}
		if strings.TrimSpace(u.Path) != "" && strings.TrimSpace(u.Path) != "/" {
			variants = append(variants, host+strings.TrimSpace(u.Path))
		}
		return variants
	}

	trimmed := strings.ToLower(strings.TrimSpace(target))
	if ip := net.ParseIP(trimmed); ip != nil {
		variants = append(variants, ip.String())
	}
	if isLikelySHA256(trimmed) {
		variants = append(variants, trimmed)
	}
	return variants
}

func isLikelySHA256(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 64 {
		return false
	}
	for _, ch := range s {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
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
