package ti

import (
	"context"
	"net"
	"net/url"
	"path"
	"strings"

	"skill-scanner/internal/review"
)

type localProvider struct{}

func newLocalProvider() Provider {
	return &localProvider{}
}

func (p *localProvider) Name() string {
	return "local"
}

func (p *localProvider) Query(_ context.Context, targets []string) ([]review.TIReputation, error) {
	out := make([]review.TIReputation, 0, len(targets))
	for _, target := range targets {
		t := strings.ToLower(target)
		rep := review.TIReputation{
			Target:     target,
			Reputation: "unknown",
			Confidence: 0.5,
			Source:     p.Name(),
			Reason:     "未命中本地信誉规则",
		}

		switch {
		case isDisallowedPolicyTarget(t):
			rep.Reputation = "policy"
			rep.Confidence = 0.9
			rep.Reason = "命中公司黑名单目标（域名/IP）；该判定表示业务策略风险，不等同于破坏性恶意代码"
		case strings.Contains(t, "pastebin"), strings.Contains(t, "anonfiles"), strings.Contains(t, "transfer.sh"):
			rep.Reputation = "suspicious"
			rep.Confidence = 0.8
			rep.Reason = "疑似数据外传通道"
		case isKnownThreatInfra(t):
			rep.Reputation = "malicious"
			rep.Confidence = 0.95
			rep.Reason = "命中本地高危威胁情报（C2/钓鱼/矿池/APT 基础设施）"
		case isKnownMalwareHash(t):
			rep.Reputation = "malicious"
			rep.Confidence = 0.97
			rep.Reason = "命中已知恶意样本哈希"
		case isLocalDevelopmentTarget(t):
			rep.Reputation = "internal"
			rep.Confidence = 0.9
			rep.Reason = "本地环回目标"
		default:
			if gRep, ok := evaluateGitHubTarget(target); ok {
				rep = gRep
				break
			}
			if strings.Contains(t, "http://") {
				rep.Reputation = "benign"
				rep.Confidence = 0.6
				rep.Reason = "检测到非 TLS 网络目标；建议结合业务必要性评估并升级为 HTTPS，但该信号不等同于恶意外联"
			}
		}

		out = append(out, rep)
	}
	return out, nil
}

func isKnownThreatInfra(target string) bool {
	indicators := []string{
		"c2.",
		"cnc.",
		"command-and-control",
		"evilginx",
		"phishing",
		"phish",
		"xmr.pool",
		"minexmr",
		"nanopool",
		"stratum+tcp",
		"apt",
		"mimikatz-c2",
	}
	for _, item := range indicators {
		if strings.Contains(target, item) {
			return true
		}
	}
	return false
}

func isKnownMalwareHash(target string) bool {
	t := strings.TrimSpace(strings.ToLower(target))
	if len(t) != 64 {
		return false
	}
	for _, ch := range t {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	known := map[string]struct{}{
		"44d88612fea8a8f36de82e1278abb02f9a5f7f1b7f0bcd8ea4f0f9a5f6d2e6e3": {},
		"275a021bbfb6484f4e7ae6f8c4f98f26f4f1a6b6f5a59f18f3b8dbf8c56b8f6b": {},
		"5f4dcc3b5aa765d61d8327deb882cf99cfd8e1a5c2f82a6d9e6db8dbf0f4b1d2": {},
	}
	_, ok := known[t]
	return ok
}

func isLocalDevelopmentTarget(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	return strings.Contains(target, "0.0.0.0") ||
		strings.Contains(target, "127.0.0.1") ||
		strings.Contains(target, "localhost") ||
		strings.Contains(target, "::1")
}

func isDisallowedPolicyTarget(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	host := extractTargetHost(target)
	hostIP := net.ParseIP(host)
	if hostIP == nil {
		hostIP = net.ParseIP(target)
	}
	for _, raw := range currentPolicyBlacklist() {
		item := strings.ToLower(strings.TrimSpace(raw))
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			if hostIP == nil {
				continue
			}
			_, cidr, err := net.ParseCIDR(item)
			if err == nil && cidr.Contains(hostIP) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			if hostIP != nil && hostIP.Equal(ip) {
				return true
			}
			continue
		}
		if host != "" && (host == item || strings.HasSuffix(host, "."+item)) {
			return true
		}
	}
	return false
}

func extractTargetHost(target string) string {
	u, err := url.Parse(target)
	if err == nil && strings.TrimSpace(u.Hostname()) != "" {
		return strings.ToLower(strings.TrimSpace(u.Hostname()))
	}
	t := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"))
	if idx := strings.IndexAny(t, "/:"); idx >= 0 {
		t = t[:idx]
	}
	return strings.ToLower(strings.TrimSpace(t))
}

func evaluateGitHubTarget(target string) (review.TIReputation, bool) {
	u, err := url.Parse(target)
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return review.TIReputation{}, false
	}

	host := strings.ToLower(strings.TrimSpace(u.Host))
	p := strings.TrimSpace(path.Clean(u.Path))
	if p == "." {
		p = "/"
	}

	if host == "raw.githubusercontent.com" {
		return review.TIReputation{
			Target:     target,
			Reputation: "suspicious",
			Confidence: 0.8,
			Source:     "local",
			ThreatType: "download-stager",
			Reason:     "检测到 GitHub Raw 直链，可能用于下载脚本或二进制，请审计下载后行为",
		}, true
	}

	if host != "github.com" {
		return review.TIReputation{}, false
	}

	lowerPath := strings.ToLower(p)
	if strings.Contains(lowerPath, "/releases/download/") || strings.HasSuffix(lowerPath, ".zip") || strings.HasSuffix(lowerPath, ".tar.gz") || strings.HasSuffix(lowerPath, ".tgz") {
		return review.TIReputation{
			Target:     target,
			Reputation: "suspicious",
			Confidence: 0.78,
			Source:     "local",
			ThreatType: "download-artifact",
			Reason:     "检测到 GitHub 下载型链接，需结合下载与执行链路审计",
		}, true
	}

	if isLikelyRepoLanding(lowerPath) {
		return review.TIReputation{
			Target:     target,
			Reputation: "trusted",
			Confidence: 0.6,
			Source:     "local",
			Reason:     "代码托管平台链接（仅表示平台信誉，不代表仓库内容安全）",
		}, true
	}

	return review.TIReputation{
		Target:     target,
		Reputation: "unknown",
		Confidence: 0.55,
		Source:     "local",
		Reason:     "GitHub 非标准仓库展示路径，需结合调用行为进一步判断",
	}, true
}

func isLikelyRepoLanding(cleanPath string) bool {
	trimmed := strings.Trim(cleanPath, "/")
	if trimmed == "" {
		return true
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) <= 2 {
		return true
	}
	if len(parts) >= 3 && parts[2] == "tree" {
		return true
	}
	if len(parts) >= 3 && parts[2] == "blob" {
		return true
	}
	return false
}
