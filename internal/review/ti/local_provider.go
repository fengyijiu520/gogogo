package ti

import (
	"context"
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
			Reason:     "未命中本地信誉规则",
		}

		switch {
		case isDisallowedCryptoPolicyTarget(t):
			rep.Reputation = "policy"
			rep.Confidence = 0.9
			rep.Reason = "命中公司准入策略禁止的加密资产或预测市场相关目标；该判定表示业务策略风险，不等同于破坏性恶意代码"
		case strings.Contains(t, "pastebin"), strings.Contains(t, "anonfiles"), strings.Contains(t, "transfer.sh"):
			rep.Reputation = "suspicious"
			rep.Confidence = 0.8
			rep.Reason = "疑似数据外传通道"
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

func isLocalDevelopmentTarget(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	return strings.Contains(target, "0.0.0.0") ||
		strings.Contains(target, "127.0.0.1") ||
		strings.Contains(target, "localhost") ||
		strings.Contains(target, "::1")
}

func isDisallowedCryptoPolicyTarget(target string) bool {
	return strings.Contains(target, "clob.polymarket.com") ||
		strings.Contains(target, "polymarket.com") ||
		strings.Contains(target, "0x2791bca1f2de4661ed88a30c99a7a9449aa84174") ||
		strings.Contains(target, "usdc")
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
			Reason:     "检测到 GitHub 下载型链接，需结合下载与执行链路审计",
		}, true
	}

	if isLikelyRepoLanding(lowerPath) {
		return review.TIReputation{
			Target:     target,
			Reputation: "trusted",
			Confidence: 0.6,
			Reason:     "代码托管平台链接（仅表示平台信誉，不代表仓库内容安全）",
		}, true
	}

	return review.TIReputation{
		Target:     target,
		Reputation: "unknown",
		Confidence: 0.55,
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
