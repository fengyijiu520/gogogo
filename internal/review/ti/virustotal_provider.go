package ti

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"skill-scanner/internal/review"
)

type virustotalProvider struct {
	apiKey     string
	httpClient *http.Client
}

func newVirusTotalProvider(apiKey string, timeout time.Duration, verifyTLS bool) Provider {
	return &virustotalProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

func (p *virustotalProvider) Name() string {
	return "virustotal"
}

func (p *virustotalProvider) Query(ctx context.Context, targets []string) ([]review.TIReputation, error) {
	out := make([]review.TIReputation, 0, len(targets))
	for _, target := range targets {
		rep, err := p.querySingle(ctx, target)
		if err != nil {
			// 单个查询失败不阻断整体，标记为 unknown
			out = append(out, review.TIReputation{
				Target:     target,
				Reputation: "unknown",
				Confidence: 0.4,
				Source:     p.Name(),
				Reason:     fmt.Sprintf("VirusTotal 查询失败: %v", err),
			})
			continue
		}
		out = append(out, rep)
	}
	return out, nil
}

func (p *virustotalProvider) querySingle(ctx context.Context, target string) (review.TIReputation, error) {
	iocType, apiTarget := classifyIOC(target)
	if apiTarget == "" {
		return review.TIReputation{}, fmt.Errorf("无法识别 IoC 类型: %s", target)
	}

	apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", iocType, url.PathEscape(apiTarget))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return review.TIReputation{}, err
	}
	req.Header.Set("x-apikey", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return review.TIReputation{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return review.TIReputation{
			Target:     target,
			Reputation: "unknown",
			Confidence: 0.5,
			Source:     p.Name(),
			Reason:     "VirusTotal 无此目标记录",
		}, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return review.TIReputation{}, fmt.Errorf("VirusTotal API 速率限制 (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return review.TIReputation{}, fmt.Errorf("VirusTotal API 返回 %d", resp.StatusCode)
	}

	var body vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return review.TIReputation{}, fmt.Errorf("解析 VirusTotal 响应失败: %w", err)
	}

	return p.buildReputation(target, body), nil
}

func (p *virustotalProvider) buildReputation(target string, body vtResponse) review.TIReputation {
	attrs := body.Data.Attributes
	malicious := attrs.LastAnalysisStats.Malicious
	suspicious := attrs.LastAnalysisStats.Suspicious
	reputation := attrs.Reputation
	tags := attrs.Tags

	reason := fmt.Sprintf("VirusTotal: %d 恶意 / %d 可疑 / %d 未检出", malicious, suspicious, attrs.LastAnalysisStats.Undetected)
	if len(tags) > 0 {
		reason += "；标签: " + strings.Join(tags, ", ")
	}

	// 判定信誉等级
	var rep string
	var conf float64
	switch {
	case malicious >= 10 || reputation <= -50:
		rep = "malicious"
		conf = 0.95
	case malicious >= 5 || reputation <= -20:
		rep = "malicious"
		conf = 0.9
	case malicious >= 2 || suspicious >= 5 || reputation <= -10:
		rep = "suspicious"
		conf = 0.8
	case malicious >= 1 || suspicious >= 2:
		rep = "suspicious"
		conf = 0.7
	case containsHighRiskTag(tags):
		rep = "suspicious"
		conf = 0.65
	case reputation >= 50:
		rep = "trusted"
		conf = 0.7
	case reputation >= 0:
		rep = "benign"
		conf = 0.6
	default:
		rep = "unknown"
		conf = 0.5
	}

	return review.TIReputation{
		Target:     target,
		Reputation: rep,
		Confidence: conf,
		Source:     p.Name(),
		Reason:     reason,
	}
}

func containsHighRiskTag(tags []string) bool {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "malware", "c2", "command-and-control", "phishing", "tor", "cryptominer":
			return true
		}
	}
	return false
}

// classifyIOC 将目标分类为 VirusTotal API 路径类型
func classifyIOC(target string) (string, string) {
	target = strings.TrimSpace(target)

	// URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return "urls", target
	}

	// SHA256 hash
	if len(target) == 64 && isHex(target) {
		return "files", target
	}

	// IP address
	if ip := net.ParseIP(target); ip != nil {
		return "ip_addresses", target
	}

	// Domain (包含 . 且不是纯 IP)
	if strings.Contains(target, ".") && !strings.Contains(target, "/") {
		return "domains", target
	}

	return "", ""
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// vtResponse 精简的 VirusTotal API v3 响应结构
type vtResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Reputation        int      `json:"reputation"`
			Tags              []string `json:"tags"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}
