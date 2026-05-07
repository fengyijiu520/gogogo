package plugins

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// SecretDetector scans files for hardcoded secrets such as passwords,
// API keys, and private keys.
type SecretDetector struct{}

// NewSecretDetector returns a new SecretDetector.
func NewSecretDetector() *SecretDetector {
	return &SecretDetector{}
}

// Name implements Plugin.
func (p *SecretDetector) Name() string {
	return "SecretDetector"
}

// Execute implements Plugin.
func (p *SecretDetector) Execute(ctx context.Context, scanPath string) ([]Finding, error) {
	patterns := map[string]*regexp.Regexp{
		"AWS密钥":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"私钥":     regexp.MustCompile(`-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----`),
		"通用密码":  regexp.MustCompile(`(?i)(password|passwd|secret)\s*=\s*['"][^'"]+['"]`),
	}

	var findings []Finding

	if err := filepath.Walk(scanPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		for ruleName, re := range patterns {
			if re.MatchString(content) {
				findings = append(findings, Finding{
					PluginName:  p.Name(),
					RuleID:      "SEC-001",
					Severity:    "高风险",
					Title:       "发现硬编码凭证",
					Description: ruleName,
					Location:    path,
				})
				break // one finding per file per rule set
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return findings, nil
}
