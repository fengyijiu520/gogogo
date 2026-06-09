package ti

import "strings"

var policyBlacklistProvider policyBlacklistProviderAPI = defaultPolicyBlacklistProvider{}

type policyBlacklistProviderAPI interface {
	ListPolicyBlacklist() []string
}

type defaultPolicyBlacklistProvider struct{}

func (defaultPolicyBlacklistProvider) ListPolicyBlacklist() []string { return nil }

func SetPolicyBlacklistProvider(provider policyBlacklistProviderAPI) {
	if provider == nil {
		policyBlacklistProvider = defaultPolicyBlacklistProvider{}
		return
	}
	policyBlacklistProvider = provider
}

func currentPolicyBlacklist() []string {
	items := policyBlacklistProvider.ListPolicyBlacklist()
	out := make([]string, 0, len(items))
	for _, item := range items {
		n := strings.ToLower(strings.TrimSpace(item))
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}
