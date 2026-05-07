package ti

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"skill-scanner/internal/review"
)

type mispProvider struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func newMISPProvider(baseURL, apiKey string, verifyTLS bool) Provider {
	tr := &http.Transport{}
	if !verifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &mispProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Transport: tr},
	}
}

func (p *mispProvider) Name() string {
	return "misp"
}

func (p *mispProvider) Query(ctx context.Context, targets []string) ([]review.TIReputation, error) {
	out := make([]review.TIReputation, 0, len(targets))
	for _, target := range targets {
		rep, err := p.queryOne(ctx, target)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, nil
}

func (p *mispProvider) queryOne(ctx context.Context, target string) (review.TIReputation, error) {
	payload := map[string]interface{}{
		"returnFormat": "json",
		"value":        target,
		"limit":        3,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/attributes/restSearch", bytes.NewReader(body))
	if err != nil {
		return review.TIReputation{}, err
	}
	req.Header.Set("Authorization", p.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return review.TIReputation{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return review.TIReputation{}, fmt.Errorf("misp status %d", resp.StatusCode)
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return review.TIReputation{}, err
	}

	rep := review.TIReputation{
		Target:     target,
		Reputation: "unknown",
		Confidence: 0.6,
		Reason:     "MISP 未命中",
	}

	response, _ := raw["response"].(map[string]interface{})
	attrs := extractArray(response, "Attribute")
	if len(attrs) > 0 {
		rep.Reputation = "suspicious"
		rep.Confidence = 0.9
		rep.Reason = "MISP 匹配到情报属性"
	}
	return rep, nil
}

func extractArray(obj map[string]interface{}, key string) []interface{} {
	if obj == nil {
		return nil
	}
	v, ok := obj[key]
	if !ok {
		return nil
	}
	arr, _ := v.([]interface{})
	return arr
}
