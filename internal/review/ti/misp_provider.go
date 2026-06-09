package ti

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"skill-scanner/internal/review"
)

type mispProvider struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func newMISPProvider(baseURL, apiKey string, verifyTLS bool) Provider {
	_ = verifyTLS
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
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
	if len(targets) == 0 {
		return nil, nil
	}
	type result struct {
		rep review.TIReputation
		err error
	}
	jobs := make(chan string)
	results := make(chan result, len(targets))
	worker := func() {
		for target := range jobs {
			rep, err := p.queryOne(ctx, target)
			results <- result{rep: rep, err: err}
		}
	}
	workers := 4
	if len(targets) < workers {
		workers = len(targets)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker()
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	close(results)

	out := make([]review.TIReputation, 0, len(targets))
	errCount := 0
	var firstErr error
	for item := range results {
		if item.err != nil {
			errCount++
			if firstErr == nil {
				firstErr = item.err
			}
			continue
		}
		out = append(out, item.rep)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	if errCount > 0 {
		out = append(out, review.TIReputation{Target: "provider:misp", Reputation: "unknown", Confidence: 0.4, Source: "misp", Reason: fmt.Sprintf("MISP 部分查询失败：%d/%d", errCount, len(targets))})
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
		Source:     p.Name(),
		Reason:     "MISP 未命中",
	}

	response, _ := raw["response"].(map[string]interface{})
	attrs := extractArray(response, "Attribute")
	if len(attrs) > 0 {
		rep.Reputation = "suspicious"
		rep.Confidence = 0.9
		rep.ThreatType = "ioc-match"
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
