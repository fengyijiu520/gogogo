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

type openCTIProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func newOpenCTIProvider(baseURL, token string, verifyTLS bool) Provider {
	_ = verifyTLS
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return &openCTIProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Transport: tr},
	}
}

func (p *openCTIProvider) Name() string {
	return "opencti"
}

func (p *openCTIProvider) Query(ctx context.Context, targets []string) ([]review.TIReputation, error) {
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
	var firstErr error
	for item := range results {
		if item.err != nil {
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
	return out, nil
}

func (p *openCTIProvider) queryOne(ctx context.Context, target string) (review.TIReputation, error) {
	gql := map[string]interface{}{
		"query": `query ObservableSearch($search: String!) {
  stixCyberObservables(search: $search, first: 5) {
    edges {
      node {
        id
        entity_type
      }
    }
  }
}`,
		"variables": map[string]interface{}{"search": target},
	}
	body, _ := json.Marshal(gql)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return review.TIReputation{}, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return review.TIReputation{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return review.TIReputation{}, fmt.Errorf("opencti status %d", resp.StatusCode)
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
		Reason:     "OpenCTI 未命中",
	}

	data, _ := raw["data"].(map[string]interface{})
	obs, _ := data["stixCyberObservables"].(map[string]interface{})
	edges, _ := obs["edges"].([]interface{})
	if len(edges) > 0 {
		rep.Reputation = "suspicious"
		rep.Confidence = 0.85
		rep.ThreatType = "observable-hit"
		rep.Reason = "OpenCTI 命中可观测对象"
	}

	return rep, nil
}
