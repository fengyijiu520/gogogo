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

type openCTIProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func newOpenCTIProvider(baseURL, token string, verifyTLS bool) Provider {
	tr := &http.Transport{}
	if !verifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
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
		Reason:     "OpenCTI 未命中",
	}

	data, _ := raw["data"].(map[string]interface{})
	obs, _ := data["stixCyberObservables"].(map[string]interface{})
	edges, _ := obs["edges"].([]interface{})
	if len(edges) > 0 {
		rep.Reputation = "suspicious"
		rep.Confidence = 0.85
		rep.Reason = "OpenCTI 命中可观测对象"
	}

	return rep, nil
}
