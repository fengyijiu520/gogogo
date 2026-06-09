package ti

import (
	"context"

	"skill-scanner/internal/review"
)

type Provider interface {
	Name() string
	Query(ctx context.Context, targets []string) ([]review.TIReputation, error)
}
