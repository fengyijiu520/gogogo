package combination

import (
	"fmt"
	"testing"
)

func TestChainRulesLoad(t *testing.T) {
	ids := RuleCatalogIDs()
	fmt.Printf("Loaded %d chain rules:\n", len(ids))
	for _, id := range ids {
		fmt.Printf("  %s\n", id)
	}

	warning := getChainRulesWarning()
	if warning != "" {
		fmt.Printf("\nWarning: %s\n", warning)
	} else {
		fmt.Println("\nNo warnings - all rules loaded successfully!")
	}

	if len(ids) == 0 {
		t.Fatal("No chain rules loaded")
	}

	t.Logf("Loaded %d chain rules", len(ids))
}
