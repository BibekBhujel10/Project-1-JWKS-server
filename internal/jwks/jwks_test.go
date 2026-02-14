package jwks

import (
	"testing"
	"time"
)

func TestJWKSFiltersExpiredKeys(t *testing.T) {
	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	ks, err := NewKeySet(
		KeySpec{ExpiresAt: now.Add(10 * time.Minute)},  // valid
		KeySpec{ExpiresAt: now.Add(-10 * time.Minute)}, // expired
	)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	doc := ks.JWKS(now)
	keysAny, ok := doc["keys"].([]map[string]any)
	if !ok {
		t.Fatalf("expected keys to be []map[string]any")
	}

	if len(keysAny) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(keysAny))
	}

	if keysAny[0]["kid"] == "" {
		t.Fatalf("expected kid to be present")
	}
}
