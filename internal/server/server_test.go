package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"jwks-server/internal/jwks"

	"github.com/golang-jwt/jwt/v5"
)

// parseWithoutClaimsValidation verifies signature + algorithm without enforcing exp/nbf/iat.
// This is important because:
// - For expired tokens, we EXPECT exp to be in the past but still want signature verification.
// - It also prevents flaky failures due to clock skew when exp is close to "now".
func parseWithoutClaimsValidation(t *testing.T, tokenStr string, pub any) *jwt.Token {
	t.Helper()

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	parsed, err := parser.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected valid signature")
	}
	return parsed
}

func TestJWKSMethodNotAllowed(t *testing.T) {
	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	ks, _ := jwks.NewKeySet(jwks.KeySpec{ExpiresAt: now.Add(1 * time.Hour)})
	s := NewServer(ks)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestJWKSReturnsOK(t *testing.T) {
	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	ks, _ := jwks.NewKeySet(
		jwks.KeySpec{ExpiresAt: now.Add(1 * time.Hour)},  // active
		jwks.KeySpec{ExpiresAt: now.Add(-1 * time.Hour)}, // expired
	)
	s := NewServer(ks)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Should return JSON with "keys"
	var doc map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := doc["keys"]; !ok {
		t.Fatalf(`expected "keys" in JWKS response`)
	}
}

func TestAuthIssuesValidJWT(t *testing.T) {
	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	ks, _ := jwks.NewKeySet(
		jwks.KeySpec{ExpiresAt: now.Add(30 * time.Minute)},  // active
		jwks.KeySpec{ExpiresAt: now.Add(-30 * time.Minute)}, // expired
	)
	s := NewServer(ks)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token == "" {
		t.Fatalf("expected token")
	}

	active, ok := ks.ActiveKey(now)
	if !ok {
		t.Fatalf("expected active key")
	}

	parsed := parseWithoutClaimsValidation(t, body.Token, active.Public)

	kid, _ := parsed.Header["kid"].(string)
	if kid != active.KID {
		t.Fatalf("expected kid %s, got %s", active.KID, kid)
	}

	// Optional: check exp equals active key expiry (matches your server logic)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("expected MapClaims")
	}
	expVal, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("expected exp claim")
	}
	if int64(expVal) != active.ExpiresAt.Unix() {
		t.Fatalf("expected exp=%d, got %d", active.ExpiresAt.Unix(), int64(expVal))
	}
}

func TestAuthExpiredParamIssuesExpiredJWT(t *testing.T) {
	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	ks, _ := jwks.NewKeySet(
		jwks.KeySpec{ExpiresAt: now.Add(30 * time.Minute)},  // active
		jwks.KeySpec{ExpiresAt: now.Add(-30 * time.Minute)}, // expired
	)
	s := NewServer(ks)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token == "" {
		t.Fatalf("expected token")
	}

	expired, ok := ks.ExpiredKey(now)
	if !ok {
		t.Fatalf("expected expired key")
	}

	parsed := parseWithoutClaimsValidation(t, body.Token, expired.Public)

	kid, _ := parsed.Header["kid"].(string)
	if kid != expired.KID {
		t.Fatalf("expected kid %s, got %s", expired.KID, kid)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("expected MapClaims")
	}

	expVal, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("expected exp claim")
	}

	if int64(expVal) != expired.ExpiresAt.Unix() {
		t.Fatalf("expected exp=%d, got %d", expired.ExpiresAt.Unix(), int64(expVal))
	}

	if expired.ExpiresAt.After(now) {
		t.Fatalf("expired key should expire in the past")
	}
}

func TestAuthMethodNotAllowed(t *testing.T) {
	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	ks, _ := jwks.NewKeySet(jwks.KeySpec{ExpiresAt: now.Add(1 * time.Hour)})
	s := NewServer(ks)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
