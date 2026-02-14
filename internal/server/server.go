package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"jwks-server/internal/jwks"

	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	keys *jwks.KeySet
	now  func() time.Time
}

func NewServer(keys *jwks.KeySet) *Server {
	return &Server{
		keys: keys,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Routes wires endpoints.
// - GET /jwks and GET /.well-known/jwks.json return JWKS (non-expired keys only)
// - POST /auth returns a signed JWT
// - POST /auth?expired=true returns a JWT signed with expired key and expired exp
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	doc := s.keys.JWKS(s.now())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Requirement: If “expired” query param is present, issue expired token.
	issueExpired := hasExpiredQuery(r.URL.RawQuery)

	now := s.now()
	var kp jwks.KeyPair
	var ok bool

	if issueExpired {
		kp, ok = s.keys.ExpiredKey(now)
	} else {
		kp, ok = s.keys.ActiveKey(now)
	}

	if !ok {
		http.Error(w, "no suitable key available", http.StatusInternalServerError)
		return
	}

	tok, err := s.issueJWT(kp, now)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"token": tok})
}

func hasExpiredQuery(raw string) bool {
	// Presence is enough:
	// /auth?expired
	// /auth?expired=true
	// /auth?expired=1
	parts := strings.Split(raw, "&")
	for _, p := range parts {
		if p == "expired" || strings.HasPrefix(p, "expired=") {
			return true
		}
	}
	return false
}

func (s *Server) issueJWT(kp jwks.KeyPair, now time.Time) (string, error) {
	if kp.Private == nil || kp.Public == nil {
		return "", errors.New("missing key material")
	}

	// Token expiration tied to key expiry (easy to reason about + matches rubric).
	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": kp.ExpiresAt.Unix(),
		"iss": "jwks-server",
		"aud": "test-client",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kp.KID

	return token.SignedString(kp.Private)
}
