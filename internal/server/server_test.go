package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dbpkg "jwks-server/internal/db"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	database, err := dbpkg.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}

	if err := dbpkg.InitSchema(database); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC).Unix()

	expiredPEM, err := dbpkg.GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}
	validPEM, err := dbpkg.GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := dbpkg.InsertKey(database, expiredPEM, now-3600); err != nil {
		t.Fatal(err)
	}
	if err := dbpkg.InsertKey(database, validPEM, now+3600); err != nil {
		t.Fatal(err)
	}

	return database
}

func parseWithoutClaimsValidation(t *testing.T, tokenStr string, publicKey any) *jwt.Token {
	t.Helper()

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !token.Valid {
		t.Fatal("expected valid signature")
	}

	return token
}

func TestJWKSReturnsOnlyValidKeys(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	s := NewServer(database)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	keys, ok := body["keys"].([]any)
	if !ok {
		t.Fatal(`expected "keys" array`)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(keys))
	}
}

func TestJWKSMethodNotAllowed(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	s := NewServer(database)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestAuthReturnsValidJWT(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	s := NewServer(database)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	record, err := dbpkg.GetValidKey(database, now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := dbpkg.ParsePrivateKeyFromPEM(record.PEM)
	if err != nil {
		t.Fatal(err)
	}

	token := parseWithoutClaimsValidation(t, body["token"], &privateKey.PublicKey)

	if token.Header["kid"] != "2" {
		t.Fatalf("expected kid 2, got %v", token.Header["kid"])
	}
}

func TestAuthReturnsExpiredJWTWhenRequested(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC)

	s := NewServer(database)
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	record, err := dbpkg.GetExpiredKey(database, now.Unix())
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := dbpkg.ParsePrivateKeyFromPEM(record.PEM)
	if err != nil {
		t.Fatal(err)
	}

	token := parseWithoutClaimsValidation(t, body["token"], &privateKey.PublicKey)

	if token.Header["kid"] != "1" {
		t.Fatalf("expected kid 1, got %v", token.Header["kid"])
	}
}

func TestAuthMethodNotAllowed(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	s := NewServer(database)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestAuthReturnsServerErrorWhenNoValidKeyExists(t *testing.T) {
	database, err := dbpkg.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := dbpkg.InitSchema(database); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC).Unix()

	expiredPEM, err := dbpkg.GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := dbpkg.InsertKey(database, expiredPEM, now-3600); err != nil {
		t.Fatal(err)
	}

	s := NewServer(database)
	s.now = func() time.Time { return time.Unix(now, 0).UTC() }

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

func TestJWKSReturnsEmptyArrayWhenNoValidKeysExist(t *testing.T) {
	database, err := dbpkg.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := dbpkg.InitSchema(database); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 2, 7, 1, 0, 0, 0, time.UTC).Unix()

	expiredPEM, err := dbpkg.GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := dbpkg.InsertKey(database, expiredPEM, now-3600); err != nil {
		t.Fatal(err)
	}

	s := NewServer(database)
	s.now = func() time.Time { return time.Unix(now, 0).UTC() }

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	keys, ok := body["keys"].([]any)
	if !ok {
		t.Fatal(`expected "keys" array`)
	}

	if len(keys) != 0 {
		t.Fatalf("expected 0 valid keys, got %d", len(keys))
	}
}