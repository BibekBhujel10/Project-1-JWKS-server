package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"jwks-server/internal/db"
	"jwks-server/internal/server"
)

func TestMainServerStartupFlow(t *testing.T) {
	database, err := db.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := db.InitSchema(database); err != nil {
		t.Fatal(err)
	}

	if err := db.EnsureSeedKeys(database); err != nil {
		t.Fatal(err)
	}

	s := server.NewServer(database)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}