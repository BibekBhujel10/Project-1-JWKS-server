package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"jwks-server/internal/jwks"
	"jwks-server/internal/server"
)

func main() {
	now := time.Now().UTC()

	// One active key (expires in future), one expired key (expiry in past)
	keyset, err := jwks.NewKeySet(
		jwks.KeySpec{ExpiresAt: now.Add(1 * time.Hour)},
		jwks.KeySpec{ExpiresAt: now.Add(-1 * time.Hour)},
	)
	if err != nil {
		log.Fatalf("failed to create keyset: %v", err)
	}

	srv := server.NewServer(keyset)

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	log.Printf("JWKS server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, srv.Routes()))
}
