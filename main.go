package main

import (
	"log"
	"net/http"

	"jwks-server/internal/db"
	"jwks-server/internal/server"
)

func main() {
	database, err := db.OpenDB("totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	if err := db.InitSchema(database); err != nil {
		log.Fatalf("failed to initialize schema: %v", err)
	}

	if err := db.EnsureSeedKeys(database); err != nil {
		log.Fatalf("failed to seed keys: %v", err)
	}

	srv := server.NewServer(database)

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", srv.Routes()))
}