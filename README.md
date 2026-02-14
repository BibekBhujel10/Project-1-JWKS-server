# Project 1 — JWKS Server (Go)

## What this does
- Generates RSA key pairs with unique `kid` and expiry timestamps.
- Serves a JWKS endpoint with ONLY non-expired public keys.
- Provides `/auth` endpoint to issue JWTs.
- Supports `?expired=true` to issue JWT signed with an expired key and expired exp.

## Endpoints
- `GET /jwks`
- `GET /.well-known/jwks.json`
- `POST /auth`
- `POST /auth?expired=true`

## Run
```bash
go mod tidy
go run .
