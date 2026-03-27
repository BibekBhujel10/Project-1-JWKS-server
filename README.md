# Project 2 - SQLite-backed JWKS Server

## Features
- Stores RSA private keys in SQLite
- Uses parameterized SQL queries to avoid SQL injection
- Serves valid public keys at `GET /.well-known/jwks.json`
- Issues JWTs at `POST /auth`
- Supports expired JWT issuance with `POST /auth?expired=true`

## DB file
The server creates:

`totally_not_my_privateKeys.db`

## Table schema
```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)