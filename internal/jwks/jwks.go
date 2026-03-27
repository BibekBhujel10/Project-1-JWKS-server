package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strconv"
)

func PublicJWK(publicKey *rsa.PublicKey, kid int64) map[string]any {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": strconv.FormatInt(kid, 10),
		"n":   n,
		"e":   e,
	}
}