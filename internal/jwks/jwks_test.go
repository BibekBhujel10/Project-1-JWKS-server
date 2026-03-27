package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestPublicJWK(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := PublicJWK(&privateKey.PublicKey, 123)

	if jwk["kid"] != "123" {
		t.Fatal("expected kid 123")
	}
	if jwk["kty"] != "RSA" {
		t.Fatal("expected RSA key type")
	}
	if jwk["alg"] != "RS256" {
		t.Fatal("expected RS256 algorithm")
	}
}