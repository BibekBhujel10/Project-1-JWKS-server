package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"time"
)

type KeySpec struct {
	ExpiresAt time.Time
}

type KeyPair struct {
	Private   *rsa.PrivateKey
	Public    *rsa.PublicKey
	KID       string
	ExpiresAt time.Time
}

// KeySet holds keys and provides selection + JWKS output.
type KeySet struct {
	mu   sync.RWMutex
	keys []KeyPair
}

// NewKeySet generates RSA keys for each spec.
func NewKeySet(specs ...KeySpec) (*KeySet, error) {
	if len(specs) == 0 {
		return nil, errors.New("no KeySpec provided")
	}

	ks := &KeySet{}
	for _, s := range specs {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		pub := &priv.PublicKey
		kid := deriveKID(pub)

		ks.keys = append(ks.keys, KeyPair{
			Private:   priv,
			Public:    pub,
			KID:       kid,
			ExpiresAt: s.ExpiresAt.UTC(),
		})
	}
	return ks, nil
}

// ActiveKey returns a non-expired key (latest expiry in the future).
func (ks *KeySet) ActiveKey(now time.Time) (KeyPair, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	now = now.UTC()
	var best KeyPair
	found := false

	for _, k := range ks.keys {
		if now.Before(k.ExpiresAt) {
			if !found || k.ExpiresAt.After(best.ExpiresAt) {
				best = k
				found = true
			}
		}
	}
	return best, found
}

// ExpiredKey returns an expired key (most recent expiry in the past).
func (ks *KeySet) ExpiredKey(now time.Time) (KeyPair, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	now = now.UTC()
	var best KeyPair
	found := false

	for _, k := range ks.keys {
		if !now.Before(k.ExpiresAt) {
			if !found || k.ExpiresAt.After(best.ExpiresAt) {
				best = k
				found = true
			}
		}
	}
	return best, found
}

// JWKS returns the JWKS document containing ONLY non-expired public keys.
func (ks *KeySet) JWKS(now time.Time) map[string]any {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	now = now.UTC()
	out := make([]map[string]any, 0)

	for _, k := range ks.keys {
		if now.Before(k.ExpiresAt) {
			out = append(out, publicJWK(k))
		}
	}

	return map[string]any{"keys": out}
}

// publicJWK converts a keypair to a JWKS public JWK map.
func publicJWK(k KeyPair) map[string]any {
	n := base64.RawURLEncoding.EncodeToString(k.Public.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.Public.E)).Bytes())

	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": k.KID,
		"n":   n,
		"e":   e,
	}
}

// deriveKID generates a stable kid from public key parts.
func deriveKID(pub *rsa.PublicKey) string {
	h := sha256.New()
	h.Write(pub.N.Bytes())
	h.Write(big.NewInt(int64(pub.E)).Bytes())
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}
