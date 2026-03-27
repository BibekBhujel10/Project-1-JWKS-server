package db

import (
	"testing"
	"time"
)

func TestInsertAndReadKeys(t *testing.T) {
	database, err := OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := InitSchema(database); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Unix()

	expiredPEM, err := GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}
	validPEM, err := GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := InsertKey(database, expiredPEM, now-60); err != nil {
		t.Fatal(err)
	}
	if err := InsertKey(database, validPEM, now+3600); err != nil {
		t.Fatal(err)
	}

	expiredKey, err := GetExpiredKey(database, now)
	if err != nil {
		t.Fatal(err)
	}
	if expiredKey.EXP > now {
		t.Fatal("expected expired key")
	}

	validKey, err := GetValidKey(database, now)
	if err != nil {
		t.Fatal(err)
	}
	if validKey.EXP <= now {
		t.Fatal("expected valid key")
	}
}

func TestGetValidKeysReturnsOnlyValidOnes(t *testing.T) {
	database, err := OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := InitSchema(database); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Unix()

	expiredPEM, _ := GeneratePEMKey()
	validPEM1, _ := GeneratePEMKey()
	validPEM2, _ := GeneratePEMKey()

	_ = InsertKey(database, expiredPEM, now-100)
	_ = InsertKey(database, validPEM1, now+100)
	_ = InsertKey(database, validPEM2, now+200)

	keys, err := GetValidKeys(database, now)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(keys))
	}
}

func TestParsePrivateKeyFromPEM(t *testing.T) {
	pemKey, err := GeneratePEMKey()
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := ParsePrivateKeyFromPEM(pemKey)
	if err != nil {
		t.Fatal(err)
	}

	if privateKey == nil {
		t.Fatal("expected private key")
	}
}

func TestEnsureSeedKeysCreatesKeys(t *testing.T) {
	database, err := OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := InitSchema(database); err != nil {
		t.Fatal(err)
	}

	if err := EnsureSeedKeys(database); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count < 2 {
		t.Fatalf("expected at least 2 keys, got %d", count)
	}
}