package db

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

type DBKey struct {
	KID int64
	PEM string
	EXP int64
}

func OpenDB(path string) (*sql.DB, error) {
	return sql.Open("sqlite", path)
}

func InitSchema(database *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`
	_, err := database.Exec(query)
	return err
}

func EnsureSeedKeys(database *sql.DB) error {
	now := time.Now().UTC().Unix()

	var validCount int
	err := database.QueryRow(
		`SELECT COUNT(*) FROM keys WHERE exp > ?`,
		now,
	).Scan(&validCount)
	if err != nil {
		return err
	}

	var expiredCount int
	err = database.QueryRow(
		`SELECT COUNT(*) FROM keys WHERE exp <= ?`,
		now,
	).Scan(&expiredCount)
	if err != nil {
		return err
	}

	if expiredCount == 0 {
		expiredPEM, err := GeneratePEMKey()
		if err != nil {
			return err
		}
		if err := InsertKey(database, expiredPEM, time.Now().UTC().Add(-1*time.Hour).Unix()); err != nil {
			return err
		}
	}

	if validCount == 0 {
		validPEM, err := GeneratePEMKey()
		if err != nil {
			return err
		}
		if err := InsertKey(database, validPEM, time.Now().UTC().Add(1*time.Hour).Unix()); err != nil {
			return err
		}
	}

	return nil
}

func InsertKey(database *sql.DB, pemKey string, exp int64) error {
	_, err := database.Exec(
		`INSERT INTO keys(key, exp) VALUES(?, ?)`,
		pemKey,
		exp,
	)
	return err
}

func GetValidKey(database *sql.DB, now int64) (DBKey, error) {
	row := database.QueryRow(
		`SELECT kid, key, exp
		 FROM keys
		 WHERE exp > ?
		 ORDER BY exp DESC
		 LIMIT 1`,
		now,
	)

	var record DBKey
	err := row.Scan(&record.KID, &record.PEM, &record.EXP)
	return record, err
}

func GetExpiredKey(database *sql.DB, now int64) (DBKey, error) {
	row := database.QueryRow(
		`SELECT kid, key, exp
		 FROM keys
		 WHERE exp <= ?
		 ORDER BY exp DESC
		 LIMIT 1`,
		now,
	)

	var record DBKey
	err := row.Scan(&record.KID, &record.PEM, &record.EXP)
	return record, err
}

func GetValidKeys(database *sql.DB, now int64) ([]DBKey, error) {
	rows, err := database.Query(
		`SELECT kid, key, exp
		 FROM keys
		 WHERE exp > ?
		 ORDER BY kid ASC`,
		now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]DBKey, 0)
	for rows.Next() {
		var record DBKey
		if err := rows.Scan(&record.KID, &record.PEM, &record.EXP); err != nil {
			return nil, err
		}
		keys = append(keys, record)
	}

	return keys, rows.Err()
}

func GeneratePEMKey() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	der := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}

func ParsePrivateKeyFromPEM(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}