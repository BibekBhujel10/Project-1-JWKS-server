package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/jwks"

	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	db  *sql.DB
	now func() time.Time
}

func NewServer(database *sql.DB) *Server {
	return &Server{
		db:  database,
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	records, err := db.GetValidKeys(s.db, s.now().Unix())
	if err != nil {
		http.Error(w, "failed to read keys", http.StatusInternalServerError)
		return
	}

	// Important: initialize as empty slice so JSON returns [] instead of null
	keys := make([]map[string]any, 0)

	for _, record := range records {
		privateKey, err := db.ParsePrivateKeyFromPEM(record.PEM)
		if err != nil {
			http.Error(w, "failed to parse key", http.StatusInternalServerError)
			return
		}

		keys = append(keys, jwks.PublicJWK(&privateKey.PublicKey, record.KID))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nowUnix := s.now().Unix()

	var record db.DBKey
	var err error

	if _, ok := r.URL.Query()["expired"]; ok {
		record, err = db.GetExpiredKey(s.db, nowUnix)
	} else {
		record, err = db.GetValidKey(s.db, nowUnix)
	}
	if err != nil {
		http.Error(w, "failed to fetch key", http.StatusInternalServerError)
		return
	}

	privateKey, err := db.ParsePrivateKeyFromPEM(record.PEM)
	if err != nil {
		http.Error(w, "failed to parse private key", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub": "userABC",
		"iat": nowUnix,
		"exp": record.EXP,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = strconv.FormatInt(record.KID, 10)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": signedToken})
}