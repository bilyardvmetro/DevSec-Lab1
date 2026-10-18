// Package api implements the laboratory REST API.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const issuer = "devsec-lab1"
const audience = "notes-api"
const MaxBody = 4096

type userKey struct{}
type API struct {
	db       *sql.DB
	key      []byte
	dummy    []byte
	mu       sync.Mutex
	attempts int
	window   time.Time
}
type Note struct {
	ID      int64  `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// New initializes the schema and a single bootstrap account. Only bcrypt hashes are accepted.
func New(db *sql.DB, key []byte, username, hash string) (*API, error) {
	if len(key) < 32 {
		return nil, errors.New("JWT key must contain at least 32 bytes")
	}
	if len(username) == 0 || len(username) > 64 {
		return nil, errors.New("username must contain 1..64 bytes")
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < 12 {
		return nil, errors.New("password hash must be bcrypt with cost >=12")
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, content TEXT NOT NULL);`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`INSERT INTO users(username,password_hash) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash`, username, hash)
	if err != nil {
		return nil, err
	}
	return &API{db: db, key: append([]byte(nil), key...), dummy: []byte(hash)}, nil
}

func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /auth/login", a.login)
	m.Handle("GET /api/data", a.authorize(http.HandlerFunc(a.list)))
	m.Handle("POST /api/data", a.authorize(http.HandlerFunc(a.create)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		m.ServeHTTP(w, r)
	})
}
func reply(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		fail(w, 415, "application/json required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(v); err == nil {
		var extra any
		err = d.Decode(&extra)
		if err == io.EOF {
			return true
		}
	}
	var sizeErr *http.MaxBytesError
	if errors.As(err, &sizeErr) {
		fail(w, 413, "body too large")
	} else {
		fail(w, 400, "invalid JSON")
	}
	return false
}

// The global bound deliberately avoids trusting client-provided forwarding headers.
func (a *API) allowLogin() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if now.Sub(a.window) >= time.Minute {
		a.window = now
		a.attempts = 0
	}
	a.attempts++
	return a.attempts <= 20
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.allowLogin() {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "too many attempts")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Username) == 0 || len(in.Username) > 64 || len(in.Password) < 1 || len(in.Password) > 72 {
		fail(w, 400, "invalid credentials format")
		return
	}
	var id int64
	var hash string
	err := a.db.QueryRowContext(r.Context(), `SELECT id,password_hash FROM users WHERE username = ?`, in.Username).Scan(&id, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		fail(w, 500, "internal error")
		return
	}
	compared := []byte(hash)
	if errors.Is(err, sql.ErrNoRows) {
		compared = a.dummy
	}
	valid := bcrypt.CompareHashAndPassword(compared, []byte(in.Password)) == nil
	if err != nil || !valid {
		fail(w, 401, "invalid username or password")
		return
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{audience}, Subject: fmt.Sprint(id), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute))}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.key)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	reply(w, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 900})
}
func (a *API) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) > 4096 {
			fail(w, 401, "valid Bearer token required")
			return
		}
		claims := new(jwt.RegisteredClaims)
		token, err := jwt.ParseWithClaims(parts[1], claims, func(t *jwt.Token) (any, error) { return a.key, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithIssuer(issuer), jwt.WithAudience(audience))
		if err != nil || !token.Valid || claims.Subject == "" {
			fail(w, 401, "invalid or expired token")
			return
		}
		var id int64
		if err = a.db.QueryRowContext(r.Context(), `SELECT id FROM users WHERE id = ?`, claims.Subject).Scan(&id); err != nil {
			fail(w, 401, "unknown user")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, id)))
	})
}
func (a *API) list(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,title,content FROM notes WHERE owner_id = ? ORDER BY id DESC LIMIT 100`, r.Context().Value(userKey{}))
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	defer rows.Close()
	notes := []Note{}
	for rows.Next() {
		var n Note
		if err = rows.Scan(&n.ID, &n.Title, &n.Content); err != nil {
			fail(w, 500, "internal error")
			return
		}
		n.Title = html.EscapeString(n.Title)
		n.Content = html.EscapeString(n.Content)
		notes = append(notes, n)
	}
	if rows.Err() != nil {
		fail(w, 500, "internal error")
		return
	}
	reply(w, 200, notes)
}
func (a *API) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	if len(in.Title) == 0 || len(in.Title) > 100 || len(in.Content) > 2000 {
		fail(w, 400, "title: 1..100 bytes; content: <=2000 bytes")
		return
	}
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO notes(owner_id,title,content) VALUES(?,?,?)`, r.Context().Value(userKey{}), in.Title, in.Content)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	reply(w, 201, Note{ID: id, Title: html.EscapeString(in.Title), Content: html.EscapeString(in.Content)})
}
