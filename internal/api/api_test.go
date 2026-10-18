package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var testKey = []byte("test-only-key-32-bytes-long-123456789")

const testPassword = "Test-only-password-123!"

func setup(t *testing.T) (*API, http.Handler) {
	t.Helper()
	db, e := sql.Open("sqlite3", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	h, e := bcrypt.GenerateFromPassword([]byte(testPassword), 12)
	if e != nil {
		t.Fatal(e)
	}
	a, e := New(db, testKey, "student", string(h))
	if e != nil {
		t.Fatal(e)
	}
	return a, a.Handler()
}
func request(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func loginToken(t *testing.T, h http.Handler) string {
	t.Helper()
	w := request(h, "POST", "/auth/login", `{"username":"student","password":"`+testPassword+`"}`, "")
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body)
	}
	var v struct {
		Token string `json:"access_token"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return v.Token
}
func signed(t *testing.T, c jwt.RegisteredClaims, method jwt.SigningMethod, key any) string {
	t.Helper()
	s, e := jwt.NewWithClaims(method, c).SignedString(key)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestAuthentication(t *testing.T) {
	_, h := setup(t)
	for _, p := range []string{"/api/data"} {
		for _, m := range []string{"GET", "POST"} {
			if w := request(h, m, p, `{}`, ""); w.Code != 401 {
				t.Fatalf("anonymous %s: %d", m, w.Code)
			}
		}
	}
	for _, body := range []string{`{"username":"student","password":"wrong"}`, `{"username":"' OR 1=1 --","password":"wrong"}`} {
		w := request(h, "POST", "/auth/login", body, "")
		if w.Code != 401 {
			t.Fatalf("invalid login: %d", w.Code)
		}
	}
	token := loginToken(t, h)
	if w := request(h, "GET", "/api/data", "", token); w.Code != 200 {
		t.Fatalf("authorized %d", w.Code)
	}
}
func TestJWTValidation(t *testing.T) {
	_, h := setup(t)
	base := jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{audience}, Subject: "1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
	tests := map[string]string{"malformed": "abc", "wrong_signature": signed(t, base, jwt.SigningMethodHS256, []byte("another-test-key-another-test-key")), "algorithm_confusion": signed(t, base, jwt.SigningMethodHS384, testKey), "none": signed(t, base, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)}
	c := base
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second))
	tests["expired"] = signed(t, c, jwt.SigningMethodHS256, testKey)
	c = base
	c.ExpiresAt = nil
	tests["no_expiration"] = signed(t, c, jwt.SigningMethodHS256, testKey)
	c = base
	c.Issuer = "other"
	tests["issuer"] = signed(t, c, jwt.SigningMethodHS256, testKey)
	c = base
	c.Audience = jwt.ClaimStrings{"other"}
	tests["audience"] = signed(t, c, jwt.SigningMethodHS256, testKey)
	c = base
	c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
	tests["not_yet_valid"] = signed(t, c, jwt.SigningMethodHS256, testKey)
	c = base
	c.Subject = "999"
	tests["unknown_user"] = signed(t, c, jwt.SigningMethodHS256, testKey)
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if w := request(h, "GET", "/api/data", "", token); w.Code != 401 {
				t.Fatalf("want 401 got %d", w.Code)
			}
		})
	}
}
func TestSQLiXSSAndOwnership(t *testing.T) {
	a, h := setup(t)
	token := loginToken(t, h)
	body := `{"title":"'; DROP TABLE users; --","content":"<script>alert('x')</script>"}`
	w := request(h, "POST", "/api/data", body, token)
	if w.Code != 201 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	var note Note
	if e := json.Unmarshal(w.Body.Bytes(), &note); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(note.Content, "<") || !strings.Contains(note.Content, "&lt;script&gt;") {
		t.Fatal("XSS not escaped")
	}
	var count int
	if e := a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); e != nil || count != 1 {
		t.Fatal("SQL injection affected users")
	}
	_, e := a.db.Exec(`INSERT INTO users(username,password_hash) VALUES(?,?)`, "other", string(a.dummy))
	if e != nil {
		t.Fatal(e)
	}
	other := signed(t, jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{audience}, Subject: "2", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, jwt.SigningMethodHS256, testKey)
	w = request(h, "GET", "/api/data", "", other)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("cross-user data leak")
	}
	w = request(h, "GET", "/api/data", "", token)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("unsafe list")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing headers")
	}
}
func TestInputValidation(t *testing.T) {
	_, h := setup(t)
	token := loginToken(t, h)
	cases := []struct {
		name, body string
		status     int
	}{{"unknown field", `{"title":"ok","extra":1}`, 400}, {"trailing JSON", `{"title":"ok"}{}`, 400}, {"empty title", `{"title":" "}`, 400}, {"oversize", `{"title":"ok","content":"` + strings.Repeat("x", 5000) + `"}`, 413}, {"long title", `{"title":"` + strings.Repeat("x", 101) + `"}`, 400}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := request(h, "POST", "/api/data", tc.body, token)
			if w.Code != tc.status {
				t.Fatalf("want %d got %d", tc.status, w.Code)
			}
		})
	}
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("media type accepted")
	}
}
func TestRateLimit(t *testing.T) {
	_, h := setup(t)
	for i := 0; i < 20; i++ {
		request(h, "POST", "/auth/login", `{}`, "")
	}
	if w := request(h, "POST", "/auth/login", `{}`, ""); w.Code != 429 {
		t.Fatalf("rate limit: %d", w.Code)
	}
}
func TestWeakConfiguration(t *testing.T) {
	db, e := sql.Open("sqlite3", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = New(db, []byte("short"), "student", "plain"); e == nil {
		t.Fatal("weak key accepted")
	}
	if _, e = New(db, testKey, "student", "plaintext"); e == nil {
		t.Fatal("plaintext password accepted")
	}
}
