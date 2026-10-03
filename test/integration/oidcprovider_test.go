package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// oidcProvider is an in-process OpenID Connect provider. It signs RS256
// id_tokens and publishes discovery + JWKS, which is everything OpenBao's
// "oidc" auth method needs to complete a login.
type oidcProvider struct {
	*httptest.Server

	mu           sync.Mutex
	clientID     string
	clientSecret string
	key          *rsa.PrivateKey
	keyID        string
	codes        map[string]*oidcCode
	accessTokens map[string]string
	seq          int
}

type oidcCode struct {
	nonce       string
	redirectURI string
	sub         string
}

func newOIDCProvider(t *testing.T) *oidcProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &oidcProvider{
		clientID:     "test-oidc-client",
		clientSecret: "test-oidc-secret",
		key:          key,
		keyID:        "test-oidc-key",
		codes:        map[string]*oidcCode{},
		accessTokens: map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/jwks", p.handleJWKS)
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/userinfo", p.handleUserinfo)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

func (p *oidcProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/jwks",
		"userinfo_endpoint":                     p.URL + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "groups"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (p *oidcProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       p.key.Public(),
		KeyID:     p.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (p *oidcProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.clientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		http.Error(w, "response_type must be code", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.seq++
	code := fmt.Sprintf("oidc-code-%d", p.seq)
	p.codes[code] = &oidcCode{
		nonce:       q.Get("nonce"),
		redirectURI: redirectURI,
		sub:         "oidc-subject-1",
	}
	p.mu.Unlock()

	location := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(q.Get("state"))
	http.Redirect(w, r, location, http.StatusFound)
}

func (p *oidcProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}
	if clientID != p.clientID || clientSecret != p.clientSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}

	p.mu.Lock()
	entry, ok := p.codes[r.Form.Get("code")]
	if ok {
		delete(p.codes, r.Form.Get("code"))
	}
	p.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss":    p.URL,
		"sub":    entry.sub,
		"aud":    p.clientID,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"name":   "OIDC Test User",
		"email":  "oidc@example.com",
		"groups": []string{"testers"},
	}
	if entry.nonce != "" {
		claims["nonce"] = entry.nonce
	}
	idToken, err := p.sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.mu.Lock()
	p.seq++
	access := fmt.Sprintf("oidc-access-%d", p.seq)
	p.accessTokens[access] = entry.sub
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *oidcProvider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	token := ""
	if auth := r.Header.Get("Authorization"); len(auth) > 7 {
		token = auth[7:]
	}
	p.mu.Lock()
	sub, ok := p.accessTokens[token]
	p.mu.Unlock()
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":   sub,
		"name":  "OIDC Test User",
		"email": "oidc@example.com",
	})
}

func (p *oidcProvider) sign(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: p.keyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

// redirectTarget follows an authorization URL without following the final
// redirect and returns the parsed Location.
func redirectTarget(t *testing.T, client *http.Client, authURL string) *url.URL {
	t.Helper()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET %s: %v", authURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d for %s", resp.StatusCode, authURL)
	}
	parsed, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return parsed
}
