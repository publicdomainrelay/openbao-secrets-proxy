package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// oauthProvider is an in-process OAuth 2.0 authorization server used to drive
// the engine's authorization-code + PKCE and refresh-token flows.
type oauthProvider struct {
	*httptest.Server

	mu           sync.Mutex
	clientID     string
	clientSecret string
	// expiresIn is the lifetime reported for access tokens.
	expiresIn int
	// requireAudience, when set, rejects authorization requests without it.
	requireAudience string
	// refreshCount counts refresh_token grants.
	refreshCount int
	// issuedAccessTokens is every access token handed out, in order.
	issuedAccessTokens []string
	// codes maps an authorization code to the request that produced it.
	codes map[string]*authCode
	// refreshTokens maps a refresh token to its subject.
	refreshTokens map[string]string
	// seq increments to make every token distinct.
	seq int
	// lastTokenRequest records the parsed token endpoint request.
	lastTokenRequest url.Values
}

type authCode struct {
	clientID      string
	redirectURI   string
	codeChallenge string
	scope         string
	sub           string
}

func newOAuthProvider(t *testing.T) *oauthProvider {
	t.Helper()
	p := &oauthProvider{
		clientID:      "test-client",
		clientSecret:  "test-secret",
		expiresIn:     3600,
		codes:         map[string]*authCode{},
		refreshTokens: map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

func (p *oauthProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if got := q.Get("client_id"); got != p.clientID {
		http.Error(w, "unknown client_id "+got, http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		http.Error(w, "response_type must be code", http.StatusBadRequest)
		return
	}
	if p.requireAudience != "" && q.Get("audience") != p.requireAudience {
		http.Error(w, "audience must be "+p.requireAudience, http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.seq++
	code := fmt.Sprintf("code-%d", p.seq)
	p.codes[code] = &authCode{
		clientID:      p.clientID,
		redirectURI:   redirectURI,
		codeChallenge: q.Get("code_challenge"),
		scope:         q.Get("scope"),
		sub:           "user-subject",
	}
	p.mu.Unlock()

	location := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(q.Get("state"))
	http.Redirect(w, r, location, http.StatusFound)
}

func (p *oauthProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := r.Form

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = form.Get("client_id")
		clientSecret = form.Get("client_secret")
	}
	if clientID != p.clientID || clientSecret != p.clientSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}

	p.mu.Lock()
	p.lastTokenRequest = form
	p.mu.Unlock()

	switch form.Get("grant_type") {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, form)
	case "refresh_token":
		p.handleRefreshGrant(w, form)
	default:
		writeTokenError(w, "unsupported_grant_type")
	}
}

func (p *oauthProvider) handleAuthorizationCodeGrant(w http.ResponseWriter, form url.Values) {
	code := form.Get("code")

	p.mu.Lock()
	entry, ok := p.codes[code]
	if ok {
		delete(p.codes, code)
	}
	p.mu.Unlock()

	if !ok {
		writeTokenError(w, "invalid_grant")
		return
	}
	if entry.redirectURI != form.Get("redirect_uri") {
		writeTokenError(w, "invalid_grant")
		return
	}
	if entry.codeChallenge != "" {
		verifier := form.Get("code_verifier")
		if verifier == "" {
			writeTokenError(w, "invalid_grant")
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if challenge != entry.codeChallenge {
			writeTokenError(w, "invalid_grant")
			return
		}
	}
	p.writeToken(w, entry.sub, entry.scope)
}

func (p *oauthProvider) handleRefreshGrant(w http.ResponseWriter, form url.Values) {
	refresh := form.Get("refresh_token")

	p.mu.Lock()
	sub, ok := p.refreshTokens[refresh]
	if ok {
		p.refreshCount++
	}
	p.mu.Unlock()

	if !ok {
		writeTokenError(w, "invalid_grant")
		return
	}
	p.writeToken(w, sub, "openid profile")
}

func (p *oauthProvider) writeToken(w http.ResponseWriter, sub, scope string) {
	p.mu.Lock()
	p.seq++
	seq := p.seq
	access := fmt.Sprintf("access-%s-%d", sub, seq)
	refresh := fmt.Sprintf("refresh-%s-%d", sub, seq)
	p.issuedAccessTokens = append(p.issuedAccessTokens, access)
	p.refreshTokens[refresh] = sub
	expiresIn := p.expiresIn
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": refresh,
		"scope":         scope,
		"id_token":      "id-token-" + access,
	})
}

func writeTokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (p *oauthProvider) setExpiresIn(seconds int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expiresIn = seconds
}

func (p *oauthProvider) refreshes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshCount
}

func (p *oauthProvider) latestAccessToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.issuedAccessTokens) == 0 {
		return ""
	}
	return p.issuedAccessTokens[len(p.issuedAccessTokens)-1]
}

func (p *oauthProvider) waitForTokenRequest(t *testing.T, timeout time.Duration) url.Values {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		form := p.lastTokenRequest
		p.mu.Unlock()
		if form != nil {
			return form
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no token request observed")
	return nil
}

// authorize runs the browser leg: it follows the provider authorization URL
// without following the final redirect, and returns the code and state.
func (p *oauthProvider) authorize(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", location, err)
	}
	return parsed.Query().Get("code"), parsed.Query().Get("state")
}

