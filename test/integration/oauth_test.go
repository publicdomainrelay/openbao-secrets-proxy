package integration

import (
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// configureOAuthProvider registers a provider on the engine pointing at the
// in-process authorization server.
func configureOAuthProvider(t *testing.T, c *cluster, name string, provider *oauthProvider, extra map[string]any) {
	t.Helper()
	body := map[string]any{
		"authorize_url":     provider.URL + "/authorize",
		"token_url":         provider.URL + "/token",
		"client_id":         "test-client",
		"client_secret":     "test-secret",
		"scopes":            []string{"openid", "profile"},
		"pkce":              true,
		"store_mode":        "entity",
		"use_refresh_token": true,
	}
	maps.Copy(body, extra)
	c.MustWrite(t, mountPath+"/oauth/"+name, body)
}

// runOAuthLogin drives login -> provider authorize -> callback and returns the
// authorization code the provider issued.
func runOAuthLogin(t *testing.T, c *cluster, name, clientToken string) string {
	t.Helper()
	resp, raw := c.MustProxy(t, http.MethodGet, "oauth/"+name+"/login", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d body = %s", resp.StatusCode, raw)
	}
	data := Data(t, raw)
	authURL, _ := data["auth_url"].(string)
	if authURL == "" {
		t.Fatalf("login response has no auth_url: %s", raw)
	}
	if redirectURI, _ := data["redirect_uri"].(string); !strings.Contains(redirectURI, "/v1/"+mountPath+"/oauth/callback/"+name) {
		t.Fatalf("redirect_uri = %q", redirectURI)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	if parsed.Query().Get("code_challenge") == "" {
		t.Fatalf("auth_url has no PKCE challenge: %s", authURL)
	}

	provider := testProviderFor(t, parsed)
	code, state := provider.authorize(t, authURL)
	if code == "" || state == "" {
		t.Fatalf("provider returned code=%q state=%q", code, state)
	}

	// The callback is an unauthenticated path: the entity travels in state.
	cbResp, cbRaw, err := c.APIRequest(http.MethodGet,
		mountPath+"/oauth/callback/"+name+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d body = %s", cbResp.StatusCode, cbRaw)
	}
	if status := Data(t, cbRaw)["status"]; status != "ok" {
		t.Fatalf("callback data = %s", cbRaw)
	}
	return code
}

// providers is a registry so runOAuthLogin can find the server that issued an
// authorization URL.
var providers = map[string]*oauthProvider{}

func testProviderFor(t *testing.T, authURL *url.URL) *oauthProvider {
	t.Helper()
	p, ok := providers[authURL.Host]
	if !ok {
		t.Fatalf("no test provider registered for host %s", authURL.Host)
	}
	return p
}

func registerProvider(p *oauthProvider) {
	parsed, err := url.Parse(p.URL)
	if err != nil {
		panic(err)
	}
	providers[parsed.Host] = p
}

func TestOAuthAuthorizationCodeFlowInjectsEntityToken(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	provider := newOAuthProvider(t)
	registerProvider(provider)

	clientToken := EntityToken(t, c, "oauth-alice")
	configureOAuthProvider(t, c, "flow", provider, nil)
	c.MustWrite(t, mountPath+"/routes/oauth-flow", map[string]any{
		"upstream":       upstream.URL,
		"require_entity": true,
		"inject": map[string]string{
			"Authorization": "Bearer $oauth:flow",
			"X-Id-Token":    "$oauth:flow:id_token",
		},
		"inject_query": map[string]string{"access_token": "$oauth:flow:access_token"},
	})

	runOAuthLogin(t, c, "flow", clientToken)

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/oauth-flow/me", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status = %d body = %s", resp.StatusCode, raw)
	}
	want := "Bearer " + provider.latestAccessToken()
	if got := upstream.header("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
	if got := upstream.lastRequest().Query["access_token"]; len(got) != 1 || got[0] != provider.latestAccessToken() {
		t.Fatalf("query access_token = %v", got)
	}

	// Token metadata is readable without revealing the secret.
	resp, raw = c.MustProxy(t, http.MethodGet, "oauth/flow/token", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token metadata status = %d body = %s", resp.StatusCode, raw)
	}
	data := Data(t, raw)
	if data["provider"] != "flow" {
		t.Fatalf("token metadata = %s", raw)
	}
	if _, leaked := data["access_token"]; leaked {
		t.Fatalf("token metadata leaked the access token: %s", raw)
	}
}

func TestOAuthTokenIsScopedToCallingEntity(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	provider := newOAuthProvider(t)
	registerProvider(provider)

	alice := EntityToken(t, c, "scoped-alice")
	bob := EntityToken(t, c, "scoped-bob")

	configureOAuthProvider(t, c, "scoped", provider, nil)
	c.MustWrite(t, mountPath+"/routes/oauth-scoped", map[string]any{
		"upstream":       upstream.URL,
		"require_entity": true,
		"inject":         map[string]string{"Authorization": "Bearer $oauth:scoped"},
	})

	// Bob has not logged in yet.
	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/oauth-scoped/me", nil, bob)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bob status = %d body = %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "scoped") {
		t.Fatalf("bob body = %s", raw)
	}

	runOAuthLogin(t, c, "scoped", alice)
	aliceToken := provider.latestAccessToken()

	resp, raw = c.MustProxy(t, http.MethodGet, "proxy/oauth-scoped/me", nil, alice)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.header("Authorization"); got != "Bearer "+aliceToken {
		t.Fatalf("Authorization = %q", got)
	}

	// Bob still has no token after Alice logged in: no cross-entity leakage.
	resp, raw = c.MustProxy(t, http.MethodGet, "proxy/oauth-scoped/me", nil, bob)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bob status after alice login = %d body = %s", resp.StatusCode, raw)
	}
}

func TestOAuthRefreshTokenIsUsedAndPersisted(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	provider := newOAuthProvider(t)
	registerProvider(provider)
	provider.setExpiresIn(1)

	clientToken := EntityToken(t, c, "refresh-user")
	configureOAuthProvider(t, c, "refresh", provider, nil)
	c.MustWrite(t, mountPath+"/routes/oauth-refresh", map[string]any{
		"upstream": upstream.URL,
		"inject":   map[string]string{"Authorization": "Bearer $oauth:refresh"},
	})

	runOAuthLogin(t, c, "refresh", clientToken)
	exchanged := provider.latestAccessToken()

	// The token is already inside the refresh window, so the first proxied
	// request must refresh it.
	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/oauth-refresh/one", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if provider.refreshes() == 0 {
		t.Fatal("expected a refresh_token grant")
	}
	refreshed := provider.latestAccessToken()
	if refreshed == exchanged {
		t.Fatal("refresh did not produce a new access token")
	}
	if got := upstream.header("Authorization"); got != "Bearer "+refreshed {
		t.Fatalf("Authorization = %q, want Bearer %s", got, refreshed)
	}

	// The refreshed token is persisted: a second request reuses it.
	resp, raw = c.MustProxy(t, http.MethodGet, "oauth/refresh/token", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token read status = %d body = %s", resp.StatusCode, raw)
	}
	if got := Data(t, raw)["has_refresh_token"]; got != true {
		t.Fatalf("has_refresh_token = %v", got)
	}
}

func TestOAuthAudienceParameterIsForwarded(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	provider := newOAuthProvider(t)
	registerProvider(provider)
	provider.requireAudience = "https://api.example.com"

	clientToken := EntityToken(t, c, "audience-user")
	configureOAuthProvider(t, c, "audience", provider, map[string]any{
		"audience": "https://api.example.com",
	})
	c.MustWrite(t, mountPath+"/routes/oauth-audience", map[string]any{
		"upstream": upstream.URL,
		"inject":   map[string]string{"Authorization": "Bearer $oauth:audience"},
	})

	runOAuthLogin(t, c, "audience", clientToken)

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/oauth-audience/me", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
}

func TestOAuthSharedStoreModeWorksWithoutEntity(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	provider := newOAuthProvider(t)
	registerProvider(provider)

	configureOAuthProvider(t, c, "shared", provider, map[string]any{"store_mode": "shared"})
	c.MustWrite(t, mountPath+"/routes/oauth-shared", map[string]any{
		"upstream": upstream.URL,
		"inject":   map[string]string{"Authorization": "Bearer $oauth:shared"},
	})

	runOAuthLogin(t, c, "shared", rootToken)

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/oauth-shared/me", nil, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.header("Authorization"); got != "Bearer "+provider.latestAccessToken() {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestOAuthCallbackRejectsUnknownState(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	provider := newOAuthProvider(t)
	registerProvider(provider)
	configureOAuthProvider(t, c, "state-check", provider, nil)

	resp, raw, err := c.APIRequest(http.MethodGet,
		mountPath+"/oauth/callback/state-check?code=whatever&state=not-a-real-state", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "unknown or already used state") {
		t.Fatalf("body = %s", raw)
	}
}

func TestOAuthSuccessRedirectAfterCallback(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	provider := newOAuthProvider(t)
	registerProvider(provider)

	clientToken := EntityToken(t, c, "redirect-user")
	configureOAuthProvider(t, c, "redirect", provider, map[string]any{
		"success_redirect": "https://app.example.com/done",
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "oauth/redirect/login", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d body = %s", resp.StatusCode, raw)
	}
	authURL := Data(t, raw)["auth_url"].(string)
	code, state := testProviderFor(t, mustParse(t, authURL)).authorize(t, authURL)

	cbResp, cbRaw, err := c.APIRequest(http.MethodGet,
		mountPath+"/oauth/callback/redirect?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cbResp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("callback status = %d body = %s", cbResp.StatusCode, cbRaw)
	}
	location := cbResp.Header.Get("Location")
	if !strings.HasPrefix(location, "https://app.example.com/done?") || !strings.Contains(location, "status=ok") {
		t.Fatalf("Location = %q", location)
	}
}

func TestOAuthProviderDelete(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	provider := newOAuthProvider(t)
	registerProvider(provider)
	configureOAuthProvider(t, c, "deletable", provider, nil)

	keys := c.MustList(t, mountPath+"/oauth")
	if !contains(keys, "deletable") {
		t.Fatalf("provider missing from %v", keys)
	}
	c.MustRun(t, "delete", mountPath+"/oauth/deletable")
	keys = c.MustList(t, mountPath+"/oauth")
	if contains(keys, "deletable") {
		t.Fatalf("provider still present in %v", keys)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed
}
