package integration

import (
	"net/http"
	"net/url"
	"testing"
)

// TestOIDCClientGetsItsOwnOAuthTokenInjected is the full requested flow:
//
//  1. A client logs in to OpenBao through the OIDC auth engine and receives a
//     token bound to an identity entity.
//  2. That client starts a third-party OAuth authorization-code flow through
//     the engine's oauth/<name>/login path. The resulting token is stored
//     against the client's entity.
//  3. The client proxies a request through the engine and the third-party
//     token is injected into a header as configured.
func TestOIDCClientGetsItsOwnOAuthTokenInjected(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	oidc := newOIDCProvider(t)
	thirdParty := newOAuthProvider(t)
	registerProvider(thirdParty)

	const oidcMount = "oidc-it"
	const oidcRedirect = "http://localhost:9876/oidc/callback"

	c.Run("auth", "enable", "-path="+oidcMount, "oidc")
	c.MustPolicy(t, "secrets-proxy-caller", CallerPolicy)
	c.MustRun(t, "write", "auth/"+oidcMount+"/config",
		"oidc_discovery_url="+oidc.URL,
		"oidc_client_id=test-oidc-client",
		"oidc_client_secret=test-oidc-secret",
		"default_role=demo",
	)
	c.MustRun(t, "write", "auth/"+oidcMount+"/role/demo",
		"allowed_redirect_uris="+oidcRedirect,
		"user_claim=sub",
		"oidc_scopes=openid,profile",
		"token_policies=secrets-proxy-caller",
	)

	clientToken := oidcLogin(t, c, oidcMount, oidcRedirect)

	configureOAuthProvider(t, c, "thirdparty", thirdParty, nil)
	c.MustWrite(t, mountPath+"/routes/oidc-api", map[string]any{
		"upstream":       upstream.URL,
		"require_entity": true,
		"inject": map[string]string{
			"Authorization": "Bearer $oauth:thirdparty",
			"X-Caller":      "$entity:alias",
		},
	})

	runOAuthLogin(t, c, "thirdparty", clientToken)

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/oidc-api/resource", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.header("Authorization"); got != "Bearer "+thirdParty.latestAccessToken() {
		t.Fatalf("Authorization = %q", got)
	}
	if got := upstream.header("X-Caller"); got == "" {
		t.Fatal("X-Caller was empty: the OIDC identity did not resolve to an entity alias")
	}

	// The OIDC token's entity is the only one holding this third-party token:
	// a different entity cannot spend it.
	other := EntityToken(t, c, "oidc-bystander")
	resp, raw = c.MustProxy(t, http.MethodGet, "proxy/oidc-api/resource", nil, other)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bystander status = %d body = %s", resp.StatusCode, raw)
	}
}

// TestOIDCEntityIsStableAcrossLogins proves the identity is anchored to the
// provider subject, not to the OpenBao token.
func TestOIDCEntityIsStableAcrossLogins(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)

	oidc := newOIDCProvider(t)
	const oidcMount = "oidc-stable"
	const oidcRedirect = "http://localhost:9877/oidc/callback"

	c.Run("auth", "enable", "-path="+oidcMount, "oidc")
	c.MustPolicy(t, "secrets-proxy-caller", CallerPolicy)
	c.MustRun(t, "write", "auth/"+oidcMount+"/config",
		"oidc_discovery_url="+oidc.URL,
		"oidc_client_id=test-oidc-client",
		"oidc_client_secret=test-oidc-secret",
		"default_role=demo",
	)
	c.MustRun(t, "write", "auth/"+oidcMount+"/role/demo",
		"allowed_redirect_uris="+oidcRedirect,
		"user_claim=sub",
		"oidc_scopes=openid",
		"token_policies=secrets-proxy-caller",
	)

	upstream := newEchoServer(t)
	c.MustWrite(t, mountPath+"/routes/stable-probe", map[string]any{
		"upstream":       upstream.URL,
		"require_entity": true,
		"inject":         map[string]string{"X-Entity": "$entity:id"},
	})

	first := oidcLogin(t, c, oidcMount, oidcRedirect)
	second := oidcLogin(t, c, oidcMount, oidcRedirect)
	if first == second {
		t.Fatal("expected two distinct client tokens")
	}

	entityOf := func(token string) string {
		resp, raw := c.MustProxy(t, http.MethodGet, "proxy/stable-probe/me", nil, token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
		}
		return upstream.header("X-Entity")
	}

	firstEntity := entityOf(first)
	secondEntity := entityOf(second)
	if firstEntity == "" {
		t.Fatal("entity id was empty")
	}
	if firstEntity != secondEntity {
		t.Fatalf("entity changed between logins: %q then %q", firstEntity, secondEntity)
	}
}

// oidcLogin walks the OpenBao OIDC auth flow and returns a client token.
func oidcLogin(t *testing.T, c *cluster, mount, redirectURI string) string {
	t.Helper()

	resp, raw, err := c.APIRequest(http.MethodPost, "auth/"+mount+"/oidc/auth_url", map[string]any{
		"role":         "demo",
		"redirect_uri": redirectURI,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth_url status = %d body = %s", resp.StatusCode, raw)
	}
	authURL, _ := Data(t, raw)["auth_url"].(string)
	if authURL == "" {
		t.Fatalf("auth_url response = %s", raw)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	if parsed.Query().Get("nonce") == "" {
		t.Fatalf("auth_url has no nonce: %s", authURL)
	}

	location := redirectTarget(t, apiClient, authURL)
	code := location.Query().Get("code")
	state := location.Query().Get("state")
	if code == "" || state == "" {
		t.Fatalf("provider redirect without code/state: %s", location)
	}

	cbResp, cbRaw, err := c.APIRequest(http.MethodGet,
		"auth/"+mount+"/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("oidc callback status = %d body = %s", cbResp.StatusCode, cbRaw)
	}
	auth, ok := DecodeJSON(t, cbRaw)["auth"].(map[string]any)
	if !ok {
		t.Fatalf("oidc callback response = %s", cbRaw)
	}
	token, _ := auth["client_token"].(string)
	if token == "" {
		t.Fatalf("oidc callback returned no client token: %s", cbRaw)
	}
	return token
}
