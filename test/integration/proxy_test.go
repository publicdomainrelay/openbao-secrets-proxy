package integration

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestPluginIsLoadedAndConfigurable(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)

	cfg := c.MustJSON(t, "read", mountPath+"/config")
	data := cfg["data"].(map[string]any)
	if data["allow_insecure_upstreams"] != true {
		t.Fatalf("allow_insecure_upstreams = %v, want true", data["allow_insecure_upstreams"])
	}
}

func TestStaticCredentialInjectedIntoArbitraryHeader(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	c.MustWrite(t, mountPath+"/credentials/static-key", map[string]any{
		"value": "super-secret-value",
	})
	c.MustWrite(t, mountPath+"/routes/static", map[string]any{
		"upstream": upstream.URL,
		"inject": map[string]string{
			"X-Custom-Auth":   "static $cred:static-key",
			"X-Second-Secret": "raw:$cred:static-key",
		},
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/static/", nil, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}

	if got := upstream.header("X-Custom-Auth"); got != "static super-secret-value" {
		t.Fatalf("X-Custom-Auth = %q", got)
	}
	if got := upstream.header("X-Second-Secret"); got != "raw:super-secret-value" {
		t.Fatalf("X-Second-Secret = %q", got)
	}
}

func TestStructuredCredentialFieldInjection(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	c.MustWrite(t, mountPath+"/credentials/basic-auth", map[string]any{
		"values": map[string]string{"username": "alice", "password": "hunter2"},
	})
	c.MustWrite(t, mountPath+"/routes/structured", map[string]any{
		"upstream": upstream.URL,
		"inject": map[string]string{
			"X-User": "$cred:basic-auth:username",
			"X-Pass": "$cred:basic-auth:password",
		},
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/structured/", nil, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.header("X-User"); got != "alice" {
		t.Fatalf("X-User = %q", got)
	}
	if got := upstream.header("X-Pass"); got != "hunter2" {
		t.Fatalf("X-Pass = %q", got)
	}
}

func TestQueryPassthroughAndInjection(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	c.MustWrite(t, mountPath+"/credentials/api-key", map[string]any{"value": "key-123"})
	c.MustWrite(t, mountPath+"/routes/query", map[string]any{
		"upstream": upstream.URL,
		"inject_query": map[string]string{
			"api_key":  "$cred:api-key",
			"constant": "fixed",
		},
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/query/search?q=hello&page=2", nil, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	query := upstream.lastRequest().Query
	for key, want := range map[string]string{"q": "hello", "page": "2", "api_key": "key-123", "constant": "fixed"} {
		if got := query[key]; len(got) != 1 || got[0] != want {
			t.Fatalf("query[%s] = %v, want %q", key, got, want)
		}
	}
}

func TestJSONBodyForwardedAndMethodSelectedPerRoute(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	c.MustWrite(t, mountPath+"/routes/body", map[string]any{"upstream": upstream.URL})

	body := map[string]any{"name": "widget", "count": 3}
	resp, raw := c.MustProxy(t, http.MethodPost, "proxy/body/items", body, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	last := upstream.lastRequest()
	if last.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", last.Method)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(last.Body), &decoded); err != nil {
		t.Fatalf("body %q: %v", last.Body, err)
	}
	if decoded["name"] != "widget" || decoded["count"].(float64) != 3 {
		t.Fatalf("body = %v", decoded)
	}

	c.MustWrite(t, mountPath+"/routes/put-route", map[string]any{
		"upstream":      upstream.URL,
		"update_method": "PUT",
	})
	resp, raw = c.MustProxy(t, http.MethodPost, "proxy/put-route/items/7", body, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.lastRequest().Method; got != http.MethodPut {
		t.Fatalf("method = %s, want PUT", got)
	}
}

func TestMethodOverrideHeader(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	c.MustWrite(t, mountPath+"/routes/override", map[string]any{"upstream": upstream.URL})

	req, err := http.NewRequest(http.MethodPost, c.addr+"/v1/"+mountPath+"/proxy/override/thing", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", rootToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Proxy-Method", "PATCH")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := upstream.lastRequest().Method; got != http.MethodPatch {
		t.Fatalf("method = %s, want PATCH", got)
	}
	if got := upstream.header("X-Proxy-Method"); got != "" {
		t.Fatalf("X-Proxy-Method leaked upstream: %q", got)
	}
}

func TestClientHeadersAreForwardedWhenTuned(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	c.MustWrite(t, mountPath+"/routes/forward-headers", map[string]any{"upstream": upstream.URL})

	req, err := http.NewRequest(http.MethodGet, c.addr+"/v1/"+mountPath+"/proxy/forward-headers/thing", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", rootToken)
	req.Header.Set("Accept", "application/vnd.custom+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := upstream.header("Accept"); got != "application/vnd.custom+json" {
		t.Fatalf("Accept = %q", got)
	}
	if got := upstream.header("X-Vault-Token"); got != "" {
		t.Fatalf("X-Vault-Token leaked upstream: %q", got)
	}
}

func TestPathRewriteWithStripPrefix(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	c.MustWrite(t, mountPath+"/routes/strip", map[string]any{
		"upstream":     upstream.URL + "/api",
		"strip_prefix": "v2",
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/strip/v2/users/9", nil, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.lastRequest().Path; got != "/api/users/9" {
		t.Fatalf("path = %q, want /api/users/9", got)
	}
}

func TestUpstreamStatusAndBodyPassthrough(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	upstream.setStatus(http.StatusTeapot)
	upstream.setHeader("WWW-Authenticate", `Bearer realm="upstream"`)

	c.MustWrite(t, mountPath+"/routes/status", map[string]any{"upstream": upstream.URL})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/status/teapot", nil, rootToken)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="upstream"` {
		t.Fatalf("www-authenticate = %q", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("body %q: %v", raw, err)
	}
}

func TestEnvelopeMode(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	upstream.setStatus(http.StatusCreated)
	upstream.setHeader("X-Upstream-Only", "visible")

	c.MustWrite(t, mountPath+"/routes/envelope", map[string]any{
		"upstream": upstream.URL,
		"mode":     "envelope",
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/envelope/thing", nil, rootToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	decoded := DecodeJSON(t, raw)
	data := decoded["data"].(map[string]any)
	if int(data["status_code"].(float64)) != http.StatusCreated {
		t.Fatalf("status_code = %v", data["status_code"])
	}
	headers := data["headers"].(map[string]any)
	if _, ok := headers["X-Upstream-Only"]; !ok {
		t.Fatalf("envelope headers missing upstream header: %v", headers)
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/does-not-exist/", nil, rootToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
}

func TestMissingCredentialIs400(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	c.MustWrite(t, mountPath+"/routes/missing-cred", map[string]any{
		"upstream": upstream.URL,
		"inject":   map[string]string{"X-Key": "$cred:nope"},
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/missing-cred/", nil, rootToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "nope") {
		t.Fatalf("body = %s", raw)
	}
}

func TestRequireEntityRejectsEntitylessToken(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	c.MustWrite(t, mountPath+"/routes/needs-entity", map[string]any{
		"upstream":       upstream.URL,
		"require_entity": true,
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/needs-entity/", nil, rootToken)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
}

func TestEntityTemplatesResolveForUserpassToken(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)

	c.MustRun(t, "auth", "enable", "-path=userpass-it", "userpass")
	c.MustPolicy(t, "secrets-proxy-caller",
		"path \""+mountPath+"/proxy/*\" {\n  capabilities = [\"read\", \"create\", \"update\", \"delete\", \"list\"]\n}\n")
	c.MustRun(t, "write", "auth/userpass-it/users/alice",
		"password=hunter2", "policies=default,secrets-proxy-caller")

	login := c.MustJSON(t, "write", "auth/userpass-it/login/alice", "password=hunter2")
	clientToken := login["auth"].(map[string]any)["client_token"].(string)

	c.MustWrite(t, mountPath+"/routes/entity", map[string]any{
		"upstream":       upstream.URL,
		"require_entity": true,
		"inject": map[string]string{
			"X-Entity-Id":    "$entity:id",
			"X-Entity-Alias": "$entity:alias",
		},
	})

	resp, raw := c.MustProxy(t, http.MethodGet, "proxy/entity/whoami", nil, clientToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	if got := upstream.header("X-Entity-Id"); got == "" {
		t.Fatal("X-Entity-Id was empty")
	}
	if got := upstream.header("X-Entity-Alias"); got != "alice" {
		t.Fatalf("X-Entity-Alias = %q, want alice", got)
	}
	if got := upstream.header("X-Vault-Token"); got != "" {
		t.Fatalf("X-Vault-Token leaked upstream: %q", got)
	}
}

func TestCredentialListAndDelete(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)

	c.MustWrite(t, mountPath+"/credentials/temp", map[string]any{"value": "x"})
	keys := c.MustList(t, mountPath+"/credentials")
	if !contains(keys, "temp") {
		t.Fatalf("credential 'temp' missing from %v", keys)
	}
	c.MustRun(t, "delete", mountPath+"/credentials/temp")
	if _, err := c.Run("read", mountPath+"/credentials/temp"); err == nil {
		t.Fatal("expected read of deleted credential to fail")
	}
}

func TestRouteList(t *testing.T) {
	c := Cluster(t)
	Configure(t, c)
	upstream := newEchoServer(t)
	c.MustWrite(t, mountPath+"/routes/listed", map[string]any{"upstream": upstream.URL})

	keys := c.MustList(t, mountPath+"/routes")
	if !contains(keys, "listed") {
		t.Fatalf("route 'listed' missing from %v", keys)
	}
}

func contains(values []string, want string) bool {
	return slices.Contains(values, want)
}
