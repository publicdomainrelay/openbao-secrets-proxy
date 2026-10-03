package secretsproxy

import "testing"

func TestHasScheme(t *testing.T) {
	for input, want := range map[string]bool{
		"https://api.example.com":  true,
		"http://127.0.0.1:9099":    true,
		"HTTP://api.example.com":   true,
		"api.example.com":          false,
		"api.example.com:8080":     false,
		"api.example.com:8080/api": false,
		"127.0.0.1:9099":           false,
		"":                         false,
		"/relative/path":           false,
		"1nvalid://host":           false,
	} {
		if got := hasScheme(input); got != want {
			t.Errorf("hasScheme(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestUpstreamURLDefaultsToHTTPS(t *testing.T) {
	cfg := &routeConfig{Name: "r", Upstream: "api.example.com:8443"}
	u, err := cfg.upstreamURL()
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "api.example.com:8443" {
		t.Fatalf("got %s://%s", u.Scheme, u.Host)
	}
}

func TestStripRoutePrefix(t *testing.T) {
	for _, tc := range []struct {
		rest, prefix, want string
	}{
		{"v2/users/9", "v2", "/users/9"},
		{"v2", "v2", ""},
		{"/v2/users", "/v2/", "/users"},
		{"v20/users", "v2", "v20/users"},
		{"users", "v2", "users"},
		{"users", "", "users"},
	} {
		if got := stripRoutePrefix(tc.rest, tc.prefix); got != tc.want {
			t.Errorf("stripRoutePrefix(%q, %q) = %q, want %q", tc.rest, tc.prefix, got, tc.want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	for _, tc := range []struct {
		base, rest, want string
	}{
		{"", "", ""},
		{"/api", "", "/api"},
		{"", "users", "/users"},
		{"/api", "users/9", "/api/users/9"},
		{"/api/", "/users", "/api/users"},
	} {
		if got := joinPath(tc.base, tc.rest); got != tc.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tc.base, tc.rest, got, tc.want)
		}
	}
}
