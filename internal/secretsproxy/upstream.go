package secretsproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// openBaoOnlyHeaders are never forwarded upstream.
var openBaoOnlyHeaders = []string{
	"X-Vault-Token",
	"X-Vault-Namespace",
	"X-Vault-Request",
	"X-Vault-Wrap-Ttl",
	"Authorization",
}

type upstreamRequest struct {
	Method  string
	URL     *url.URL
	Header  http.Header
	Body    []byte
	Timeout time.Duration

	InsecureSkipVerify bool
	AllowInsecure      bool
	UserAgent          string
}

type upstreamResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *upstreamRequest) validate() error {
	if r.URL.Scheme == "http" && !r.AllowInsecure {
		return fmt.Errorf("upstream %s uses http; set allow_insecure_upstreams=true on the engine config to permit it", r.URL.Host)
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		return fmt.Errorf("unsupported upstream scheme %q", r.URL.Scheme)
	}
	return nil
}

func (r *upstreamRequest) do(ctx context.Context) (*upstreamResponse, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader
	if len(r.Body) > 0 {
		body = strings.NewReader(string(r.Body))
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), body)
	if err != nil {
		return nil, err
	}
	for k, values := range r.Header {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if r.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: r.InsecureSkipVerify}, //nolint:gosec
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream body: %w", err)
	}
	return &upstreamResponse{Status: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}
