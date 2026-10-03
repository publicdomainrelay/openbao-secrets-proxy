package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type echoRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   map[string][]string `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type echoServer struct {
	*httptest.Server
	mu   sync.Mutex
	last echoRequest
	// status is the status code the server replies with.
	status int
	// contentType override for the reply.
	contentType string
	// extraHeaders are added to every reply.
	extraHeaders map[string]string
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	e := &echoServer{status: http.StatusOK, contentType: "application/json"}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		query := map[string][]string{}
		for k, v := range r.URL.Query() {
			query[k] = v
		}
		headers := map[string][]string{}
		for k, v := range r.Header {
			headers[k] = v
		}
		req := echoRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Query:   query,
			Headers: headers,
			Body:    string(raw),
		}
		e.mu.Lock()
		e.last = req
		status := e.status
		contentType := e.contentType
		extra := map[string]string{}
		for k, v := range e.extraHeaders {
			extra[k] = v
		}
		e.mu.Unlock()

		for k, v := range extra {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(req)
	}))
	t.Cleanup(e.Server.Close)
	return e
}

func (e *echoServer) lastRequest() echoRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

func (e *echoServer) setStatus(status int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status = status
}

func (e *echoServer) setHeader(key, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.extraHeaders == nil {
		e.extraHeaders = map[string]string{}
	}
	e.extraHeaders[key] = value
}

func (e *echoServer) header(header string) string {
	values := e.lastRequest().Headers[http.CanonicalHeaderKey(header)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
