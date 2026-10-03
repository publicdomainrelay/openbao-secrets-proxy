// Command echo-upstream is a tiny stand-in for a protected API. It echoes the
// request it received so you can see exactly which headers the secrets-proxy
// engine injected.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9099", "address to listen on")
	required := flag.String("require-header", "", "reject requests missing this header")
	expected := flag.String("require-value", "", "reject requests whose --require-header does not have this value")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *required != "" {
			if r.Header.Get(*required) != *expected {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":   "unauthorized",
					"message": "missing or wrong " + *required,
					"got":     r.Header.Get(*required),
				})
				return
			}
		}

		headers := map[string][]string{}
		for k, v := range r.Header {
			headers[k] = v
		}

		query := map[string][]string{}
		for k, v := range r.URL.Query() {
			query[k] = v
		}

		var body string
		if r.Body != nil {
			buf := make([]byte, 32*1024)
			n, _ := r.Body.Read(buf)
			body = string(buf[:n])
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo-Server", "echo-upstream")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method":  r.Method,
			"path":    r.URL.Path,
			"query":   query,
			"headers": headers,
			"body":    strings.TrimSpace(body),
		})
	})

	log.Printf("echo-upstream listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
