package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	pluginName = "openbao-secrets-proxy"
	mountPath  = "secrets-proxy"
	rootToken  = "root"
)

// cluster is a live OpenBao dev server with the plugin registered and mounted.
type cluster struct {
	t          *testing.T
	addr       string
	token      string
	pluginDir  string
	configPath string
	logPath    string
	cmd        *exec.Cmd
	baoBin     string
}

var (
	sharedOnce sync.Once
	shared     *cluster
	sharedErr  error
)

// Cluster returns the process-wide dev server, starting it on first use.
func Cluster(t *testing.T) *cluster {
	t.Helper()
	sharedOnce.Do(func() {
		shared, sharedErr = startCluster()
	})
	if sharedErr != nil {
		t.Fatalf("start cluster: %v", sharedErr)
	}
	shared.t = t
	return shared
}

func startCluster() (*cluster, error) {
	baoBin, err := exec.LookPath("bao")
	if err != nil {
		if v := os.Getenv("BAO_BIN"); v != "" {
			baoBin = v
		} else {
			return nil, fmt.Errorf("bao binary not found: %w", err)
		}
	}

	workDir, err := os.MkdirTemp("", "secrets-proxy-it-")
	if err != nil {
		return nil, err
	}

	root, err := findRepoRoot()
	if err != nil {
		return nil, err
	}

	pluginDir := filepath.Join(workDir, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return nil, err
	}

	binary := filepath.Join(pluginDir, pluginName)
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = root
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return nil, fmt.Errorf("build plugin: %w", err)
	}

	configPath := filepath.Join(workDir, "openbao.hcl")
	if err := os.WriteFile(configPath, fmt.Appendf(nil, "plugin_directory = %q\n", pluginDir), 0o644); err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	logPath := filepath.Join(workDir, "openbao.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(baoBin, "server", "-dev",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address=127.0.0.1:"+fmt.Sprint(port),
		"-config="+configPath,
	)
	cmd.Env = append(os.Environ(), "BAO_ADDR="+addr, "BAO_TOKEN="+rootToken)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	c := &cluster{
		addr:       addr,
		token:      rootToken,
		pluginDir:  pluginDir,
		configPath: configPath,
		logPath:    logPath,
		cmd:        cmd,
		baoBin:     baoBin,
	}
	if err := c.waitReady(30 * time.Second); err != nil {
		c.Stop()
		return nil, err
	}
	if err := c.registerAndMount(binary); err != nil {
		c.Stop()
		return nil, err
	}
	return c, nil
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

func (c *cluster) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(c.addr + "/v1/sys/health")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("openbao did not become ready; see %s", c.logPath)
}

func (c *cluster) registerAndMount(binary string) error {
	raw, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)

	if _, err := c.Run("plugin", "register",
		"-sha256="+hex.EncodeToString(sum[:]),
		"-command="+pluginName,
		"secret", pluginName,
	); err != nil {
		return fmt.Errorf("plugin register: %w", err)
	}
	if _, err := c.Run("secrets", "enable",
		"-path="+mountPath,
		"-plugin-name="+pluginName,
		"plugin",
	); err != nil {
		return fmt.Errorf("secrets enable: %w", err)
	}
	tuneArgs := []string{"secrets", "tune"}
	for _, header := range PassthroughRequestHeaders {
		tuneArgs = append(tuneArgs, "-passthrough-request-headers="+header)
	}
	tuneArgs = append(tuneArgs, mountPath)
	if _, err := c.Run(tuneArgs...); err != nil {
		return fmt.Errorf("secrets tune: %w", err)
	}
	return nil
}

// PassthroughRequestHeaders is the mount tuning an operator applies so the
// engine can see the client's own request headers. OpenBao strips every header
// that is not listed here, and always strips X-Vault-Token.
var PassthroughRequestHeaders = []string{
	"Accept",
	"Accept-Language",
	"Content-Type",
	"If-Match",
	"If-None-Match",
	"If-Modified-Since",
	"X-Proxy-Method",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Real-Ip",
	"User-Agent",
	"Cookie",
}

// Run executes a bao CLI command against the dev server.
func (c *cluster) Run(args ...string) (string, error) {
	cmd := exec.Command(c.baoBin, args...)
	cmd.Env = append(os.Environ(),
		"BAO_ADDR="+c.addr,
		"BAO_TOKEN="+c.token,
		"BAO_FORMAT=json",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("bao %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// MustRun runs a bao CLI command and fails the test on error.
func (c *cluster) MustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := c.Run(args...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

// MustJSON runs a bao CLI command and decodes its JSON output.
func (c *cluster) MustJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out := c.MustRun(t, args...)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decode %q output %q: %v", strings.Join(args, " "), out, err)
	}
	return decoded
}

func (c *cluster) Stop() {
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
	}
}

// apiClient never follows redirects: proxied responses and OAuth callbacks can
// legitimately be redirects that the test needs to inspect.
var apiClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// APIRequest performs a raw HTTP request against the OpenBao API.
func (c *cluster) APIRequest(method, path string, body any, token string) (*http.Response, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.addr+"/v1/"+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, raw, nil
}

// Proxy performs an authenticated request through the mounted engine.
func (c *cluster) Proxy(method, path string, body any, token string) (*http.Response, []byte, error) {
	return c.APIRequest(method, mountPath+"/"+strings.TrimPrefix(path, "/"), body, token)
}

// MustProxy fails the test when the request cannot be performed.
func (c *cluster) MustProxy(t *testing.T, method, path string, body any, token string) (*http.Response, []byte) {
	t.Helper()
	resp, raw, err := c.Proxy(method, path, body, token)
	if err != nil {
		t.Fatalf("proxy %s %s: %v", method, path, err)
	}
	return resp, raw
}

// CallerPolicy grants a non-root token access to the engine's caller-facing
// paths. Root tokens bypass ACLs, so any test that uses an identity-backed
// token needs this.
const CallerPolicy = `
path "` + mountPath + `/proxy/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
path "` + mountPath + `/oauth/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
path "` + mountPath + `/credentials/*" {
  capabilities = ["read", "list"]
}
path "` + mountPath + `/routes/*" {
  capabilities = ["read", "list"]
}
`

// EntityToken creates a userpass user and returns a login token that carries an
// identity entity.
func EntityToken(t *testing.T, c *cluster, username string) string {
	t.Helper()
	c.Run("auth", "enable", "-path=userpass-it", "userpass")
	c.MustPolicy(t, "secrets-proxy-caller", CallerPolicy)
	c.MustRun(t, "write", "auth/userpass-it/users/"+username,
		"password=hunter2", "policies=default,secrets-proxy-caller")
	login := c.MustJSON(t, "write", "auth/userpass-it/login/"+username, "password=hunter2")
	auth, ok := login["auth"].(map[string]any)
	if !ok {
		t.Fatalf("login response = %v", login)
	}
	token, ok := auth["client_token"].(string)
	if !ok || token == "" {
		t.Fatalf("login response has no client token: %v", login)
	}
	return token
}

// Data returns the data object of an OpenBao response.
func Data(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoded := DecodeJSON(t, raw)
	data, ok := decoded["data"].(map[string]any)
	if !ok {
		t.Fatalf("response has no data object: %s", raw)
	}
	return data
}

// MustPolicy writes an HCL policy.
func (c *cluster) MustPolicy(t *testing.T, name, hcl string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), name+".hcl")
	if err := os.WriteFile(file, []byte(hcl), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	c.MustRun(t, "policy", "write", name, file)
}

// MustList runs a bao list command and returns the returned keys.
func (c *cluster) MustList(t *testing.T, path string) []string {
	t.Helper()
	out := c.MustRun(t, "list", path)
	var keys []string
	if err := json.Unmarshal([]byte(out), &keys); err != nil {
		t.Fatalf("decode list %q output %q: %v", path, out, err)
	}
	return keys
}

// MustWrite writes structured data through the bao CLI. The CLI only decodes
// JSON when the whole body is passed as @file, which is required for map and
// list typed fields.
func (c *cluster) MustWrite(t *testing.T, path string, data map[string]any) {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal %v: %v", data, err)
	}
	file := filepath.Join(t.TempDir(), "body.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatalf("write body file: %v", err)
	}
	c.MustRun(t, "write", path, "@"+file)
}

// DecodeJSON decodes a JSON body, failing the test on error.
func DecodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode json %q: %v", string(raw), err)
	}
	return out
}

// Configure applies engine configuration used by every test.
func Configure(t *testing.T, c *cluster) {
	t.Helper()
	c.MustRun(t, "write", mountPath+"/config",
		"allow_insecure_upstreams=true",
		"public_url="+c.addr,
	)
}
