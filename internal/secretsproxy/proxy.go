package secretsproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const methodOverrideHeader = "X-Proxy-Method"

func (b *Backend) pathsProxy() []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"route": {
			Type:        framework.TypeString,
			Description: "Route name.",
		},
		"rest": {
			Type:        framework.TypeString,
			Description: "Sub-path forwarded to the upstream.",
		},
	}
	ops := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation:   &framework.PathOperation{Callback: b.pathProxy},
		logical.HeaderOperation: &framework.PathOperation{Callback: b.pathProxy},
		logical.CreateOperation: &framework.PathOperation{Callback: b.pathProxy},
		logical.UpdateOperation: &framework.PathOperation{Callback: b.pathProxy},
		logical.PatchOperation:  &framework.PathOperation{Callback: b.pathProxy},
		logical.DeleteOperation: &framework.PathOperation{Callback: b.pathProxy},
		logical.ListOperation:   &framework.PathOperation{Callback: b.pathProxy},
	}
	return []*framework.Path{
		{
			Pattern:             "proxy/" + framework.GenericNameRegex("route"),
			Fields:              fields,
			Operations:          ops,
			TakesArbitraryInput: true,
			HelpSynopsis:        "Proxy a request to a route's upstream.",
			HelpDescription:     "Injects the route's configured secrets into headers and query parameters.",
		},
		{
			Pattern:             "proxy/" + framework.GenericNameRegex("route") + "/" + framework.MatchAllRegex("rest"),
			Fields:              fields,
			Operations:          ops,
			TakesArbitraryInput: true,
			HelpSynopsis:        "Proxy a request to a route's upstream sub-path.",
			HelpDescription:     "Injects the route's configured secrets into headers and query parameters.",
		},
	}
}

func (b *Backend) pathProxy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("route").(string)
	rest := strings.TrimPrefix(d.Get("rest").(string), "/")

	route, err := b.loadRoute(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, logical.CodedError(http.StatusNotFound, fmt.Sprintf("route %q not found", name))
	}
	if route.RequireEntity && req.EntityID == "" {
		return nil, logical.CodedError(http.StatusForbidden, "route requires an identity entity and this token has none")
	}

	cfg, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	entity, err := b.entityInfo(ctx, req)
	if err != nil {
		return nil, err
	}

	res := &resolver{
		ctx:      ctx,
		storage:  req.Storage,
		entityID: req.EntityID,
		entity:   entity,
		provider: func(providerName string) (*oauthProvider, error) {
			return b.loadProvider(ctx, req.Storage, providerName)
		},
	}

	upstream, err := route.upstreamURL()
	if err != nil {
		return nil, logical.CodedError(http.StatusBadGateway, err.Error())
	}

	header := b.buildUpstreamHeaders(req, route)
	for key, tpl := range route.Inject {
		value, err := render(tpl, res)
		if err != nil {
			return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("inject %s: %v", key, err))
		}
		header.Set(key, value)
	}
	for key, value := range route.ExtraHeaders {
		header.Set(key, value)
	}

	query := upstream.Query()
	if route.PassthroughQuery {
		for k, v := range passthroughValues(req) {
			query.Set(k, v)
		}
	}
	for key, tpl := range route.InjectQuery {
		value, err := render(tpl, res)
		if err != nil {
			return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("inject_query %s: %v", key, err))
		}
		query.Set(key, value)
	}
	upstream.RawQuery = query.Encode()

	upstream.Path = joinPath(upstream.Path, strings.TrimPrefix(rest, route.StripPrefix))

	method, err := b.upstreamMethod(req, route)
	if err != nil {
		return nil, logical.CodedError(http.StatusBadRequest, err.Error())
	}

	body, contentType, err := requestBody(req)
	if err != nil {
		return nil, logical.CodedError(http.StatusBadRequest, err.Error())
	}
	if contentType != "" && header.Get("Content-Type") == "" {
		header.Set("Content-Type", contentType)
	}

	resp, err := (&upstreamRequest{
		Method:             method,
		URL:                upstream,
		Header:             header,
		Body:               body,
		Timeout:            routeTimeout(route, cfg),
		InsecureSkipVerify: route.InsecureSkipVerify && cfg.AllowInsecureUpstreams,
		AllowInsecure:      cfg.AllowInsecureUpstreams,
		UserAgent:          cfg.UserAgent,
	}).do(ctx)
	if err != nil {
		return nil, logical.CodedError(http.StatusBadGateway, fmt.Sprintf("upstream %s: %v", upstream.Host, err))
	}

	return renderProxyResponse(route, resp), nil
}

func (b *Backend) entityInfo(ctx context.Context, req *logical.Request) (*logical.Entity, error) {
	if req.EntityID == "" || b.system == nil {
		return nil, nil
	}
	return b.system.EntityInfo(req.EntityID)
}

func (b *Backend) buildUpstreamHeaders(req *logical.Request, route *routeConfig) http.Header {
	header := http.Header{}
	for key, values := range req.Headers {
		if isDroppedHeader(key) {
			continue
		}
		for _, v := range values {
			header.Add(key, v)
		}
	}
	clientIP := ""
	if req.Connection != nil {
		clientIP = req.Connection.RemoteAddr
	}
	if clientIP != "" {
		appendForwarded(header, "X-Forwarded-For", clientIP)
	}
	if host := firstHeader(req.Headers, "Host"); host != "" {
		header.Set("X-Forwarded-Host", host)
		header.Set("X-Forwarded-Proto", firstNonEmpty(firstHeader(req.Headers, "X-Forwarded-Proto"), "http"))
	}
	return header
}

func isDroppedHeader(key string) bool {
	canonical := http.CanonicalHeaderKey(key)
	if canonical == "Host" {
		return true
	}
	for _, h := range hopByHopHeaders {
		if canonical == http.CanonicalHeaderKey(h) {
			return true
		}
	}
	for _, h := range openBaoOnlyHeaders {
		if canonical == http.CanonicalHeaderKey(h) {
			return true
		}
	}
	return canonical == http.CanonicalHeaderKey(methodOverrideHeader)
}

func appendForwarded(header http.Header, key, value string) {
	if existing := header.Get(key); existing != "" {
		header.Set(key, existing+", "+value)
		return
	}
	header.Set(key, value)
}

func firstHeader(header http.Header, key string) string {
	if header == nil {
		return ""
	}
	values := header.Values(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (b *Backend) upstreamMethod(req *logical.Request, route *routeConfig) (string, error) {
	if override := firstHeader(req.Headers, methodOverrideHeader); override != "" {
		return strings.ToUpper(override), nil
	}
	switch req.Operation {
	case logical.ReadOperation, logical.ListOperation:
		return http.MethodGet, nil
	case logical.HeaderOperation:
		return http.MethodHead, nil
	case logical.DeleteOperation:
		return http.MethodDelete, nil
	case logical.PatchOperation:
		return http.MethodPatch, nil
	case logical.CreateOperation, logical.UpdateOperation:
		return route.UpdateMethod, nil
	}
	return "", fmt.Errorf("unsupported operation %q", req.Operation)
}

func requestBody(req *logical.Request) ([]byte, string, error) {
	switch req.Operation {
	case logical.CreateOperation, logical.UpdateOperation, logical.PatchOperation:
	default:
		return nil, "", nil
	}
	if len(req.Data) == 0 {
		return nil, "", nil
	}
	contentType := firstHeader(req.Headers, "Content-Type")
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		form := url.Values{}
		for k, v := range req.Data {
			form.Set(k, fmt.Sprint(v))
		}
		return []byte(form.Encode()), "application/x-www-form-urlencoded", nil
	}
	raw, err := json.Marshal(req.Data)
	if err != nil {
		return nil, "", fmt.Errorf("encode request body: %w", err)
	}
	return raw, "application/json", nil
}

func passthroughValues(req *logical.Request) map[string]string {
	out := map[string]string{}
	switch req.Operation {
	case logical.ReadOperation, logical.ListOperation, logical.DeleteOperation, logical.HeaderOperation:
	default:
		return out
	}
	for k, v := range req.Data {
		switch value := v.(type) {
		case string:
			out[k] = value
		case []string:
			out[k] = strings.Join(value, ",")
		case []any:
			parts := make([]string, 0, len(value))
			for _, e := range value {
				parts = append(parts, fmt.Sprint(e))
			}
			out[k] = strings.Join(parts, ",")
		}
	}
	return out
}

func joinPath(base, rest string) string {
	switch {
	case rest == "":
		return base
	case base == "" || base == "/":
		return "/" + rest
	}
	return path.Join(base, rest)
}

func routeTimeout(route *routeConfig, cfg *backendConfig) time.Duration {
	if route.Timeout > 0 {
		return route.Timeout
	}
	return cfg.RequestTimeout
}

func renderProxyResponse(route *routeConfig, resp *upstreamResponse) *logical.Response {
	contentType := resp.Header.Get("Content-Type")
	if route.Mode == modeEnvelope {
		headers := map[string][]string{}
		for k, v := range resp.Header {
			headers[k] = v
		}
		return &logical.Response{Data: map[string]any{
			"status_code": resp.Status,
			"headers":     headers,
			"body":        string(resp.Body),
		}}
	}

	data := map[string]any{
		logical.HTTPStatusCode: resp.Status,
	}
	if resp.Status != http.StatusNoContent {
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		data[logical.HTTPContentType] = contentType
		data[logical.HTTPRawBody] = resp.Body
	}
	if v := resp.Header.Get("Cache-Control"); v != "" {
		data[logical.HTTPCacheControlHeader] = v
	}
	if v := resp.Header.Get("Pragma"); v != "" {
		data[logical.HTTPPragmaHeader] = v
	}
	if v := resp.Header.Get("WWW-Authenticate"); v != "" {
		data[logical.HTTPWWWAuthenticateHeader] = v
	}
	return &logical.Response{Data: data}
}
