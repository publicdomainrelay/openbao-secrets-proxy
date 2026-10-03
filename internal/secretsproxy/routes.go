package secretsproxy

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	modeRaw      = "raw"
	modeEnvelope = "envelope"

	updateMethodPost  = "POST"
	updateMethodPut   = "PUT"
	updateMethodPatch = "PATCH"
)

type routeConfig struct {
	Name               string            `json:"name"`
	Upstream           string            `json:"upstream"`
	StripPrefix        string            `json:"strip_prefix"`
	Inject             map[string]string `json:"inject"`
	InjectQuery        map[string]string `json:"inject_query"`
	RequireEntity      bool              `json:"require_entity"`
	Timeout            time.Duration     `json:"timeout"`
	Mode               string            `json:"mode"`
	PassthroughQuery   bool              `json:"passthrough_query"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
	UpdateMethod       string            `json:"update_method"`
	ExtraHeaders       map[string]string `json:"extra_headers"`
}

func defaultRoute(name string) *routeConfig {
	return &routeConfig{
		Name:             name,
		Mode:             modeRaw,
		PassthroughQuery: true,
		UpdateMethod:     updateMethodPost,
		Inject:           map[string]string{},
		InjectQuery:      map[string]string{},
		ExtraHeaders:     map[string]string{},
	}
}

func (r *routeConfig) upstreamURL() (*url.URL, error) {
	if r.Upstream == "" {
		return nil, fmt.Errorf("route %q has no upstream", r.Name)
	}
	raw := r.Upstream
	if !hasScheme(raw) {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("route %q upstream %q: %w", r.Name, r.Upstream, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("route %q upstream %q has no host", r.Name, r.Upstream)
	}
	return u, nil
}

// hasScheme reports whether raw starts with a URL scheme, i.e. matches
// "^[a-zA-Z][a-zA-Z0-9+.-]*://". A bare "host:port/path" is not a scheme.
func hasScheme(raw string) bool {
	i := 0
	for i < len(raw) {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return false
			}
		default:
			return strings.HasPrefix(raw[i:], "://") && i > 0
		}
		i++
	}
	return false
}

// stripRoutePrefix removes prefix from rest only at a path segment boundary.
func stripRoutePrefix(rest, prefix string) string {
	if prefix == "" {
		return rest
	}
	prefix = strings.Trim(prefix, "/")
	trimmed := strings.TrimPrefix(rest, "/")
	switch {
	case trimmed == prefix:
		return ""
	case strings.HasPrefix(trimmed, prefix+"/"):
		return "/" + trimmed[len(prefix)+1:]
	}
	return rest
}

func (b *Backend) loadRoute(ctx context.Context, s logical.Storage, name string) (*routeConfig, error) {
	return readJSON[routeConfig](ctx, s, routePrefix+name)
}

func (b *Backend) pathsRoutes() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "routes/?",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRouteList},
			},
			HelpSynopsis:    "List configured proxy routes.",
			HelpDescription: "Returns the names of every configured route.",
		},
		{
			Pattern: "routes/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Route name.",
				},
				"upstream": {
					Type:        framework.TypeString,
					Description: "Upstream base URL, for example https://api.github.com.",
				},
				"strip_prefix": {
					Type:        framework.TypeString,
					Description: "Prefix removed from the proxied sub-path before it is joined to the upstream.",
				},
				"inject": {
					Type:        framework.TypeMap,
					Description: "Header name to template map, for example Authorization=\"Bearer $oauth:github\".",
				},
				"inject_query": {
					Type:        framework.TypeMap,
					Description: "Query parameter name to template map.",
				},
				"require_entity": {
					Type:        framework.TypeBool,
					Description: "Reject requests whose token has no identity entity.",
				},
				"timeout": {
					Type:        framework.TypeDurationSecond,
					Description: "Upstream request timeout in seconds.",
				},
				"mode": {
					Type:          framework.TypeString,
					Description:   "raw returns the upstream body and status unchanged; envelope wraps them in JSON.",
					AllowedValues: []any{modeRaw, modeEnvelope},
				},
				"passthrough_query": {
					Type:        framework.TypeBool,
					Description: "Forward read/delete/list query parameters to the upstream.",
				},
				"insecure_skip_verify": {
					Type:        framework.TypeBool,
					Description: "Skip TLS verification for this route's upstream.",
				},
				"update_method": {
					Type:          framework.TypeString,
					Description:   "HTTP method used for OpenBao update operations (POST/PUT/PATCH).",
					AllowedValues: []any{updateMethodPost, updateMethodPut, updateMethodPatch},
				},
				"extra_headers": {
					Type:        framework.TypeMap,
					Description: "Static headers added to every upstream request.",
				},
			},
			ExistenceCheck: b.pathRouteExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRouteWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRouteWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRouteRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRouteDelete},
			},
			HelpSynopsis:    "Manage a proxy route.",
			HelpDescription: "A route names an upstream API and the secrets injected into its requests.",
		},
	}
}

func (b *Backend) pathRouteExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	route, err := b.loadRoute(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return route != nil, nil
}

func (b *Backend) pathRouteList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := listNames(ctx, req.Storage, routePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *Backend) pathRouteWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	route, err := b.loadRoute(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if route == nil {
		route = defaultRoute(name)
	}

	if v, ok := d.GetOk("upstream"); ok {
		route.Upstream = v.(string)
	}
	if v, ok := d.GetOk("strip_prefix"); ok {
		route.StripPrefix = v.(string)
	}
	if v, ok := d.GetOk("inject"); ok {
		route.Inject = toStringMap(v)
	}
	if v, ok := d.GetOk("inject_query"); ok {
		route.InjectQuery = toStringMap(v)
	}
	if v, ok := d.GetOk("require_entity"); ok {
		route.RequireEntity = v.(bool)
	}
	if v, ok := d.GetOk("timeout"); ok {
		route.Timeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("mode"); ok {
		route.Mode = v.(string)
	}
	if v, ok := d.GetOk("passthrough_query"); ok {
		route.PassthroughQuery = v.(bool)
	}
	if v, ok := d.GetOk("insecure_skip_verify"); ok {
		route.InsecureSkipVerify = v.(bool)
	}
	if v, ok := d.GetOk("update_method"); ok {
		route.UpdateMethod = v.(string)
	}
	if v, ok := d.GetOk("extra_headers"); ok {
		route.ExtraHeaders = toStringMap(v)
	}

	if route.Upstream == "" {
		return logical.ErrorResponse("upstream is required"), nil
	}
	if _, err := route.upstreamURL(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if route.Mode == "" {
		route.Mode = modeRaw
	}
	if route.UpdateMethod == "" {
		route.UpdateMethod = updateMethodPost
	}

	if err := writeJSON(ctx, req.Storage, routePrefix+name, route); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *Backend) pathRouteRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	route, err := b.loadRoute(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, nil
	}
	return &logical.Response{Data: map[string]any{
		"name":                 route.Name,
		"upstream":             route.Upstream,
		"strip_prefix":         route.StripPrefix,
		"inject":               route.Inject,
		"inject_query":         route.InjectQuery,
		"require_entity":       route.RequireEntity,
		"timeout":              int(route.Timeout.Seconds()),
		"mode":                 route.Mode,
		"passthrough_query":    route.PassthroughQuery,
		"insecure_skip_verify": route.InsecureSkipVerify,
		"update_method":        route.UpdateMethod,
		"extra_headers":        route.ExtraHeaders,
	}}, nil
}

func (b *Backend) pathRouteDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, routePrefix+d.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func toStringMap(v any) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]string:
		for k, val := range m {
			out[k] = val
		}
	case map[string]any:
		for k, val := range m {
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}
