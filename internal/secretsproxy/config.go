package secretsproxy

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type backendConfig struct {
	RequestTimeout         time.Duration `json:"request_timeout"`
	OAuthStateTTL          time.Duration `json:"oauth_state_ttl"`
	AllowInsecureUpstreams bool          `json:"allow_insecure_upstreams"`
	PublicURL              string        `json:"public_url"`
	UserAgent              string        `json:"user_agent"`
}

func defaultConfig() *backendConfig {
	return &backendConfig{
		RequestTimeout: 30 * time.Second,
		OAuthStateTTL:  10 * time.Minute,
		UserAgent:      "openbao-secrets-proxy",
	}
}

func (b *Backend) loadConfig(ctx context.Context, s logical.Storage) (*backendConfig, error) {
	cfg, err := readJSON[backendConfig](ctx, s, configStorageKey)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return defaultConfig(), nil
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.OAuthStateTTL <= 0 {
		cfg.OAuthStateTTL = 10 * time.Minute
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "openbao-secrets-proxy"
	}
	return cfg, nil
}

func (b *Backend) pathsConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"request_timeout": {
					Type:        framework.TypeDurationSecond,
					Description: "Default upstream request timeout in seconds.",
				},
				"oauth_state_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "How long an OAuth authorization state nonce stays valid, in seconds.",
				},
				"allow_insecure_upstreams": {
					Type:        framework.TypeBool,
					Description: "Allow http:// upstream URLs and TLS verification skips.",
				},
				"public_url": {
					Type:        framework.TypeString,
					Description: "Externally reachable OpenBao base URL used to build OAuth redirect URIs.",
				},
				"user_agent": {
					Type:        framework.TypeString,
					Description: "User-Agent sent to upstreams.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			},
			HelpSynopsis:    "Configure defaults for the secrets-proxy engine.",
			HelpDescription: "Sets the default upstream timeout, OAuth state TTL, public URL and User-Agent.",
		},
	}
}

func (b *Backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if v, ok := d.GetOk("request_timeout"); ok {
		cfg.RequestTimeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("oauth_state_ttl"); ok {
		cfg.OAuthStateTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("allow_insecure_upstreams"); ok {
		cfg.AllowInsecureUpstreams = v.(bool)
	}
	if v, ok := d.GetOk("public_url"); ok {
		cfg.PublicURL = v.(string)
	}
	if v, ok := d.GetOk("user_agent"); ok {
		cfg.UserAgent = v.(string)
	}
	if err := writeJSON(ctx, req.Storage, configStorageKey, cfg); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *Backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"request_timeout":          int(cfg.RequestTimeout.Seconds()),
		"oauth_state_ttl":          int(cfg.OAuthStateTTL.Seconds()),
		"allow_insecure_upstreams": cfg.AllowInsecureUpstreams,
		"public_url":               cfg.PublicURL,
		"user_agent":               cfg.UserAgent,
	}}, nil
}
