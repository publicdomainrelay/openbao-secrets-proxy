package secretsproxy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/oauth2"

	"github.com/publicdomainrelay/openbao-secrets-proxy/internal/oauthclient"
)

const (
	storeModeEntity = "entity"
	storeModeShared = "shared"
)

type oauthProvider struct {
	Name               string            `json:"name"`
	AuthorizeURL       string            `json:"authorize_url"`
	TokenURL           string            `json:"token_url"`
	ClientID           string            `json:"client_id"`
	ClientSecret       string            `json:"client_secret"`
	Scopes             []string          `json:"scopes"`
	RedirectURL        string            `json:"redirect_url"`
	Audience           string            `json:"audience"`
	ExtraAuthParams    map[string]string `json:"extra_auth_params"`
	ExtraTokenParams   map[string]string `json:"extra_token_params"`
	AuthStyle          string            `json:"auth_style"`
	PKCE               bool              `json:"pkce"`
	StoreMode          string            `json:"store_mode"`
	RefreshWindow      time.Duration     `json:"refresh_window"`
	UseRefreshToken    bool              `json:"use_refresh_token"`
	SuccessRedirect    string            `json:"success_redirect"`
	DisableRefreshSave bool              `json:"disable_refresh_save"`
}

type oauthState struct {
	State           string    `json:"state"`
	Provider        string    `json:"provider"`
	EntityID        string    `json:"entity_id"`
	RedirectURI     string    `json:"redirect_uri"`
	CodeVerifier    string    `json:"code_verifier"`
	SuccessRedirect string    `json:"success_redirect"`
	CreatedAt       time.Time `json:"created_at"`
}

type tokenRecord struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	TokenType    string         `json:"token_type"`
	IDToken      string         `json:"id_token"`
	Expiry       time.Time      `json:"expiry"`
	Scopes       []string       `json:"scopes"`
	ObtainedAt   time.Time      `json:"obtained_at"`
	Raw          map[string]any `json:"raw"`
}

func (p *oauthProvider) client() *oauthclient.Provider {
	return &oauthclient.Provider{
		AuthorizeURL:     p.AuthorizeURL,
		TokenURL:         p.TokenURL,
		ClientID:         p.ClientID,
		ClientSecret:     p.ClientSecret,
		Scopes:           p.Scopes,
		RedirectURL:      p.RedirectURL,
		Audience:         p.Audience,
		ExtraAuthParams:  p.ExtraAuthParams,
		ExtraTokenParams: p.ExtraTokenParams,
		AuthStyle:        p.AuthStyle,
		UsePKCE:          p.PKCE,
	}
}

func (b *Backend) loadProvider(ctx context.Context, s logical.Storage, name string) (*oauthProvider, error) {
	return readJSON[oauthProvider](ctx, s, oauthPrefix+name)
}

func tokenKey(provider *oauthProvider, name, entityID string) string {
	if provider.StoreMode == storeModeShared {
		return oauthTokenPrefix + name + "/shared"
	}
	return oauthTokenPrefix + name + "/entity/" + entityID
}

func loadToken(ctx context.Context, s logical.Storage, provider *oauthProvider, name, entityID string) (*tokenRecord, error) {
	return readJSON[tokenRecord](ctx, s, tokenKey(provider, name, entityID))
}

func saveToken(ctx context.Context, s logical.Storage, provider *oauthProvider, name, entityID string, rec *tokenRecord) error {
	return writeJSON(ctx, s, tokenKey(provider, name, entityID), rec)
}

func tokenFromOAuth(t *oauth2.Token) *tokenRecord {
	rec := &tokenRecord{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Expiry:       t.Expiry,
		ObtainedAt:   time.Now().UTC(),
		Raw:          map[string]any{},
	}
	if v := t.Extra("id_token"); v != nil {
		if s, ok := v.(string); ok {
			rec.IDToken = s
		}
	}
	if raw, ok := t.Extra("raw").(map[string]any); ok {
		for k, v := range raw {
			rec.Raw[k] = v
		}
	}
	if scopes, ok := t.Extra("scope").(string); ok {
		rec.Scopes = strings.Fields(scopes)
	}
	return rec
}

func refreshIfNeeded(ctx context.Context, s logical.Storage, provider *oauthProvider, name, entityID string, rec *tokenRecord, now time.Time) (*tokenRecord, error) {
	if provider.DisableRefreshSave || !provider.UseRefreshToken || rec.RefreshToken == "" {
		return rec, nil
	}
	window := provider.RefreshWindow
	if window <= 0 {
		window = 60 * time.Second
	}
	if !rec.Expiry.IsZero() && now.Add(window).Before(rec.Expiry) {
		return rec, nil
	}
	fresh, err := provider.client().Refresh(ctx, rec.RefreshToken)
	if err != nil {
		if rec.AccessToken != "" && (rec.Expiry.IsZero() || now.Before(rec.Expiry)) {
			return rec, nil
		}
		return nil, fmt.Errorf("refresh %q token for entity %s: %w", name, entityID, err)
	}
	updated := tokenFromOAuth(fresh)
	if updated.RefreshToken == "" {
		updated.RefreshToken = rec.RefreshToken
	}
	if updated.IDToken == "" {
		updated.IDToken = rec.IDToken
	}
	if err := saveToken(ctx, s, provider, name, entityID, updated); err != nil {
		return nil, err
	}
	return updated, nil
}

func (b *Backend) pathsOAuth() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "oauth/?",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathOAuthList},
			},
			HelpSynopsis: "List configured OAuth providers.",
		},
		{
			Pattern: "oauth/callback/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name":              {Type: framework.TypeString, Description: "OAuth provider name."},
				"code":              {Type: framework.TypeString, Description: "Authorization code from the provider."},
				"state":             {Type: framework.TypeString, Description: "State nonce minted by the login path."},
				"error":             {Type: framework.TypeString, Description: "OAuth error code from the provider."},
				"error_description": {Type: framework.TypeString, Description: "OAuth error description from the provider."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathOAuthCallback},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathOAuthCallback},
			},
			HelpSynopsis:    "OAuth redirect target.",
			HelpDescription: "Unauthenticated. Exchanges the authorization code and stores the token on the entity named by state.",
		},
		{
			Pattern: "oauth/" + framework.GenericNameRegex("name") + "/login",
			Fields: map[string]*framework.FieldSchema{
				"name":             {Type: framework.TypeString, Description: "OAuth provider name."},
				"redirect_uri":     {Type: framework.TypeString, Description: "Override the callback URL registered with the provider."},
				"success_redirect": {Type: framework.TypeString, Description: "Browser redirect target after a successful callback."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathOAuthLogin},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathOAuthLogin},
			},
			HelpSynopsis:    "Start an OAuth authorization-code flow.",
			HelpDescription: "Returns an authorization URL bound to the caller's identity entity.",
		},
		{
			Pattern: "oauth/" + framework.GenericNameRegex("name") + "/token",
			Fields: map[string]*framework.FieldSchema{
				"name":   {Type: framework.TypeString, Description: "OAuth provider name."},
				"reveal": {Type: framework.TypeBool, Description: "Include the token material in the response."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathOAuthTokenRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathOAuthTokenDelete},
			},
			HelpSynopsis:    "Inspect or drop the caller entity's stored token.",
			HelpDescription: "Metadata is always returned; set reveal=true to include the token itself.",
		},
		{
			Pattern: "oauth/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name":               {Type: framework.TypeString, Description: "OAuth provider name."},
				"authorize_url":      {Type: framework.TypeString, Description: "Authorization endpoint."},
				"token_url":          {Type: framework.TypeString, Description: "Token endpoint."},
				"client_id":          {Type: framework.TypeString, Description: "OAuth client id."},
				"client_secret":      {Type: framework.TypeString, Description: "OAuth client secret."},
				"scopes":             {Type: framework.TypeCommaStringSlice, Description: "Requested scopes."},
				"redirect_url":       {Type: framework.TypeString, Description: "Default callback URL."},
				"audience":           {Type: framework.TypeString, Description: "Audience parameter for providers that need one."},
				"extra_auth_params":  {Type: framework.TypeMap, Description: "Extra authorization request parameters."},
				"extra_token_params": {Type: framework.TypeMap, Description: "Extra token request parameters."},
				"auth_style": {
					Type:          framework.TypeString,
					Description:   "How client credentials are sent to the token endpoint.",
					AllowedValues: []any{oauthclient.AuthStyleBasic, oauthclient.AuthStyleBody},
				},
				"pkce":                 {Type: framework.TypeBool, Description: "Use PKCE (S256)."},
				"store_mode":           {Type: framework.TypeString, Description: "entity stores a token per identity entity; shared stores one token.", AllowedValues: []any{storeModeEntity, storeModeShared}},
				"refresh_window":       {Type: framework.TypeDurationSecond, Description: "Refresh the token this many seconds before expiry."},
				"use_refresh_token":    {Type: framework.TypeBool, Description: "Refresh expired tokens with the refresh token."},
				"success_redirect":     {Type: framework.TypeString, Description: "Default browser redirect after a successful callback."},
				"disable_refresh_save": {Type: framework.TypeBool, Description: "Do not persist refreshed tokens."},
			},
			ExistenceCheck: b.pathOAuthExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathOAuthWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathOAuthWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathOAuthRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathOAuthDelete},
			},
			HelpSynopsis:    "Manage an OAuth provider.",
			HelpDescription: "Providers run the authorization-code flow and keep tokens per identity entity.",
		},
	}
}

func (b *Backend) pathOAuthExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	p, err := b.loadProvider(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return p != nil, nil
}

func (b *Backend) pathOAuthList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := listNames(ctx, req.Storage, oauthPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *Backend) pathOAuthWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	p, err := b.loadProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		p = &oauthProvider{
			Name:            name,
			AuthStyle:       oauthclient.AuthStyleBasic,
			PKCE:            true,
			StoreMode:       storeModeEntity,
			UseRefreshToken: true,
			RefreshWindow:   60 * time.Second,
		}
	}
	if v, ok := d.GetOk("authorize_url"); ok {
		p.AuthorizeURL = v.(string)
	}
	if v, ok := d.GetOk("token_url"); ok {
		p.TokenURL = v.(string)
	}
	if v, ok := d.GetOk("client_id"); ok {
		p.ClientID = v.(string)
	}
	if v, ok := d.GetOk("client_secret"); ok {
		p.ClientSecret = v.(string)
	}
	if v, ok := d.GetOk("scopes"); ok {
		p.Scopes = toStringSlice(v)
	}
	if v, ok := d.GetOk("redirect_url"); ok {
		p.RedirectURL = v.(string)
	}
	if v, ok := d.GetOk("audience"); ok {
		p.Audience = v.(string)
	}
	if v, ok := d.GetOk("extra_auth_params"); ok {
		p.ExtraAuthParams = toStringMap(v)
	}
	if v, ok := d.GetOk("extra_token_params"); ok {
		p.ExtraTokenParams = toStringMap(v)
	}
	if v, ok := d.GetOk("auth_style"); ok {
		p.AuthStyle = v.(string)
	}
	if v, ok := d.GetOk("pkce"); ok {
		p.PKCE = v.(bool)
	}
	if v, ok := d.GetOk("store_mode"); ok {
		p.StoreMode = v.(string)
	}
	if v, ok := d.GetOk("refresh_window"); ok {
		p.RefreshWindow = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("use_refresh_token"); ok {
		p.UseRefreshToken = v.(bool)
	}
	if v, ok := d.GetOk("success_redirect"); ok {
		p.SuccessRedirect = v.(string)
	}
	if v, ok := d.GetOk("disable_refresh_save"); ok {
		p.DisableRefreshSave = v.(bool)
	}
	if p.AuthorizeURL == "" || p.TokenURL == "" || p.ClientID == "" {
		return logical.ErrorResponse("authorize_url, token_url and client_id are required"), nil
	}
	if p.StoreMode == "" {
		p.StoreMode = storeModeEntity
	}
	if err := writeJSON(ctx, req.Storage, oauthPrefix+name, p); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *Backend) pathOAuthRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	p, err := b.loadProvider(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	return &logical.Response{Data: map[string]any{
		"name":               p.Name,
		"authorize_url":      p.AuthorizeURL,
		"token_url":          p.TokenURL,
		"client_id":          p.ClientID,
		"has_client_secret":  p.ClientSecret != "",
		"scopes":             p.Scopes,
		"redirect_url":       p.RedirectURL,
		"audience":           p.Audience,
		"extra_auth_params":  p.ExtraAuthParams,
		"extra_token_params": p.ExtraTokenParams,
		"auth_style":         p.AuthStyle,
		"pkce":               p.PKCE,
		"store_mode":         p.StoreMode,
		"refresh_window":     int(p.RefreshWindow.Seconds()),
		"use_refresh_token":  p.UseRefreshToken,
		"success_redirect":   p.SuccessRedirect,
	}}, nil
}

func (b *Backend) pathOAuthDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, oauthPrefix+d.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *Backend) pathOAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	provider, err := b.loadProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return logical.ErrorResponse(fmt.Sprintf("oauth provider %q not found", name)), nil
	}
	if provider.StoreMode != storeModeShared && req.EntityID == "" {
		return logical.ErrorResponse("this token has no identity entity; use an auth method that creates entities, or set store_mode=shared"), nil
	}

	cfg, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	redirectURI := d.Get("redirect_uri").(string)
	if redirectURI == "" {
		redirectURI = provider.RedirectURL
	}
	if redirectURI == "" {
		redirectURI = defaultCallbackURL(cfg, req, name)
	}
	if redirectURI == "" {
		return logical.ErrorResponse("cannot determine redirect_uri; set the engine public_url or the provider redirect_url"), nil
	}

	verifier := ""
	if provider.PKCE {
		verifier, err = oauthclient.NewVerifier()
		if err != nil {
			return nil, err
		}
	}

	state, err := oauthclient.NewState()
	if err != nil {
		return nil, err
	}

	client := provider.client()
	client.RedirectURL = redirectURI
	authURL, err := client.AuthCodeURL(state, verifier)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	purgeExpiredStates(ctx, req.Storage, cfg.OAuthStateTTL)

	record := &oauthState{
		State:           state,
		Provider:        name,
		EntityID:        req.EntityID,
		RedirectURI:     redirectURI,
		CodeVerifier:    verifier,
		SuccessRedirect: d.Get("success_redirect").(string),
		CreatedAt:       time.Now().UTC(),
	}
	if record.SuccessRedirect == "" {
		record.SuccessRedirect = provider.SuccessRedirect
	}
	if err := writeJSON(ctx, req.Storage, oauthStatePrefix+state, record); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{
		"auth_url":     authURL,
		"state":        state,
		"redirect_uri": redirectURI,
		"provider":     name,
		"entity_id":    req.EntityID,
	}}, nil
}

func (b *Backend) pathOAuthCallback(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	provider, err := b.loadProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return logical.ErrorResponse(fmt.Sprintf("oauth provider %q not found", name)), nil
	}

	stateParam := d.Get("state").(string)
	if stateParam == "" {
		return logical.ErrorResponse("missing state"), nil
	}
	record, err := readJSON[oauthState](ctx, req.Storage, oauthStatePrefix+stateParam)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return logical.ErrorResponse("unknown or already used state"), nil
	}
	if subtle.ConstantTimeCompare([]byte(record.State), []byte(stateParam)) != 1 {
		return logical.ErrorResponse("state mismatch"), nil
	}

	cfg, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if time.Since(record.CreatedAt) > cfg.OAuthStateTTL {
		_ = req.Storage.Delete(ctx, oauthStatePrefix+stateParam)
		return logical.ErrorResponse("state expired"), nil
	}
	if record.Provider != name {
		return logical.ErrorResponse("state was issued for a different provider"), nil
	}
	if err := req.Storage.Delete(ctx, oauthStatePrefix+stateParam); err != nil {
		return nil, err
	}

	if providerErr := d.Get("error").(string); providerErr != "" {
		msg := fmt.Sprintf("provider returned %s: %s", providerErr, d.Get("error_description").(string))
		if record.SuccessRedirect != "" {
			return &logical.Response{Redirect: appendQuery(record.SuccessRedirect, map[string]string{"status": "error", "error": providerErr})}, nil
		}
		return logical.ErrorResponse(msg), nil
	}

	code := d.Get("code").(string)
	if code == "" {
		return logical.ErrorResponse("missing code"), nil
	}

	client := provider.client()
	client.RedirectURL = record.RedirectURI
	token, err := client.Exchange(ctx, code, record.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	stored := tokenFromOAuth(token)
	entityID := record.EntityID
	if provider.StoreMode == storeModeShared {
		entityID = ""
	}
	if entityID == "" && provider.StoreMode != storeModeShared {
		return logical.ErrorResponse("state carried no entity id"), nil
	}
	if err := saveToken(ctx, req.Storage, provider, name, entityID, stored); err != nil {
		return nil, err
	}

	if record.SuccessRedirect != "" {
		return &logical.Response{Redirect: appendQuery(record.SuccessRedirect, map[string]string{"status": "ok", "provider": name})}, nil
	}
	return &logical.Response{Data: map[string]any{
		"status":     "ok",
		"provider":   name,
		"entity_id":  entityID,
		"scopes":     stored.Scopes,
		"expires_at": formatTime(stored.Expiry),
	}}, nil
}

func (b *Backend) pathOAuthTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	provider, err := b.loadProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return logical.ErrorResponse(fmt.Sprintf("oauth provider %q not found", name)), nil
	}
	entityID := req.EntityID
	if provider.StoreMode == storeModeShared {
		entityID = ""
	} else if entityID == "" {
		return logical.ErrorResponse("this token has no identity entity"), nil
	}
	rec, err := loadToken(ctx, req.Storage, provider, name, entityID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	data := map[string]any{
		"provider":          name,
		"entity_id":         entityID,
		"token_type":        rec.TokenType,
		"scopes":            rec.Scopes,
		"expires_at":        formatTime(rec.Expiry),
		"obtained_at":       formatTime(rec.ObtainedAt),
		"has_refresh_token": rec.RefreshToken != "",
	}
	if d.Get("reveal").(bool) {
		data["access_token"] = rec.AccessToken
		data["refresh_token"] = rec.RefreshToken
		data["id_token"] = rec.IDToken
	}
	return &logical.Response{Data: data}, nil
}

func (b *Backend) pathOAuthTokenDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	provider, err := b.loadProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return logical.ErrorResponse(fmt.Sprintf("oauth provider %q not found", name)), nil
	}
	entityID := req.EntityID
	if provider.StoreMode == storeModeShared {
		entityID = ""
	}
	if err := req.Storage.Delete(ctx, tokenKey(provider, name, entityID)); err != nil {
		return nil, err
	}
	return nil, nil
}

// Abandoned OAuth states (the browser never came back) would otherwise live
// forever, because storage has no TTL. Sweep them opportunistically when a new
// login arrives, with bounded work per call.
const (
	stateSweepThreshold = 16
	stateSweepLimit     = 64
)

func purgeExpiredStates(ctx context.Context, s logical.Storage, ttl time.Duration) {
	keys, err := s.List(ctx, oauthStatePrefix)
	if err != nil || len(keys) <= stateSweepThreshold {
		return
	}
	cutoff := time.Now().Add(-ttl)
	for i, key := range keys {
		if i >= stateSweepLimit {
			return
		}
		record, err := readJSON[oauthState](ctx, s, oauthStatePrefix+key)
		if err != nil || record == nil {
			continue
		}
		if record.CreatedAt.Before(cutoff) {
			_ = s.Delete(ctx, oauthStatePrefix+key)
		}
	}
}

func defaultCallbackURL(cfg *backendConfig, req *logical.Request, name string) string {
	mount := strings.Trim(req.MountPoint, "/")
	suffix := "v1/" + mount + "/oauth/callback/" + name
	if cfg.PublicURL != "" {
		return strings.TrimSuffix(cfg.PublicURL, "/") + "/" + suffix
	}
	host := ""
	if req.Headers != nil {
		if v := req.Headers["Host"]; len(v) > 0 {
			host = v[0]
		}
	}
	if host == "" {
		return ""
	}
	scheme := "http"
	if v := req.Headers["X-Forwarded-Proto"]; len(v) > 0 && v[0] != "" {
		scheme = v[0]
	}
	return scheme + "://" + host + "/" + suffix
}

func appendQuery(raw string, values map[string]string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, v := range values {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		return strings.Fields(s)
	}
	return nil
}
