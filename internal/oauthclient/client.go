// Package oauthclient is a small OAuth 2.0 authorization-code + PKCE client
// used by the secrets-proxy engine. It has no OpenBao dependencies.
package oauthclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

const (
	AuthStyleBasic = "basic"
	AuthStyleBody  = "body"
)

// Provider holds everything needed to talk to one OAuth 2.0 authorization
// server.
type Provider struct {
	AuthorizeURL     string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	Scopes           []string
	RedirectURL      string
	Audience         string
	ExtraAuthParams  map[string]string
	ExtraTokenParams map[string]string
	AuthStyle        string
	UsePKCE          bool
}

func (p *Provider) config() *oauth2.Config {
	style := oauth2.AuthStyleAutoDetect
	switch p.AuthStyle {
	case AuthStyleBasic:
		style = oauth2.AuthStyleInHeader
	case AuthStyleBody:
		style = oauth2.AuthStyleInParams
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       p.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.AuthorizeURL,
			TokenURL:  p.TokenURL,
			AuthStyle: style,
		},
	}
}

func (p *Provider) authOptions(verifier string) []oauth2.AuthCodeOption {
	var opts []oauth2.AuthCodeOption
	if p.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", p.Audience))
	}
	for k, v := range p.ExtraAuthParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	if p.UsePKCE && verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}
	return opts
}

func (p *Provider) tokenOptions(verifier string) []oauth2.AuthCodeOption {
	var opts []oauth2.AuthCodeOption
	for k, v := range p.ExtraTokenParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	if p.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", p.Audience))
	}
	if p.UsePKCE && verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	return opts
}

// AuthCodeURL builds the authorization request URL for the given state.
func (p *Provider) AuthCodeURL(state, verifier string) (string, error) {
	if p.AuthorizeURL == "" {
		return "", fmt.Errorf("authorize_url is required")
	}
	if p.ClientID == "" {
		return "", fmt.Errorf("client_id is required")
	}
	return p.config().AuthCodeURL(state, p.authOptions(verifier)...), nil
}

// Exchange trades an authorization code for a token.
func (p *Provider) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	if p.TokenURL == "" {
		return nil, fmt.Errorf("token_url is required")
	}
	return p.config().Exchange(ctx, code, p.tokenOptions(verifier)...)
}

// Refresh gets a new access token from a refresh token.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if p.TokenURL == "" {
		return nil, fmt.Errorf("token_url is required")
	}
	src := p.config().TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	return src.Token()
}

// NewVerifier builds an RFC 7636 PKCE code verifier.
func NewVerifier() (string, error) {
	buf := make([]byte, 48)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	var sb strings.Builder
	for _, b := range buf {
		sb.WriteByte(alphabet[int(b)%len(alphabet)])
	}
	return sb.String(), nil
}

// NewState returns a random OAuth state nonce.
func NewState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

var (
	_ = http.DefaultClient
	_ = rand.Reader
)
