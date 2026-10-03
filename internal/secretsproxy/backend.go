package secretsproxy

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const backendHelp = `
The secrets-proxy secrets engine is a reverse proxy. It forwards requests to
arbitrary upstream APIs and injects secrets into arbitrary headers and query
parameters.

Routes describe an upstream URL plus injection templates. Credentials are
static secret values. OAuth providers run an authorization-code flow and store
the resulting token against the calling OpenBao identity entity, so requests
proxied by that entity carry that entity's token.

Configure with:

  bao write secrets-proxy/routes/github upstream=https://api.github.com \
    'inject=Authorization="Bearer $oauth:github"'
  bao write secrets-proxy/credentials/openai value=sk-...
  bao write secrets-proxy/oauth/github authorize_url=... token_url=... client_id=... scopes=repo

Then proxy:

  bao read secrets-proxy/proxy/github/user
`

// Factory is the logical.Factory used by plugin.Serve.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := New()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// New builds the secrets-proxy secrets engine.
func New() *Backend {
	var b Backend
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"oauth/callback/*",
			},
		},
		Paths: framework.PathAppend(
			b.pathsConfig(),
			b.pathsRoutes(),
			b.pathsCredentials(),
			b.pathsOAuth(),
			b.pathsProxy(),
		),
		Secrets: []*framework.Secret{},
	}
	return &b
}

// Backend wraps framework.Backend with the secrets-proxy handlers.
type Backend struct {
	*framework.Backend

	system logical.SystemView
}

// Setup keeps the system view so proxy requests can resolve the caller entity.
func (b *Backend) Setup(ctx context.Context, config *logical.BackendConfig) error {
	b.system = config.System
	return b.Backend.Setup(ctx, config)
}
