package secretsproxy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	refCredential = "cred"
	refOAuth      = "oauth"
	refEntity     = "entity"
)

func isIdentChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '_', '-', '.', '@', '/':
		return true
	}
	return false
}

// refLen reports the length of the reference beginning at s[start], which must
// be '$'. References are kind, then ':', then name, then an optional ':' and
// field. ':' separates parts, so it never appears inside one.
func refLen(s string, start int) (int, bool) {
	i := start + 1
	j := i
	for j < len(s) && isIdentChar(s[j]) {
		j++
	}
	if j == i || j >= len(s) || s[j] != ':' {
		return 0, false
	}
	j++
	k := j
	for k < len(s) && isIdentChar(s[k]) {
		k++
	}
	if k == j {
		return 0, false
	}
	if k < len(s) && s[k] == ':' {
		m := k + 1
		for m < len(s) && isIdentChar(s[m]) {
			m++
		}
		if m > k+1 {
			k = m
		}
	}
	return k - start, true
}

// render expands $cred:, $oauth: and $entity: references in tpl. Unknown
// references are emitted verbatim so literals containing '$' survive.
func render(tpl string, r *resolver) (string, error) {
	var sb strings.Builder
	i := 0
	for i < len(tpl) {
		if tpl[i] != '$' {
			sb.WriteByte(tpl[i])
			i++
			continue
		}
		if i+1 < len(tpl) && tpl[i+1] == '$' {
			sb.WriteByte('$')
			i += 2
			continue
		}
		n, ok := refLen(tpl, i)
		if !ok {
			sb.WriteByte('$')
			i++
			continue
		}
		token := tpl[i+1 : i+n]
		value, handled, err := r.resolve(token)
		if err != nil {
			return "", err
		}
		if !handled {
			sb.WriteByte('$')
			sb.WriteString(token)
		} else {
			sb.WriteString(value)
		}
		i += n
	}
	return sb.String(), nil
}

type resolver struct {
	ctx      context.Context
	storage  logical.Storage
	entityID string
	entity   *logical.Entity
	provider func(name string) (*oauthProvider, error)
	now      func() time.Time
}

func (r *resolver) timestamp() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *resolver) resolve(token string) (string, bool, error) {
	kind, rest, _ := strings.Cut(token, ":")
	switch kind {
	case refCredential:
		name, field, _ := strings.Cut(rest, ":")
		if name == "" {
			return "", false, nil
		}
		c, err := readJSON[credential](r.ctx, r.storage, credentialPrefix+name)
		if err != nil {
			return "", false, err
		}
		if c == nil {
			return "", false, fmt.Errorf("credential %q not found", name)
		}
		out, err := c.field(field)
		return out, true, err

	case refOAuth:
		name, field, _ := strings.Cut(rest, ":")
		if name == "" {
			return "", false, nil
		}
		out, err := r.oauthField(name, field)
		return out, true, err

	case refEntity:
		return r.entityField(rest)
	}
	return "", false, nil
}

func (r *resolver) entityField(field string) (string, bool, error) {
	switch field {
	case "id":
		return r.entityID, true, nil
	case "name":
		if r.entity == nil {
			return "", true, nil
		}
		return r.entity.Name, true, nil
	case "alias":
		if r.entity == nil || len(r.entity.Aliases) == 0 {
			return "", true, nil
		}
		return r.entity.Aliases[0].Name, true, nil
	}
	return "", false, nil
}

func (r *resolver) oauthField(name, field string) (string, error) {
	if r.provider == nil {
		return "", fmt.Errorf("oauth provider %q is unavailable in this context", name)
	}
	provider, err := r.provider(name)
	if err != nil {
		return "", err
	}
	if provider == nil {
		return "", fmt.Errorf("oauth provider %q not found", name)
	}
	if provider.StoreMode != storeModeShared && r.entityID == "" {
		return "", fmt.Errorf("oauth provider %q needs an identity entity; this token has none", name)
	}
	record, err := loadToken(r.ctx, r.storage, provider, name, r.entityID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("no %q token for entity %s; run secrets-proxy/oauth/%s/login first", name, r.entityID, name)
	}
	latest, err := refreshIfNeeded(r.ctx, r.storage, provider, name, r.entityID, record, r.timestamp())
	if err != nil {
		return "", err
	}
	switch field {
	case "", "access_token":
		return latest.AccessToken, nil
	case "refresh_token":
		return latest.RefreshToken, nil
	case "token_type":
		return latest.TokenType, nil
	case "id_token":
		return latest.IDToken, nil
	}
	return "", fmt.Errorf("unknown oauth token field %q", field)
}
