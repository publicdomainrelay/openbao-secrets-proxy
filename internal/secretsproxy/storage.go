package secretsproxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	configStorageKey = "config"

	routePrefix      = "routes/"
	credentialPrefix = "credentials/"
	oauthPrefix      = "oauth/providers/"
	oauthStatePrefix = "oauth/state/"
	oauthTokenPrefix = "oauth/tokens/"
)

func readJSON[T any](ctx context.Context, s logical.Storage, key string) (*T, error) {
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var out T
	if err := json.Unmarshal(entry.Value, &out); err != nil {
		return nil, fmt.Errorf("decode %q: %w", key, err)
	}
	return &out, nil
}

func writeJSON(ctx context.Context, s logical.Storage, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{Key: key, Value: raw})
}

func listNames(ctx context.Context, s logical.Storage, prefix string) ([]string, error) {
	names, err := s.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}
