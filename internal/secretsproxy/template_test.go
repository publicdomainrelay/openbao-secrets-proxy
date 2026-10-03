package secretsproxy

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func testResolver(t *testing.T, entity *logical.Entity, entityID string) (*resolver, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	if err := writeJSON(ctx, storage, credentialPrefix+"api", &credential{Name: "api", Value: "sk-live-123"}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(ctx, storage, credentialPrefix+"pair", &credential{
		Name:   "pair",
		Values: map[string]string{"username": "alice", "password": "hunter2"},
	}); err != nil {
		t.Fatal(err)
	}

	return &resolver{
		ctx:      ctx,
		storage:  storage,
		entityID: entityID,
		entity:   entity,
	}, storage
}

func TestRenderLiteralAndEscape(t *testing.T) {
	r, _ := testResolver(t, nil, "")
	for input, want := range map[string]string{
		"plain text":     "plain text",
		"price $$5":      "price $5",
		"no refs at all": "no refs at all",
		"$unknown:thing": "$unknown:thing",
		"$cred":          "$cred",
		"Bearer tok":     "Bearer tok",
	} {
		got, err := render(input, r)
		if err != nil {
			t.Fatalf("render(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("render(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRenderCredentialReferences(t *testing.T) {
	r, _ := testResolver(t, nil, "")
	got, err := render("Bearer $cred:api", r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Bearer sk-live-123" {
		t.Fatalf("got %q", got)
	}

	got, err = render("$cred:pair:username:$cred:pair:password", r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice:hunter2" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderCredentialErrors(t *testing.T) {
	r, _ := testResolver(t, nil, "")
	if _, err := render("$cred:missing", r); err == nil {
		t.Fatal("expected error for missing credential")
	}
	if _, err := render("$cred:pair:nope", r); err == nil {
		t.Fatal("expected error for missing credential field")
	}
}

func TestRenderEntityReferences(t *testing.T) {
	entity := &logical.Entity{
		ID:      "entity-123",
		Name:    "alice",
		Aliases: []*logical.Alias{{Name: "alice-alias"}},
	}
	r, _ := testResolver(t, entity, "entity-123")

	for input, want := range map[string]string{
		"$entity:id":    "entity-123",
		"$entity:name":  "alice",
		"$entity:alias": "alice-alias",
	} {
		got, err := render(input, r)
		if err != nil {
			t.Fatalf("render(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("render(%q) = %q, want %q", input, got, want)
		}
	}

	bare, _ := testResolver(t, nil, "")
	got, err := render("[$entity:id]", bare)
	if err != nil {
		t.Fatal(err)
	}
	if got != "[]" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderOAuthWithoutProvider(t *testing.T) {
	r, _ := testResolver(t, nil, "entity-123")
	_, err := render("$oauth:github", r)
	if err == nil {
		t.Fatal("expected error when no provider lookup is configured")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderOAuthSharedModeNeedsNoEntity(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := context.Background()
	if err := writeJSON(ctx, storage, tokenKey(&oauthProvider{StoreMode: storeModeShared}, "shared", ""), &tokenRecord{
		AccessToken: "shared-token",
		TokenType:   "Bearer",
	}); err != nil {
		t.Fatal(err)
	}

	r := &resolver{
		ctx:     ctx,
		storage: storage,
		provider: func(string) (*oauthProvider, error) {
			return &oauthProvider{Name: "shared", StoreMode: storeModeShared}, nil
		},
	}
	got, err := render("Bearer $oauth:shared", r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Bearer shared-token" {
		t.Fatalf("got %q", got)
	}
}
