package secretsproxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type credential struct {
	Name   string            `json:"name"`
	Value  string            `json:"value"`
	Values map[string]string `json:"values"`
}

func (c *credential) field(name string) (string, error) {
	if name == "" {
		if c.Value != "" {
			return c.Value, nil
		}
		raw, err := json.Marshal(c.Values)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	if c.Values == nil {
		return "", fmt.Errorf("credential %q has no field %q", c.Name, name)
	}
	v, ok := c.Values[name]
	if !ok {
		return "", fmt.Errorf("credential %q has no field %q", c.Name, name)
	}
	return v, nil
}

func (b *Backend) loadCredential(ctx context.Context, s logical.Storage, name string) (*credential, error) {
	return readJSON[credential](ctx, s, credentialPrefix+name)
}

func (b *Backend) pathsCredentials() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "credentials/?",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathCredentialList},
			},
			HelpSynopsis:    "List stored credentials.",
			HelpDescription: "Returns the names of every static credential.",
		},
		{
			Pattern: "credentials/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Credential name.",
				},
				"value": {
					Type:        framework.TypeString,
					Description: "A single secret value.",
				},
				"values": {
					Type:        framework.TypeMap,
					Description: "A structured secret, addressable as $cred:<name>:<field>.",
				},
				"reveal": {
					Type:        framework.TypeBool,
					Description: "On read, include the secret material in the response.",
				},
			},
			ExistenceCheck: b.pathCredentialExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathCredentialWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathCredentialDelete},
			},
			HelpSynopsis:    "Manage a static credential.",
			HelpDescription: "Credentials are values injected into upstream requests by templates such as $cred:name.",
		},
	}
}

func (b *Backend) pathCredentialExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	c, err := b.loadCredential(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return c != nil, nil
}

func (b *Backend) pathCredentialList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := listNames(ctx, req.Storage, credentialPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *Backend) pathCredentialWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	c, err := b.loadCredential(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if c == nil {
		c = &credential{Name: name}
	}
	if v, ok := d.GetOk("value"); ok {
		c.Value = v.(string)
	}
	if v, ok := d.GetOk("values"); ok {
		c.Values = toStringMap(v)
	}
	if c.Value == "" && len(c.Values) == 0 {
		return logical.ErrorResponse("one of value or values is required"), nil
	}
	if err := writeJSON(ctx, req.Storage, credentialPrefix+name, c); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *Backend) pathCredentialRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.loadCredential(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}
	data := map[string]any{"name": c.Name}
	if d.Get("reveal").(bool) {
		data["value"] = c.Value
		data["values"] = c.Values
	}
	return &logical.Response{Data: data}, nil
}

func (b *Backend) pathCredentialDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, credentialPrefix+d.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}
