package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
}

var _ logical.Factory = Factory

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	backend := &backend{}
	backend.Backend = &framework.Backend{
		Help:        strings.TrimSpace(pluginHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			backend.configPaths(),
			backend.jwtPaths(),
			backend.signPaths(),
		),
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := backend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return backend, nil
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// mapToStruct maps a JSON input that is a plain interface{} into a struct and uses the JSON
// mappings defined in that struct to correctly populate the fields.
func (b *backend) mapToStruct(data interface{}, mappedStruct any) error {
	jsonStr, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to serialize data to json: %w", err)
	}

	if err := json.Unmarshal(jsonStr, mappedStruct); err != nil {
		return fmt.Errorf("failed to deserialize user config json: %w", err)
	}

	return nil
}
