package nats

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
)

func (b *backend) signPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:      jwtPathPrefix + framework.GenericNameRegex(nameKey) + "/sign",
			HelpSynopsis: "Signs the nonce (challenge string) returned by NATS during authentication.",
			Fields: map[string]*framework.FieldSchema{
				nameKey: {Type: framework.TypeString},
				nonceKey: {
					Type:        framework.TypeString,
					Description: "The nonce (challenge string) returned by NATS during authentication.",
					Required:    true,
				},
			},
			ExistenceCheck: b.handleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.signNonce,
			},
		},
	}
}

func (b *backend) signNonce(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	issuerName := data.Get(nameKey).(string)
	nonce := data.Get(nonceKey).(string)

	identity, err := b.readIdentity(ctx, req, issuerName)
	if err != nil {
		return nil, fmt.Errorf("error reading identity: %w", err)
	}
	if identity == nil {
		return nil, fmt.Errorf("'%s' identity not found", issuerName)
	}

	keyPair, err := nkeys.FromSeed([]byte(identity.Seed))
	if err != nil {
		return nil, err
	}

	signedNonce, err := keyPair.Sign([]byte(nonce))
	if err != nil {
		return nil, fmt.Errorf("failed to sign nonce: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signed_nonce": signedNonce,
		},
	}, nil
}
