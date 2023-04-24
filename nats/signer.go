package nats

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
)

func (b *backend) signaturePaths() []*framework.Path {

	return []*framework.Path{
		{
			Pattern:      "sign",
			HelpSynopsis: "Signs the Nats challenge (nonce) with the account passed in.",
			Fields: map[string]*framework.FieldSchema{
				"signing_account": {
					Type:     framework.TypeString,
					Required: true,
				},
				"nonce": {
					Type:        framework.TypeString,
					Description: `The nonce issued by Nats, which must be signed in order to use the user JWT`,
					Required:    true,
				},
			},
			ExistenceCheck: b.handleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.signNoncePath,
			},
		},
	}
}

func (b *backend) signNoncePath(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	issuerName := data.Get("signing_account").(string)
	nonce := data.Get("nonce").(string)

	issuerIdentity, err := b.readIdentity(ctx, req, issuerName)
	if err != nil {
		return nil, fmt.Errorf("error reading identity: %w", err)
	}

	if issuerIdentity == nil {
		return nil, fmt.Errorf("'%s' identity not found", issuerName)
	}

	signedNonce, err := b.signNonce(issuerIdentity, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to sign nonce: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signed_nonce": signedNonce,
		},
	}, nil
}

func (b *backend) signNonce(signingIdentity *Identity, nonce string) ([]byte, error) {
	keyPair, err := nkeys.FromSeed([]byte(signingIdentity.Seed))
	if err != nil {
		return nil, err
	}

	signedNonce, err := keyPair.Sign([]byte(nonce))
	if err != nil {
		return nil, fmt.Errorf("failed to sign nonce: %w", err)
	}

	return signedNonce, nil
}
