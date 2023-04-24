package nats

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func (b *backend) jwtPaths() []*framework.Path {

	var accountTypes []interface{}
	accountTypes = append(accountTypes, "account")
	accountTypes = append(accountTypes, "user")

	return []*framework.Path{
		{
			Pattern:      "jwts/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Generates a JWT for an identity.",
			Fields: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString},
				"type": {
					Type:          framework.TypeString,
					Default:       "user",
					AllowedValues: accountTypes,
					Required:      true,
				},
				"account": {
					Type: framework.TypeString,
					Description: `Name of a previously generated Account that should be used to sign 
					the User JWT (required if type=user)`,
				},
				"config": {
					Type:        framework.TypeMap,
					Description: `Configuration for either Account or User JWT (required)`,
					Required:    true,
				},
				"nonce": {
					Type:        framework.TypeString,
					Description: `The nonce issued by Nats, which must be signed in order to use the JWT`,
					Required:    true,
				},
			},
			ExistenceCheck: b.handleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.createIdentityJwt,
			},
		},
	}
}

func (b *backend) createIdentityJwt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	name := data.Get("name").(string)
	identityType := PrefixByteFromString(data.Get("type").(string))

	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading identity: %w", err)
	}
	if identity == nil {
		identity, err = b.createIdentity(ctx, req, identityType, name)
		if err != nil {
			return nil, err
		}
	}

	var token string
	var signedNonce []byte
	switch identityType {
	case nkeys.PrefixByteAccount:
		if token, err = b.createAccountToken(ctx, req, data, identity); err != nil {
			return nil, err
		}
	case nkeys.PrefixByteUser:
		if token, signedNonce, err = b.createUserToken(ctx, req, data, identity); err != nil {
			return nil, err
		}
	}

	returnData := map[string]interface{}{
		identity.Name: NKeyWithToken{
			PublicKey: identity.PublicKey,
			Jwt:       token,
		},
	}

	if signedNonce != nil {
		returnData["signed_nonce"] = signedNonce
	}

	return &logical.Response{
		Data: returnData,
	}, nil
}

func (b *backend) createAccountToken(ctx context.Context, req *logical.Request, data *framework.FieldData,
	identity *Identity) (string, error) {

	accountConfig := &jwt.Account{}
	b.mapToStruct(data.Get("config"), accountConfig)

	issuer, err := b.readIdentity(ctx, req, "operator")
	if err != nil {
		return "", fmt.Errorf("error reading operator identity. error=%w", err)
	}
	if issuer == nil {
		return "", fmt.Errorf("operator identity not found")
	}

	keyPair, err := nkeys.FromSeed([]byte(issuer.Seed))
	if err != nil {
		return "", fmt.Errorf("failed to create key pair from seed: %w", err)
	}

	claims := jwt.NewAccountClaims(string(identity.PublicKey))
	claims.Name = identity.Name
	claims.Account = *accountConfig

	token, err := claims.Encode(keyPair)
	if err != nil {
		return "", fmt.Errorf("failed to encode account claims: %w", err)
	}

	return token, nil
}

func (b *backend) createUserToken(ctx context.Context, req *logical.Request, data *framework.FieldData,
	identity *Identity) (string, []byte, error) {

	issuerName := data.Get("account").(string)
	if issuerName == "" {
		return "", nil, fmt.Errorf("must pass an account to sign the user token")
	}

	userConfig := &jwt.User{}
	b.mapToStruct(data.Get("config"), userConfig)

	issuer, err := b.readIdentity(ctx, req, issuerName)
	if err != nil {
		return "", nil, fmt.Errorf("error reading '%s' identity: %w", issuerName, err)
	}
	if issuer == nil {
		return "", nil, fmt.Errorf("'%s' identity not found", issuerName)
	}

	keyPair, err := nkeys.FromSeed([]byte(issuer.Seed))
	if err != nil {
		return "", nil, err
	}

	claims := jwt.NewUserClaims(string(identity.PublicKey))
	claims.Name = identity.Name
	claims.User = *userConfig

	token, err := claims.Encode(keyPair)
	if err != nil {
		return "", nil, err
	}

	nonce := data.Get("nonce")

	if nonce != nil {
		signedNonce, err := b.signNonce(issuer, nonce.(string))
		if err != nil {
			return "", nil, err
		}
		return token, signedNonce, nil
	}

	return token, nil, nil
}

func (b *backend) readJwt(ctx context.Context, req *logical.Request, name string) (string, error) {
	path := fmt.Sprintf("jwts/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", nil
	}

	return string(entry.Value), nil
}

func (b *backend) storeJwt(ctx context.Context, req *logical.Request, name string, token string) error {

	path := fmt.Sprintf("jwts/%s", name)

	err := req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   path,
		Value: []byte(token),
	})

	if err != nil {
		return fmt.Errorf("failed to store JWT for %s: %w", name, err)
	}
	return nil
}
