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
			Pattern:      jwtPathPrefix + framework.GenericNameRegex(nameKey),
			HelpSynopsis: "Generates a JWT for an identity.",
			Fields: map[string]*framework.FieldSchema{
				nameKey: {Type: framework.TypeString},
				typeKey: {
					Type:          framework.TypeString,
					Description:   "Type of JWT to generate.",
					Default:       "user",
					AllowedValues: accountTypes,
					Required:      true,
				},
				accountKey: {
					Type:        framework.TypeString,
					Description: "Name of a previously generated Account that should be used to sign the User JWT. (required if type=user)",
				},
				configKey: {
					Type:        framework.TypeMap,
					Description: "Configuration for either Account or User JWT. (required)",
					Required:    true,
				},
			},
			ExistenceCheck: b.handleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.createIdentityJWT,
			},
		},
	}
}

func (b *backend) createIdentityJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	name := data.Get(nameKey).(string)
	identityType := PrefixByteFromString(data.Get(typeKey).(string))

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
	switch identityType {
	case nkeys.PrefixByteAccount:
		if token, err = b.createAccountToken(ctx, req, data, identity); err != nil {
			return nil, err
		}
	case nkeys.PrefixByteUser:
		if token, err = b.createUserToken(ctx, req, data, identity); err != nil {
			return nil, err
		}
	}

	returnData := map[string]interface{}{
		identity.Name: NKeyWithToken{
			PublicKey: identity.PublicKey,
			JWT:       token,
		},
	}

	return &logical.Response{
		Data: returnData,
	}, nil
}

func (b *backend) createAccountToken(ctx context.Context, req *logical.Request, data *framework.FieldData, account *Identity) (string, error) {
	accountConfig := &jwt.Account{}
	b.mapToStruct(data.Get(configKey), accountConfig)

	operator, err := b.readIdentity(ctx, req, operatorName)
	if err != nil {
		return "", fmt.Errorf("error reading operator identity: %w", err)
	}
	if operator == nil {
		return "", fmt.Errorf("operator identity not found")
	}

	keyPair, err := nkeys.FromSeed([]byte(operator.Seed))
	if err != nil {
		return "", fmt.Errorf("error creating key pair from seed: %w", err)
	}

	claims := jwt.NewAccountClaims(string(account.PublicKey))
	claims.Name = account.Name
	claims.Account = *accountConfig

	token, err := claims.Encode(keyPair)
	if err != nil {
		return "", fmt.Errorf("error encoding account claims: %w", err)
	}

	return token, nil
}

func (b *backend) createUserToken(ctx context.Context, req *logical.Request, data *framework.FieldData, user *Identity) (string, error) {
	accountName := data.Get(accountKey).(string)
	if accountName == "" {
		return "", fmt.Errorf("account must be provided to create user token")
	}

	userConfig := &jwt.User{}
	b.mapToStruct(data.Get(configKey), userConfig)

	account, err := b.readIdentity(ctx, req, accountName)
	if err != nil {
		return "", fmt.Errorf("error reading account identity: %w", err)
	}
	if account == nil {
		return "", fmt.Errorf("account identity not found")
	}

	keyPair, err := nkeys.FromSeed([]byte(account.Seed))
	if err != nil {
		return "", err
	}

	claims := jwt.NewUserClaims(string(user.PublicKey))
	claims.Name = user.Name
	claims.User = *userConfig

	token, err := claims.Encode(keyPair)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (b *backend) readJWT(ctx context.Context, req *logical.Request, name string) (string, error) {
	path := fmt.Sprintf("%s%s", jwtPathPrefix, name)

	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("error reading JWT: %w", err)
	}
	if entry == nil {
		return "", nil
	}

	return string(entry.Value), nil
}

func (b *backend) storeJWT(ctx context.Context, req *logical.Request, name string, token string) error {
	path := fmt.Sprintf("%s%s", jwtPathPrefix, name)

	err := req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   path,
		Value: []byte(token),
	})

	if err != nil {
		return fmt.Errorf("error storing JWT: %w", err)
	}

	return nil
}
