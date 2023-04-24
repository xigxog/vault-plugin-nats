package nats

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const operatorName string = "operator"
const systemAccountName string = "system_account"
const sysAccountUserName string = "system_account_user"

type NKeyWithToken struct {
	PublicKey string `json:"public_key"`
	Jwt       string `json:"jwt"`
}

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:      "config",
			HelpSynopsis: "Configures the plugin with various NATS server configuration.",
			Fields: map[string]*framework.FieldSchema{
				"account-jwt-server-url": {
					Type:    framework.TypeString,
					Default: "nats://127.0.0.1:4222",
				},
				"service-url": {
					Type:    framework.TypeString,
					Default: "nats://127.0.0.1:4222",
				},
				"tag": {
					Type:        framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of tags`,
				},
			},
			ExistenceCheck: b.handleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.readConfiguration,
				logical.CreateOperation: b.saveConfiguration,
				logical.UpdateOperation: b.saveConfiguration,
			},
		},
	}
}

func (b *backend) readConfiguration(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	operatorIdentity, err := b.readIdentity(ctx, req, operatorName)
	if err != nil {
		return nil, err
	}
	operatorJwt, err := b.readJwt(ctx, req, operatorName)
	if err != nil {
		return nil, err
	}

	sysAccountIdentity, err := b.readIdentity(ctx, req, systemAccountName)
	if err != nil {
		return nil, err
	}
	systemAccountJwt, err := b.readJwt(ctx, req, systemAccountName)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			operatorIdentity.Name: NKeyWithToken{
				PublicKey: operatorIdentity.PublicKey,
				Jwt:       operatorJwt,
			},
			sysAccountIdentity.Name: NKeyWithToken{
				PublicKey: sysAccountIdentity.PublicKey,
				Jwt:       systemAccountJwt,
			},
		},
	}, nil
}

func (b *backend) saveConfiguration(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	var operatorJwt string
	var systemAccountJwt string

	operatorIdentity, err := b.readIdentity(ctx, req, operatorName)
	if err != nil {
		return nil, err
	}
	if operatorIdentity == nil {
		operatorIdentity, err = b.createIdentity(ctx, req, nkeys.PrefixByteOperator, operatorName)
		if err != nil {
			return nil, err
		}
	}

	sysAccountIdentity, err := b.readIdentity(ctx, req, systemAccountName)
	if err != nil {
		return nil, err
	}
	if sysAccountIdentity == nil {
		if sysAccountIdentity, err = b.createIdentity(ctx, req, nkeys.PrefixByteAccount, systemAccountName); err != nil {
			return nil, err
		}
	}

	accountServerUrl := data.Get("account-jwt-server-url").(string)
	operatorServiceUrl := data.Get("service-url").(string)
	tags := data.Get("tag").([]string)

	if operatorJwt, err = b.createOperatorToken(ctx, req, operatorIdentity, sysAccountIdentity,
		accountServerUrl, []string{operatorServiceUrl}, tags); err != nil {
		return nil, err
	} else if systemAccountJwt, err = b.createSystemAccountToken(ctx, req, operatorIdentity, sysAccountIdentity); err != nil {
		return nil, err
	}

	if userIdentity, err := b.readIdentity(ctx, req, sysAccountUserName); err != nil {
		return nil, err
	} else if userIdentity == nil {
		if _, err = b.createIdentity(ctx, req, nkeys.PrefixByteUser, sysAccountUserName); err != nil {
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			operatorIdentity.Name: NKeyWithToken{
				PublicKey: operatorIdentity.PublicKey,
				Jwt:       operatorJwt,
			},
			sysAccountIdentity.Name: NKeyWithToken{
				PublicKey: sysAccountIdentity.PublicKey,
				Jwt:       systemAccountJwt,
			},
		},
	}, nil
}

func (b *backend) createSystemAccountToken(ctx context.Context, req *logical.Request, operatorIdentity *Identity, sysAccountIdentity *Identity) (string, error) {

	var signingPublicKey string

	if signingKP, err := nkeys.CreateAccount(); err != nil {
		return "", fmt.Errorf("failed to create system account: %w", err)
	} else if signingPublicKey, err = signingKP.PublicKey(); err != nil {
		return "", err
	}

	sysAccClaim := jwt.NewAccountClaims(sysAccountIdentity.PublicKey)
	sysAccClaim.Name = "SYS"
	sysAccClaim.SigningKeys.Add(signingPublicKey)

	sysAccClaim.Exports = jwt.Exports{&jwt.Export{
		Name:                 "account-monitoring-services",
		Subject:              "$SYS.REQ.ACCOUNT.*.*",
		Type:                 jwt.Service,
		ResponseType:         jwt.ResponseTypeStream,
		AccountTokenPosition: 4,
		Info: jwt.Info{
			Description: `Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO`,
			InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
		},
	}, &jwt.Export{
		Name:                 "account-monitoring-streams",
		Subject:              "$SYS.ACCOUNT.*.>",
		Type:                 jwt.Stream,
		AccountTokenPosition: 3,
		Info: jwt.Info{
			Description: `Account specific monitoring stream`,
			InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
		},
	}}

	var sysAccJwt string
	if opKp, err := nkeys.FromSeed([]byte(operatorIdentity.Seed)); err != nil {
		return "", err
	} else if sysAccJwt, err = sysAccClaim.Encode(opKp); err != nil {
		return "", err
	}

	if err := b.storeJwt(ctx, req, sysAccountIdentity.Name, sysAccJwt); err != nil {
		return "", err
	}

	return sysAccJwt, nil

}

func (b *backend) createOperatorToken(ctx context.Context, req *logical.Request, operatorIdentity *Identity,
	systemAccountIdentity *Identity, accountServerUrl string, operatorServiceUrls []string, tags []string) (string, error) {

	keyPair, err := nkeys.FromSeed([]byte(operatorIdentity.Seed))
	if err != nil {
		return "", err
	}
	v := jwt.NewOperatorClaims(string(operatorIdentity.PublicKey))
	v.Name = operatorIdentity.Name
	v.Operator = jwt.Operator{
		AccountServerURL:    accountServerUrl,
		OperatorServiceURLs: operatorServiceUrls,
		SystemAccount:       systemAccountIdentity.PublicKey,
		GenericFields: jwt.GenericFields{
			Tags: tags,
		},
	}

	token, err := v.Encode(keyPair)
	if err != nil {
		return "", err
	}

	if err = b.storeJwt(ctx, req, operatorIdentity.Name, token); err != nil {
		return "", err
	}

	return token, nil
}
