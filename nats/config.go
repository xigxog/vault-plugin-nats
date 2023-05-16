package nats

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type NKeyWithToken struct {
	PublicKey string `json:"public_key"`
	JWT       string `json:"jwt"`
}

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:      "config",
			HelpSynopsis: "Configures the plugin with various NATS server configuration.",
			Fields: map[string]*framework.FieldSchema{
				accountSrvURLKey: {
					Type:        framework.TypeString,
					Description: "Account JWT server URL, only http/https/nats urls supported.",
					Default:     "nats://127.0.0.1:4222",
				},
				svcURLKey: {
					Type:        framework.TypeString,
					Description: "NATS server URL, only nats/tls urls supported.",
					Default:     "nats://127.0.0.1:4222",
				},
				tagsKey: {
					Type:        framework.TypeCommaStringSlice,
					Description: "Comma separated string or list of tags",
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

	operator, err := b.readIdentity(ctx, req, operatorName)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		return nil, fmt.Errorf("operator identity not found, plugin must be initialized by creating a config")
	}
	sysAccount, err := b.readIdentity(ctx, req, sysAccountName)
	if err != nil {
		return nil, err
	}
	if sysAccount == nil {
		return nil, fmt.Errorf("system account identity not found, plugin must be initialized by creating a config")
	}

	operatorJWT, err := b.readJWT(ctx, req, operatorName)
	if err != nil {
		return nil, err
	}
	sysAccountJWT, err := b.readJWT(ctx, req, sysAccountName)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			operator.Name: NKeyWithToken{
				PublicKey: operator.PublicKey,
				JWT:       operatorJWT,
			},
			sysAccount.Name: NKeyWithToken{
				PublicKey: sysAccount.PublicKey,
				JWT:       sysAccountJWT,
			},
		},
	}, nil
}

func (b *backend) saveConfiguration(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	operator, err := b.readIdentity(ctx, req, operatorName)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		b.Logger().Debug("operator identity does not exist, creating it")
		operator, err = b.createIdentity(ctx, req, nkeys.PrefixByteOperator, operatorName)
		if err != nil {
			return nil, err
		}
	}

	sysAccount, err := b.readIdentity(ctx, req, sysAccountName)
	if err != nil {
		return nil, err
	}
	if sysAccount == nil {
		b.Logger().Debug("system account identity does not exist, creating it")
		if sysAccount, err = b.createIdentity(ctx, req, nkeys.PrefixByteAccount, sysAccountName); err != nil {
			return nil, err
		}
	}

	user, err := b.readIdentity(ctx, req, sysAccountUser)
	if err != nil {
		return nil, err
	}
	if user == nil {
		if _, err = b.createIdentity(ctx, req, nkeys.PrefixByteUser, sysAccountUser); err != nil {
			return nil, err
		}
	}

	operatorJWT, err := b.createOperatorToken(ctx, req, data, operator, sysAccount)
	if err != nil {
		return nil, err
	}
	sysAccountJWT, err := b.createSysAccountToken(ctx, req, operator, sysAccount)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			operator.Name: NKeyWithToken{
				PublicKey: operator.PublicKey,
				JWT:       operatorJWT,
			},
			sysAccount.Name: NKeyWithToken{
				PublicKey: sysAccount.PublicKey,
				JWT:       sysAccountJWT,
			},
		},
	}, nil
}

func (b *backend) createSysAccountToken(ctx context.Context, req *logical.Request,
	operator *Identity, sysAccount *Identity) (string, error) {

	var signingPublicKey string

	if signingKP, err := nkeys.CreateAccount(); err != nil {
		return "", fmt.Errorf("failed to create system account: %w", err)
	} else if signingPublicKey, err = signingKP.PublicKey(); err != nil {
		return "", err
	}

	sysAccountClaim := jwt.NewAccountClaims(sysAccount.PublicKey)
	sysAccountClaim.Name = "SYS"
	sysAccountClaim.SigningKeys.Add(signingPublicKey)

	sysAccountClaim.Exports = jwt.Exports{&jwt.Export{
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

	var sysAccountJWT string
	if opKp, err := nkeys.FromSeed([]byte(operator.Seed)); err != nil {
		return "", err
	} else if sysAccountJWT, err = sysAccountClaim.Encode(opKp); err != nil {
		return "", err
	}

	if err := b.storeJWT(ctx, req, sysAccount.Name, sysAccountJWT); err != nil {
		return "", err
	}

	return sysAccountJWT, nil
}

func (b *backend) createOperatorToken(ctx context.Context, req *logical.Request, data *framework.FieldData,
	operator *Identity, sysAccount *Identity) (string, error) {

	keyPair, err := nkeys.FromSeed([]byte(operator.Seed))
	if err != nil {
		return "", err
	}

	accSrvURL := data.Get(accountSrvURLKey).(string)
	svcURL := data.Get(svcURLKey).(string)
	tags := data.Get(tagsKey).([]string)

	v := jwt.NewOperatorClaims(string(operator.PublicKey))
	v.Name = operator.Name
	v.Operator = jwt.Operator{
		AccountServerURL:    accSrvURL,
		OperatorServiceURLs: []string{svcURL},
		SystemAccount:       sysAccount.PublicKey,
		GenericFields: jwt.GenericFields{
			Tags: tags,
		},
	}

	token, err := v.Encode(keyPair)
	if err != nil {
		return "", err
	}

	if err = b.storeJWT(ctx, req, operator.Name, token); err != nil {
		return "", err
	}

	return token, nil
}
