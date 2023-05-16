package nats

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/nkeys"
)

// Identity is a trusted entity in vault.
type Identity struct {
	Name        string   `json:"name"`
	Seed        string   `json:"seed"`
	PublicKey   string   `json:"public_key"`
	TrustedKeys []string `json:"trusted_keys_list" structs:"trusted_keys" mapstructure:"trusted_keys"`
}

func (b *backend) createIdentity(ctx context.Context, req *logical.Request, keyType nkeys.PrefixByte, name string) (*Identity, error) {
	pair, err := nkeys.CreatePair(keyType)
	if err != nil {
		return nil, err
	}
	defer pair.Wipe()

	identity, err := b.storeIdentity(ctx, req, name, pair, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to store identity '%s': %w", name, err)
	}

	return identity, err
}

func (b *backend) readIdentity(ctx context.Context, req *logical.Request, name string) (*Identity, error) {
	path := fmt.Sprintf("identities/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity '%s': %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}

	var identity Identity
	entry.DecodeJSON(&identity)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize identity at %s", path)
	}

	return &identity, nil
}

func (b *backend) storeIdentity(ctx context.Context, req *logical.Request, name string, pair nkeys.KeyPair, trustedKeys []string) (*Identity, error) {
	pubKey, err := pair.PublicKey()
	if err != nil {
		return nil, err
	}
	seed, err := pair.Seed()
	if err != nil {
		return nil, err
	}

	identity := &Identity{
		Name:        name,
		PublicKey:   pubKey,
		TrustedKeys: trustedKeys,
		Seed:        string(seed),
	}
	path := fmt.Sprintf("identities/%s", name)

	entry, err := logical.StorageEntryJSON(path, identity)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// PrefixByteFromString returns a PrefixByte from the stringified value
func PrefixByteFromString(p string) nkeys.PrefixByte {
	switch p {
	case "operator":
		return nkeys.PrefixByteOperator
	case "server":
		return nkeys.PrefixByteServer
	case "cluster":
		return nkeys.PrefixByteCluster
	case "account":
		return nkeys.PrefixByteAccount
	case "user":
		return nkeys.PrefixByteUser
	case "seed":
		return nkeys.PrefixByteSeed
	case "private":
		return nkeys.PrefixBytePrivate
	}

	return nkeys.PrefixByteUnknown
}
