#!/bin/bash

export BASE=http://127.0.0.1:8200/v1/nats
export VAULT_TOKEN=root

# Create NATS Config
curl --request POST "$BASE/config" \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "account-jwt-server-url": "nats://127.0.0.1:4222",
        "service-url": "nats://test:4222",
        "tag": "test,dusty"
    }' | jq .

# Get JWT for a new Account
curl --request POST "$BASE/jwt/my_account" \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-raw '{
    "type": "account",
    "config": {
        "limits": {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "imports": -1,
            "exports": -1,
            "wildcards": true,
            "conn": -1,
            "leaf": -1
        },
        "signing_keys": [],
        "default_permissions": {
            "pub": {
                "allow": [
                    "req.>",
                    "res.>"
                ]
            },
            "sub": {}
        }
    }
}' | jq .

# Get JWT for a new User signed by our new account
curl --location --request POST "$BASE/jwt/my_user" \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-raw '{
    "type": "user",
    "account": "my_account",
    "nonce": "aN9-ZtS7taDoAZk",
    "config": {
        "pub": {},
        "sub": {},
        "subs": -1,
        "data": -1,
        "payload": -1
    }
}' | jq .

# Sign a nonce using the User JWT
curl --location --request POST "$BASE/jwt/my_user/sign" \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-raw '{
    "nonce": "aN9-ZtS7taDoAZk"
}' | jq .
