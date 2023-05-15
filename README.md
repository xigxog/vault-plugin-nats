# Vault NATS Secrets Engine

[![Go Report Card](https://goreportcard.com/badge/github.com/xigxog/vault-plugin-nats)](https://goreportcard.com/report/github.com/xigxog/vault-plugin-nats)

This engine generates and manages NATS NKeys for Operators, Accounts, and Users.
The NKeys can then be used to generate JWTs for Users and Accounts. The secrets
engine can be used to implement [NATS decentralized
authentication/authorization](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt#decentralized-authentication-authorization-using-jwt)
utilzing Vault instead of `nsc`.

## Enable Engine

```bash
vault secrets enable [-path {cluster name}] vault-plugin-nats
```

## Configuration Lifecycle

- [Create Configuration](#create-configuration)

## Create Configuration

This endpoint configures the plugin with various NATS server configuration. It
returns the Operator and System Account JWTs.

| Method | Path                 |
| ------ | -------------------- |
| POST   | `:mount-path`/config |

### Parameters

| Name                   | Type    | Description                                                                                   |
| ---------------------- | ------- | --------------------------------------------------------------------------------------------- |
| `:mount-path`          | String  | The mount path of the plugin. This is specified as part of the URL.                           |
| account_jwt_server_url | URL     | Account JWT server URL, only http/https/nats urls supported. (default: nats://127.0.0.1:4222) |
| service_url            | URL     | NATS server URL, only nats/tls urls supported. (default: nats://127.0.0.1:4222)               |
| tags                   | Strings | Comma separated list of user tags. (optional)                                                 |

### Sample Payload

```json
{
  "account_jwt_url": "nats://127.0.0.1:4222",
  "service_url": "nats://127.0.0.1:4222",
  "tags": "staging"
}
```

### Sample Request

```shell
curl --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/config | jq .
```

### Sample Response

```json
{
  "request_id": "03391799-3541-b74a-571a-e77f049ab0d3",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "operator_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJTNjVBTERVQUtHTjdTRUlJRUJFWFhOSVpJS1dHR0kzN0c3NEpJTlVHVlpJUUNLVVdESjZRIiwiaWF0IjoxNjY2MjkzMjY2LCJpc3MiOiJPQUtJVzNFS0oySUFFRUZGTURLV0dSSUlKMlY0Rk9YWk1NM0lCSkQ0RkNWUEJHREtVNUdOS0lXNyIsIm5hbWUiOiJERU1PIiwic3ViIjoiT0FLSVczRUtKMklBRUVGRk1ES1dHUklJSjJWNEZPWFpNTTNJQkpENEZDVlBCR0RLVTVHTktJVzciLCJuYXRzIjp7ImFjY291bnRfc2VydmVyX3VybCI6Im5hdHM6Ly9sb2NhbGhvc3Q6NDIyMiIsIm9wZXJhdG9yX3NlcnZpY2VfdXJscyI6WyJuYXRzOi8vbG9jYWxob3N0OjQyMjIiLCJuYXRzOi8vYXNmOjQyMjIiXSwic3lzdGVtX2FjY291bnQiOiJBQU41M0NLUkJOUUVKN0NYMjRCM1NPU0JDS1ZCT1VDWkRYRkNaWkhEMkdDUTJOWjZEV1FHRVNKNiIsInR5cGUiOiJvcGVyYXRvciIsInZlcnNpb24iOjJ9fQ.0bvh_F_gmOdTJFY8Fc_BarGm-WpNwLTiq1GjA_T1Kgo2ZAlrCKGq1bGfrqUNGMalxQpRcs6a-ofcoEUkF0nvCg",
    "system_account_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJDUTRQUE9SV0NOU0dKUjROUjVVSkwzQ0tDM1NMTUxTM1RWTE1BQ1EyN0Q2NkxWQzVYQldBIiwiaWF0IjoxNjY2MjgzOTE3LCJpc3MiOiJPQUtJVzNFS0oySUFFRUZGTURLV0dSSUlKMlY0Rk9YWk1NM0lCSkQ0RkNWUEJHREtVNUdOS0lXNyIsIm5hbWUiOiJTWVMiLCJzdWIiOiJBQU41M0NLUkJOUUVKN0NYMjRCM1NPU0JDS1ZCT1VDWkRYRkNaWkhEMkdDUTJOWjZEV1FHRVNKNiIsIm5hdHMiOnsiZXhwb3J0cyI6W3sibmFtZSI6ImFjY291bnQtbW9uaXRvcmluZy1zdHJlYW1zIiwic3ViamVjdCI6IiRTWVMuQUNDT1VOVC4qLlx1MDAzZSIsInR5cGUiOiJzdHJlYW0iLCJhY2NvdW50X3Rva2VuX3Bvc2l0aW9uIjozLCJkZXNjcmlwdGlvbiI6IkFjY291bnQgc3BlY2lmaWMgbW9uaXRvcmluZyBzdHJlYW0iLCJpbmZvX3VybCI6Imh0dHBzOi8vZG9jcy5uYXRzLmlvL25hdHMtc2VydmVyL2NvbmZpZ3VyYXRpb24vc3lzX2FjY291bnRzIn0seyJuYW1lIjoiYWNjb3VudC1tb25pdG9yaW5nLXNlcnZpY2VzIiwic3ViamVjdCI6IiRTWVMuUkVRLkFDQ09VTlQuKi4qIiwidHlwZSI6InNlcnZpY2UiLCJyZXNwb25zZV90eXBlIjoiU3RyZWFtIiwiYWNjb3VudF90b2tlbl9wb3NpdGlvbiI6NCwiZGVzY3JpcHRpb24iOiJSZXF1ZXN0IGFjY291bnQgc3BlY2lmaWMgbW9uaXRvcmluZyBzZXJ2aWNlcyBmb3I6IFNVQlNaLCBDT05OWiwgTEVBRlosIEpTWiBhbmQgSU5GTyIsImluZm9fdXJsIjoiaHR0cHM6Ly9kb2NzLm5hdHMuaW8vbmF0cy1zZXJ2ZXIvY29uZmlndXJhdGlvbi9zeXNfYWNjb3VudHMifV0sImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiY29ubiI6LTEsImxlYWYiOi0xfSwic2lnbmluZ19rZXlzIjpbIkFDTlZLVFNEWExPSktSNUVYN1JJU1I1QjJMVEg2S1VCRzJFTE1JNUkyS1pXR1BNUE43REc3U05aIl0sImRlZmF1bHRfcGVybWlzc2lvbnMiOnsicHViIjp7fSwic3ViIjp7fX0sInR5cGUiOiJhY2NvdW50IiwidmVyc2lvbiI6Mn19.1uvNMxMpSYbKjE4fhLcJ6JK8eXi17M2Zzegm1mZdTyQPTG08PbRSjr5ppB4UgVx9WDRtJREIPtNStgDwZGteBQ"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

## Generate JWTs

This endpoint generates User and Account JWTs using the provided configuration.
If a User JWT is being generated the name of a previously created Account must
be provided. Additionaly for User JWTs a signed nonce required to authenticate
with the NATS server is returned.

| Methods | Path                      |
| ------- | ------------------------- |
| POST    | `:mount-path`/jwt/`:name` |

### Parameters

| Name       | Type                     | Description                                                                                                                                                                                                                                                       |
| ---------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| mount-path | String                   | The mount path of the plugin. This is specified as part of the URL.                                                                                                                                                                                               |
| name       | String                   | The name of the account or user for which to create a JWT.                                                                                                                                                                                                        |
| type       | Enum [`account`, `user`] | Type of JWT to generate. (required)                                                                                                                                                                                                                               |
| account    | String                   | Name of a previously generated Account that should be used to sign the User JWT. (required if type=user)                                                                                                                                                          |
| config     | JSON                     | Configuration for either [Account](https://github.com/nats-io/jwt/blob/e11ce317263cef69619fc1ca743b195d02aa1d8a/account_claims.go#L57) or [User](https://github.com/nats-io/jwt/blob/e11ce317263cef69619fc1ca743b195d02aa1d8a/user_claims.go#L25) JWT. (required) |

### JWT Sample Response

```json
{
  "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJPSVhTUUw2Rk1YNlJVTVVaWUc1RVA3RktTTjVKQjRZNVk3VFdJRkNHRk9ORERBV0VITEpBIiwiaWF0IjoxNjY2MjgzOTE3LCJpc3MiOiJBQ05WS1RTRFhMT0pLUjVFWDdSSVNSNUIyTFRINktVQkcyRUxNSTVJMktaV0dQTVBON0RHN1NOWiIsIm5hbWUiOiJzeXMiLCJzdWIiOiJVQ1RSM0hIWU42WUJGTTNJN1hIWkVRNkFKWlFGN1pHQVVFQ09VTVBGRjZaM0JURDQ0RVo0U0NXSSIsIm5hdHMiOnsicHViIjp7fSwic3ViIjp7fSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaXNzdWVyX2FjY291bnQiOiJBQU41M0NLUkJOUUVKN0NYMjRCM1NPU0JDS1ZCT1VDWkRYRkNaWkhEMkdDUTJOWjZEV1FHRVNKNiIsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.B3iUDYznSKSvcz-Xozm9oaZb_aaFgiYBCLiH5aEGv156PwDmilrK6CRzXg5fWiRt3Hewn-4EBsUqiXntOmqmBw"
}
```

## Sign Nonce

This endpoint signs the nonce (challenge string) returned by NATS during
authentication. Signing can only be used with User JWTs.

| Methods | Path                           |
| ------- | ------------------------------ |
| POST    | `:mount-path`/jwt/`:name`/sign |

### Parameters

| Name       | Type   | Description                                                          |
| ---------- | ------ | -------------------------------------------------------------------- |
| mount-path | String | The mount path of the plugin. This is specified as part of the URL.  |
| name       | String | The name of the user that is used to sign the nonce.                 |
| nonce      | String | The nonce (challenge string) returned by NATS during authentication. |

### JWT Sample Response

```json
{
  "signed_nonce": "RA2ZdifT+iwAZVtr6Lg8Nqkn2WPHHOaf70Qo+I2o214QDYK/JFHhWZe5h7uEc+vE+U6d/TL69/l5TnFhRmhYCg=="
}
```

## Local Development

```shell
make start
make enable
./hack/test.sh
```
