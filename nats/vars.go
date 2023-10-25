package nats

const pluginHelp = `
The NATS secret engine for managing Operators, Accounts, and Users.
`

const (
	jwtPathPrefix = "jwt/"

	operatorName   = "operator"
	sysAccountName = "system_account"
	sysAccountUser = "system_account_user"

	accountKey       = "account"
	accountSrvURLKey = "account_jwt_server_url"
	configKey        = "config"
	nameKey          = "name"
	nonceKey         = "nonce"
	svcURLKey        = "service_url"
	tagsKey          = "tags"
	typeKey          = "type"
)
