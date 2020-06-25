package opendistro

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"

	od "github.com/WhizUs/go-opendistro"
	odsec "github.com/WhizUs/go-opendistro/security"
)

func New() (interface{}, error) {
	db := NewOpendistro()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues), nil
}

func Run(apiTLSConfig *api.TLSConfig) error {
	dbplugin.Serve(NewOpendistro(), api.VaultPluginTLSProvider(apiTLSConfig))
	return nil
}

func NewOpendistro() *Opendistro {
	return &Opendistro{
		credentialProducer: &credsutil.SQLCredentialsProducer{
			DisplayNameLen: 15,
			RoleNameLen:    15,
			UsernameLen:    100,
			Separator:      "_",
		},
	}
}

type Opendistro struct {

	// The CredentialsProducer is never mutated and thus is inherently thread-safe.
	credentialProducer credsutil.CredentialsProducer

	// This protects the configs from races while also allowing multiple threads
	// to read the configs simultaneously when it's not changing.
	mux sync.RWMutex

	// The root credential configs.
	config map[string]interface{}
}

func (o *Opendistro) Type() (string, error) {
	return "opendistro", nil
}

// SecretValues is used by some error-sanitizing middleware in Vault that basically
// replaces the keys in the map with the values given so they're not leaked via
// error messages.
func (o *Opendistro) SecretValues() map[string]interface{} {
	o.mux.RLock()
	defer o.mux.RUnlock()

	replacements := make(map[string]interface{})
	for _, secretKey := range []string{"password", "client_key"} {
		vIfc, found := o.config[secretKey]
		if !found {
			continue
		}
		secretVal, ok := vIfc.(string)
		if !ok {
			continue
		}
		// So, supposing a password of "0pen5e5ame",
		// this will cause that string to get replaced with "[password]".
		replacements[secretVal] = "[" + secretKey + "]"
	}
	return replacements
}

func (o *Opendistro) Init(ctx context.Context, config map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {

	for _, requiredField := range []string{"username", "password", "url"} {
		raw, ok := config[requiredField]
		if !ok {
			return nil, fmt.Errorf(`%q must be provided`, requiredField)
		}
		if _, ok := raw.(string); !ok {
			return nil, fmt.Errorf(`%q must be a string`, requiredField)
		}
	}

	for _, optionalField := range []string{"ca_cert", "ca_path", "client_cert", "client_key", "tls_server_name"} {
		raw, ok := config[optionalField]
		if !ok {
			continue
		}
		if _, ok = raw.(string); !ok {
			return nil, fmt.Errorf(`%q must be a string`, optionalField)
		}
	}

	if raw, ok := config["insecure"]; ok {

		_, err := strconv.ParseBool(raw.(string))

		if err != nil {
			return nil, errors.New(`"insecure" must be a bool`)
		}
	}

	client, err := buildClient(config)
	if err != nil {
		return nil, errwrap.Wrapf("couldn't make client with inbound configs: {{err}}", err)
	}

	if verifyConnection {
		if _, err := client.Security.Health.Get(ctx); err != nil {
			return nil, errwrap.Wrapf("client test of getting health status failed: {{err}}", err)
		}
	}

	o.mux.Lock()
	defer o.mux.Unlock()
	o.config = config
	return o.config, nil
}

func (o *Opendistro) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, _ time.Time) (string, string, error) {
	username, err := o.credentialProducer.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", errwrap.Wrapf(fmt.Sprintf("unable to generate username for %q: {{err}}", usernameConfig), err)
	}

	password, err := o.credentialProducer.GeneratePassword()
	if err != nil {
		return "", "", errwrap.Wrapf("unable to generate password: {{err}}", err)
	}

	stmt, err := newCreationStatement(statements)
	if err != nil {
		return "", "", errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	var roles []string
	if stmt.NewRolePermissions != nil {
		roles = []string{username}
	} else {
		roles = stmt.PreexistingRoles
	}

	user := &odsec.UserCreate{
		Password: password,
		Roles:    roles,
	}

	// Don't let anyone write the configs while we're using it for our current client.
	o.mux.RLock()
	defer o.mux.RUnlock()

	client, err := buildClient(o.config)
	if err != nil {
		return "", "", errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	// If a new role should be created, it is created by providing permissions spec and name, we use username as role-name to find it easier
	if stmt.NewRolePermissions != nil {
		if err := client.Security.Roles.Create(ctx, username, stmt.NewRolePermissions); err != nil {
			return "", "", errwrap.Wrapf(fmt.Sprintf("unable to create role name %s, role definition %#v: {{err}}", username, stmt.NewRolePermissions), err)
		}
	}

	// Just create a user
	if err := client.Security.Users.Create(ctx, username, user); err != nil {
		return "", "", errwrap.Wrapf(fmt.Sprintf("unable to create user name %s, user %q: {{err}}", username, user), err)
	}

	return username, password, nil
}

func (o *Opendistro) RenewUser(_ context.Context, _ dbplugin.Statements, _ string, _ time.Time) error {
	// Normally, this function would update a "VALID UNTIL" statement on a database user
	// but there's no similar need here.
	return nil
}

func (o *Opendistro) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	stmt, err := newCreationStatement(statements)
	if err != nil {
		return errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	o.mux.RLock()
	defer o.mux.RUnlock()

	client, err := buildClient(o.config)
	if err != nil {
		return errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	var errs error

	if stmt.NewRolePermissions != nil {
		if err := client.Security.Roles.Delete(ctx, username); err != nil {
			errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to delete role name %s: {{err}}", username), err))
		}
	}

	if err := client.Security.Users.Delete(ctx, username); err != nil {
		errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to delete user name %s: {{err}}", username), err))
	}
	return errs
}

func (o *Opendistro) RotateRootCredentials(ctx context.Context, _ []string) (map[string]interface{}, error) {
	newPassword, err := o.credentialProducer.GeneratePassword()
	if err != nil {
		return nil, errwrap.Wrapf("unable to generate root password: {{err}}", err)
	}

	o.mux.Lock()
	defer o.mux.Unlock()

	client, err := buildClient(o.config)
	if err != nil {
		return nil, errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	if err := client.Security.Users.ChangePassword(ctx, o.config["username"].(string), newPassword); err != nil {
		return nil, errwrap.Wrapf("unable to change password: {{}}", err)
	}

	o.config["password"] = newPassword
	return o.config, nil
}

func (o *Opendistro) Close() error {
	return nil
}

func (o *Opendistro) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := o.Init(ctx, config, verifyConnection)
	return err
}

func newCreationStatement(statements dbplugin.Statements) (*creationStatement, error) {
	if len(statements.Creation) == 0 {
		return nil, dbutil.ErrEmptyCreationStatement
	}

	stmt := &creationStatement{}

	if err := json.Unmarshal([]byte(statements.Creation[0]), stmt); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to unmarshal %s: {{err}}", []byte(statements.Creation[0])), err)
	}

	if len(stmt.PreexistingRoles) > 0 && stmt.NewRolePermissions != nil {
		return nil, errors.New(`"opendistro_roles" and "opendistro_role_permissions" are mutually exclusive`)
	}

	return stmt, nil
}

type creationStatement struct {
	PreexistingRoles   []string               `json:"opendistro_roles"`
	NewRolePermissions *odsec.RolePermissions `json:"opendistro_role_permissions"`
}

// buildClient is a helper method for building a client from the present configs,
// which is done often.
func buildClient(config map[string]interface{}) (*od.Client, error) {

	// We can presume these required fields are provided by strings
	// because they're validated in Init.
	clientConfig := &od.ClientConfig{
		Username: config["username"].(string),
		Password: config["password"].(string),
		BaseURL:  config["url"].(string),
	}

	hasTLSConf := false
	tlsConf := &od.TLSConfig{}

	// We can presume that if these are provided, they're in the expected format
	// because they're also validated in Init.
	if raw, ok := config["ca_cert"]; ok {
		tlsConf.CACert = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["ca_path"]; ok {
		tlsConf.CAPath = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["client_cert"]; ok {
		tlsConf.ClientCert = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["client_key"]; ok {
		tlsConf.ClientKey = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["tls_server_name"]; ok {
		tlsConf.TLSServerName = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["insecure"]; ok {

		insecure, _ := strconv.ParseBool(raw.(string))

		tlsConf.Insecure = insecure
		hasTLSConf = true
	}

	// We should only fulfill the clientConfig's TLSConfig pointer if we actually
	// want the client to use TLS.
	if hasTLSConf {
		clientConfig.TLSConfig = tlsConf
	}

	client, err := od.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GenerateCredentials returns a generated password
func (o *Opendistro) GenerateCredentials(ctx context.Context) (string, error) {
	password, err := o.credentialProducer.GeneratePassword()
	if err != nil {
		return "", err
	}
	return password, nil
}

// SetCredentials is used to set the credentials for a database user to a
// specific username and password. This is not currently supported by the
// elastic search plugin, but is needed to conform to the dbplugin.Database
// interface
func (o *Opendistro) SetCredentials(ctx context.Context, statements dbplugin.Statements, staticConfig dbplugin.StaticUserConfig) (username string, password string, err error) {
	return "", "", dbutil.Unimplemented()
}
