package build

/*
import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/go-rootcerts"
)

var (
	usersEndpoint        = "/_opendistro/_security/api/internalusers/"
	rolesEndpoint        = "/_opendistro/_security/api/roles/"
	rolesMappingEndpoint = "/_opendistro/_security/api/rolesmapping/"
)

type ClientConfig struct {
	Username, Password, BaseURL string

	// Leave this nil to flag that TLS is not desired
	TLSConfig *TLSConfig
}

// TLSConfig contains the parameters needed to configure TLS on the HTTP client
// used to communicate with Opendistro.
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify theHTTPClient
	// Opendistro server SSL certificate.
	CACert string

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Opendistro server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for Opendistro communication
	ClientCert string

	// ClientKey is the path to the private key for Opendistro communication
	ClientKey string

	// TLSServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	TLSServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

func NewClient(configs *ClientConfig) (*Client, error) {
	client := retryablehttp.NewClient()

	if configs.TLSConfig != nil {
		conf := &tls.Config{
			ServerName:         configs.TLSConfig.TLSServerName,
			InsecureSkipVerify: configs.TLSConfig.Insecure,
			MinVersion:         tls.VersionTLS12,
		}
		if configs.TLSConfig.ClientCert != "" && configs.TLSConfig.ClientKey != "" {
			clientCertificate, err := tls.LoadX509KeyPair(configs.TLSConfig.ClientCert, configs.TLSConfig.ClientKey)
			if err != nil {
				return nil, err
			}
			conf.Certificates = append(conf.Certificates, clientCertificate)
		}
		if configs.TLSConfig.CACert != "" || configs.TLSConfig.CAPath != "" {
			rootConfig := &rootcerts.Config{
				CAFile: configs.TLSConfig.CACert,
				CAPath: configs.TLSConfig.CAPath,
			}
			if err := rootcerts.ConfigureTLS(conf, rootConfig); err != nil {
				return nil, err
			}
		}

		client.HTTPClient.Transport = &http.Transport{TLSClientConfig: conf}
	}
	return &Client{
		Username: configs.Username,
		Password: configs.Password,
		BaseURL:  configs.BaseURL,
		Client:   client,
	}, nil
}

type Client struct {
	Username, Password, BaseURL string
	Client                      *retryablehttp.Client
}

type Patch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// Role management

type Role struct {
	IsStatic    bool   `json:"static"`
	IsReserved  bool   `json:"reserved"`
	IsHidden    bool   `json:"hidden"`
	Description string `json:"description"`
	RolePermissions
}

type RoleMapping struct {
	IsReserved  bool   `json:"reserved"`
	IsHidden    bool   `json:"hidden"`
	Description string `json:"description"`
	RoleMappingRelations
}

type RolePermissions struct {
	ClusterPermissions []string             `json:"cluster_permissions,omitempty"`
	IndexPermissions   []*IndexPermissions  `json:"index_permissions,omitempty"`
	TenantPermissions  []*TenantPermissions `json:"tenant_permissions,omitempty"`
}

type IndexPermissions struct {
	IndexPatterns  []string `json:"index_patterns,omitempty"`
	Dls            []string `json:"dls,omitempty"`
	Fls            []string `json:"fls,omitempty"`
	MaskedFields   []string `json:"masked_fields,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

type TenantPermissions struct {
	TenantPatterns []string `json:"tenant_patterns,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

type RoleMappingRelations struct {
	BackendRoles []string `json:"backend_roles,omitempty"`
	Hosts        []string `json:"hosts,omitempty"`
	Users        []string `json:"users,omitempty"`
}

func (c *Client) CreateRole(ctx context.Context, name string, rolePermissions *RolePermissions) error {
	endpoint := rolesEndpoint + name
	method := http.MethodPut

	rolePermissionsBytes, err := json.Marshal(rolePermissions)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.BaseURL+endpoint, bytes.NewReader(rolePermissionsBytes))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) GetRole(ctx context.Context, name string) (*map[string]Role, error) {
	endpoint := rolesEndpoint + name
	method := http.MethodGet

	req, err := http.NewRequest(method, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	var role map[string]Role
	if err := c.do(ctx, req, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

func (c *Client) DeleteRole(ctx context.Context, name string) error {
	endpoint := rolesEndpoint + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.BaseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) CreateRoleMapping(ctx context.Context, name string, roleMappingRelations *RoleMappingRelations) error {

	endpoint := rolesMappingEndpoint + name
	method := http.MethodPut

	roleMappingRelationsBytes, err := json.Marshal(roleMappingRelations)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.BaseURL+endpoint, bytes.NewReader(roleMappingRelationsBytes))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) GetRoleMapping(ctx context.Context, name string) (*map[string]RoleMapping, error) {
	endpoint := rolesMappingEndpoint + name
	method := http.MethodGet

	req, err := http.NewRequest(method, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	var roleMapping map[string]RoleMapping
	if err := c.do(ctx, req, &roleMapping); err != nil {
		return nil, err
	}
	return &roleMapping, nil
}

func (c *Client) DeleteRoleMapping(ctx context.Context, name string) error {
	endpoint := rolesMappingEndpoint + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.BaseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

// User management

type User struct {
}

type UserCreate struct {
	Password     string   `json:"password"` // Passwords must be at least 6 characters long.
	BackendRoles []string `json:"backend_roles,omitempty"`
	Attributes   []string `json:"attributes,omitempty"`
}

func (c *Client) CreateUser(ctx context.Context, name string, user *UserCreate) error {
	endpoint := usersEndpoint + name
	method := http.MethodPut

	userJson, err := json.Marshal(user)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.BaseURL+endpoint, bytes.NewReader(userJson))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) ChangePassword(ctx context.Context, name, newPassword string) error {
	endpoint := usersEndpoint
	method := http.MethodPatch

	patch := Patch{
		Op:    "replace",
		Path:  "/" + name,
		Value: map[string]interface{}{
			"password": newPassword,
		},
	}

	pwdChangeBodyJson, err := json.Marshal([]Patch{patch})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.BaseURL+endpoint, bytes.NewReader(pwdChangeBodyJson))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) DeleteUser(ctx context.Context, name string) error {
	endpoint := usersEndpoint + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.BaseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

// Low-level request handling

func (c *Client) do(ctx context.Context, req *http.Request, ret interface{}) error {
	// Prepare the request.
	retryableReq, err := retryablehttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return err
	}
	retryableReq.SetBasicAuth(c.Username, c.Password)
	retryableReq.Header.Add("Content-Type", "application/json")

	// Execute the request.
	resp, err := c.Client.Do(retryableReq.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read the body once so it can be retained for error output if needed.
	// Since no responses are list responses, response bodies should have a small footprint
	// and are very useful for debugging.
	body, _ := ioutil.ReadAll(resp.Body)

	// If we were successful, try to unmarshal the body if the caller wants it.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if ret == nil {
			// No body to read out.
			return nil
		}
		if err := json.Unmarshal(body, ret); err != nil {
			// We received a success response from the ES API but the body was in an unexpected format.
			return fmt.Errorf("%s; %d: %s", err, resp.StatusCode, body)
		}
		// Body has been successfully read out.
		return nil
	}

	// 404 is actually another form of success in the ES API. It just means that an object we were searching
	// for wasn't found.
	if resp.StatusCode == 404 {
		return nil
	}

	// We received some sort of API error. Let's return it.
	return fmt.Errorf("%d: %s", resp.StatusCode, body)
}
*/
