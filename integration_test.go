package opendistro

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/helper/tlsutil"
	"github.com/ory/dockertest"
)

const (
	esVaultUser     = "vault"
	esVaultPassword = "vault"
)

const (
	adminUser     = "admin"
	adminPassword = "admin"
)

func TestIntegration_Container(t *testing.T) {
	cleanup, client, retAddress := prepareTestContainer(t)
	defer cleanup()
	verifyTestContainer(t, retAddress)

	tc := NewOpendistroEnv(t, client, retAddress)

	env := &IntegrationTestEnv{
		Username:   esVaultUser,
		Password:   esVaultPassword,
		URL:        tc.BaseURL,
		CaCert:     filepath.Join("testdata", "certs", "root-ca.pem"),
		ClientCert: filepath.Join("testdata", "certs", "kirk.pem"),
		ClientKey:  filepath.Join("testdata", "certs", "kirk-key.pem"),
		Opendistro: NewOpendistro(),
		TestUsers:  make(map[string]dbplugin.Statements),
		TestCreds:  make(map[string]string),
		tc:         tc,
	}
	t.Run("test init", env.TestOpendistro_Init)
	t.Run("test create user", env.TestOpendistro_CreateUser)
	t.Run("test revoke user", env.TestOpendistro_RevokeUser)
	t.Run("test rotate root creds", env.TestOpendistro_RotateRootCredentials)

}

type IntegrationTestEnv struct {
	Username, Password, URL       string
	CaCert, ClientCert, ClientKey string
	Opendistro                    *Opendistro
	TestUsers                     map[string]dbplugin.Statements
	TestCreds                     map[string]string

	tc *OpendistroEnv
}

func (e *IntegrationTestEnv) TestOpendistro_Init(t *testing.T) {
	config := map[string]interface{}{
		"username":    e.Username,
		"password":    e.Password,
		"url":         e.URL,
		"ca_cert":     e.CaCert,
		"client_cert": e.ClientCert,
		"client_key":  e.ClientKey,
	}
	configToStore, err := e.Opendistro.Init(context.Background(), config, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(configToStore) != len(config) {
		t.Fatalf("expected %s, received %s", config, configToStore)
	}
	for k, v := range config {
		if configToStore[k] != v {
			t.Fatalf("for %s, expected %s but received %s", k, v, configToStore[k])
		}
	}
}

func (e *IntegrationTestEnv) TestOpendistro_CreateUser(t *testing.T) {
	statements1 := dbplugin.Statements{
		Creation: []string{`{ "opendistro_role_permissions": { "index_permissions": [{ "index_patterns": ["test-index-*"], "allowed_actions": ["unlimited"] }]}}`},
	}
	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "display-name",
		RoleName:    "role-name",
	}
	username1, password1, err := e.Opendistro.CreateUser(context.Background(), statements1, usernameConfig, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if username1 == "" {
		t.Fatal("expected username")
	}
	if password1 == "" {
		t.Fatal("expected password")
	}
	e.TestUsers[username1] = statements1
	e.TestCreds[username1] = password1

	if !e.tc.Authenticate(t, username1, password1) {
		t.Errorf("want successful authenication, got failed authentication for user:%s with password:%s", username1, password1)
	}
	statements2 := dbplugin.Statements{
		Creation: []string{`{"opendistro_roles": ["readall"]}`},
	}
	username2, password2, err := e.Opendistro.CreateUser(context.Background(), statements2, usernameConfig, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if username2 == "" {
		t.Fatal("expected username")
	}
	if password2 == "" {
		t.Fatal("expected password")
	}
	e.TestUsers[username2] = statements2
	e.TestCreds[username2] = password2

	if !e.tc.Authenticate(t, username2, password2) {
		t.Errorf("want successful authenication, got failed authentication for user:%s with password:%s", username2, password2)
	}
}

func (e *IntegrationTestEnv) TestOpendistro_RevokeUser(t *testing.T) {

	for username, statements := range e.TestUsers {

		if err := e.Opendistro.RevokeUser(context.Background(), statements, username); err != nil {
			t.Fatal(err)
		}

		password := e.TestCreds[username]
		if e.tc.Authenticate(t, username, password) {
			t.Errorf("want authenication failure, got successful authentication for user:%s with password:%s", username, password)
		}
	}
}

func (e *IntegrationTestEnv) TestOpendistro_RotateRootCredentials(t *testing.T) {
	originalConfig := map[string]interface{}{
		"username":    e.Username,
		"password":    e.Password,
		"url":         e.URL,
		"ca_cert":     e.CaCert,
		"client_cert": e.ClientCert,
		"client_key":  e.ClientKey,
	}

	//Client Certificate has to be removed
	transport := cleanhttp.DefaultTransport()

	caCert := readCertFile(t, "root-ca.pem")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	transport.TLSClientConfig = tlsConfig

	e.tc.Client.Transport = transport

	if !e.tc.Authenticate(t, e.Username, e.Password) {
		t.Errorf("want successful authenication, got failed authentication for user:%s with password:%s", e.Username, e.Password)
	}

	configToStore, err := e.Opendistro.RotateRootCredentials(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	if e.tc.Authenticate(t, e.Username, e.Password) {
		t.Errorf("want authenication failure, got successful authentication for user:%s with password:%s", e.Username, e.Password)
	}

	if len(originalConfig) != len(configToStore) {
		t.Fatalf("expected %s, received %s", originalConfig, configToStore)
	}
	for k, v := range originalConfig {
		if k == "password" {
			if configToStore[k] == v {
				t.Fatal("password should have changed")
			}
			continue
		}
		if configToStore[k] != v {
			t.Fatalf("for %s, expected %s but received %s", k, v, configToStore[k])
		}
	}
}

func readCertFile(t *testing.T, filename string) []byte {
	t.Helper()
	b, err := ioutil.ReadFile(filepath.Join("testdata", "certs", filename))
	if err != nil {
		t.Fatalf("Failed to read %s file: %s", filename, err)
	}
	return b
}

func prepareTestContainer(t *testing.T) (cleanup func(), client *http.Client, retAddress string) {
	t.Helper()

	certsDir, err := filepath.Abs(filepath.Join("testdata", "certs"))
	if err != nil {
		t.Fatalf("could not create an absolute path to the testdata/certs directory: %s", err)
	}

	configsDir, err := filepath.Abs(filepath.Join("testdata", "configs"))
	if err != nil {
		t.Fatalf("could not create an absolute path to the testdata/configs directory: %s", err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "whizus/elasticsearch-od",
		Tag:        "7.2.0",
		WorkingDir: "/usr/share/elasticsearch/",
		Mounts: []string{
			certsDir + ":/usr/share/elasticsearch/configs/certificates",
			configsDir + "/elasticsearch.yml" + ":/usr/share/elasticsearch/config/elasticsearch.yml",
		},
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		t.Fatalf("Could not start local OpenDistro docker container: %s", err)
	}
	cleanup = func() {
		cleanupResource(t, pool, resource)
	}

	log.Println("Waiting 20 seconds for OpenDistro to become ready...")
	time.Sleep(20 * time.Second)
	log.Println("OpenDistro is ready")

	caCert := readCertFile(t, "root-ca.pem")
	clientCert := readCertFile(t, "kirk.pem")
	clientKey := readCertFile(t, "kirk-key.pem")
	tlsConf, err := tlsutil.ClientTLSConfig(caCert, clientCert, clientKey)
	if err != nil {
		cleanup()
		t.Fatalf("Could not create a client tls.Conf: %s", err)
	}

	transport := cleanhttp.DefaultTransport()
	transport.TLSClientConfig = tlsConf
	client = cleanhttp.DefaultClient()
	client.Transport = transport

	retAddress = fmt.Sprintf("https://localhost:%s", resource.GetPort("9200/tcp"))

	if err := pool.Retry(func() error {
		var err error

		req, err := http.NewRequest(http.MethodGet, retAddress+"/_cat/health", nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(adminUser, adminPassword)

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		defer func() {
			err := resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}
		}()

		_, err = ioutil.ReadAll(resp.Body)
		return err
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to docker: %s", err)
	}
	return
}

func verifyTestContainer(t *testing.T, address string) {
	t.Helper()
	fn := func(client *http.Client) (int, error) {
		resp, err := client.Get(address + "/_cat/health")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		return resp.StatusCode, nil
	}
	var err error

	// verify server is using TLS
	transport := cleanhttp.DefaultTransport()
	client := cleanhttp.DefaultClient()
	client.Transport = transport
	_, err = fn(client)
	if err == nil {
		t.Fatal("want error with 'x509: certificate signed by unknown authority', got none")
	}

	if !strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
		t.Fatalf("want error with 'x509: certificate signed by unknown authority', got %s", err)
	}

	// verify client cert is required
	caCert := readCertFile(t, "root-ca.pem")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	transport.TLSClientConfig = tlsConfig

	statusCode, err := fn(client)
	if err != nil {
		t.Fatalf("error type: %T, value: %#v, string: %s", err, err, err)
	}
	if http.StatusUnauthorized != statusCode {
		t.Fatalf("want status code %d, got %d", http.StatusUnauthorized, statusCode)
	}
}

func cleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	t.Helper()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

type OpendistroEnv struct {
	Username, Password string
	BaseURL            string
	Client             *http.Client
}

func NewOpendistroEnv(t *testing.T, client *http.Client, retAddress string) *OpendistroEnv {
	t.Helper()

	tc := &OpendistroEnv{
		Username: "admin",
		Password: adminPassword,
		Client:   client,
		BaseURL:  retAddress,
	}

	if !tc.Authenticate(t, adminUser, adminPassword) {
		t.Fatal("failed to authenticate admin user")
	}
	// Create a vault role and vault user in ElasticSearch
	tc.CreateVaultUser(t)
	if !tc.Authenticate(t, esVaultUser, esVaultPassword) {
		t.Fatal("failed to authenticate vault user")
	}
	return tc
}

func (e *OpendistroEnv) Authenticate(t *testing.T, user, password string) bool {
	t.Helper()

	endpoint := "/_opendistro/_security/api/internalusers/" + user
	method := http.MethodGet

	req, err := http.NewRequest(method, e.BaseURL+endpoint, nil)
	if err != nil {
		t.Fatalf("failed to create a request for authenticating a user: %s", err)
	}
	req.SetBasicAuth(user, password)

	resp, err := e.Client.Do(req)
	if err != nil {
		t.Fatalf("request to OpenDistro failed for %s user using password %s: %s", user, password, err)
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %s", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	case http.StatusNotFound:
		return false
	default:
		t.Fatalf("authenication error: unexpected status code: %d", resp.StatusCode)
		return false
	}
}

func (e *OpendistroEnv) createVaultRole(t *testing.T) {
	t.Helper()

	endpoint := "/_opendistro/_security/api/rolesmapping/all_access"
	method := http.MethodPatch

	body, err := json.Marshal([]map[string]interface{}{
		{
			"op":    "add",
			"path":  "/users",
			"value": []string{esVaultUser},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal the body to create the vault role: %s", err)
	}
	req, err := http.NewRequest(method, e.BaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create a request for creating the vault role: %s", err)
	}
	if err := e.do(req, nil); err != nil {
		t.Fatalf("failed to create the vault role: %s", err)
	}
}

func (e *OpendistroEnv) CreateVaultUser(t *testing.T) {
	t.Helper()
	e.createVaultRole(t)

	endpoint := "/_opendistro/_security/api/internalusers/" + esVaultUser
	method := http.MethodPut

	type user struct {
		Password string `json:"password"`
	}

	u := &user{
		Password: esVaultPassword,
	}

	body, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("failed to marshal the body to create the vault user: %s", err)
	}
	req, err := http.NewRequest(method, e.BaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create a request for creating the vault user: %s", err)
	}
	if err := e.do(req, nil); err != nil {
		t.Fatalf("failed to create the vault user: %s", err)
	}
}

func (e *OpendistroEnv) do(req *http.Request, ret interface{}) error {
	req.SetBasicAuth(e.Username, e.Password)
	req.Header.Add("Content-Type", "application/json")

	resp, err := e.Client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if ret == nil {
			return nil
		}
		if err := json.Unmarshal(body, ret); err != nil {
			return fmt.Errorf("%s; %d: %s", err, resp.StatusCode, body)
		}
		return nil
	}

	if resp.StatusCode == 404 {
		return nil
	}
	return fmt.Errorf("%d: %s", resp.StatusCode, body)
}
