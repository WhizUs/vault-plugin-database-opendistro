package mock

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	superUsername = "fizz"
	superPassword = "buzz"
)

func Opendistro() *FakeOpendistro {
	return &FakeOpendistro{
		Roles: make(map[string]map[string]interface{}),
		Users: make(map[string]map[string]interface{}),
	}
}

type FakeOpendistro struct {
	Roles map[string]map[string]interface{}
	Users map[string]map[string]interface{}
}

func (f *FakeOpendistro) HandleRequests(w http.ResponseWriter, r *http.Request) {
	// See if the username and password given match any expected.
	reqUsername, reqPassword, _ := r.BasicAuth()
	match := false
	if reqUsername == superUsername && reqPassword == superPassword {
		match = true
	} else {
		// posting user: {"password":"pa55w0rd","roles":["vault"]}
		for name, user := range f.Users {
			if name != reqUsername {
				continue
			}
			password, ok := user["password"].(string)
			if !ok {
				break
			}
			if password != reqPassword {
				break
			}
			match = true
		}
	}
	if !match {
		w.WriteHeader(401)
		_, err := w.Write([]byte("Authentication finally failed"))
		if err != nil {
			panic(fmt.Sprintf("could not write: %s", err))
		}
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("unable to read request body due to %s", err.Error())))
		return
	}
	body := make(map[string]interface{})
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			w.WriteHeader(400)
			w.Write([]byte(fmt.Sprintf("unable to unmarshal %s due to %s", bodyBytes, err.Error())))
			return
		}
	}

	switch {
	case 0 == strings.Compare(r.URL.Path, "/_opendistro/_security/health"):
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(healthcheck))
			return
		}
	case strings.HasPrefix(r.URL.Path, "/_opendistro/_security/api/roles/"):
		switch r.Method {
		case http.MethodPut:
			if _, found := f.Roles[""]; found {
				//w.Write([]byte(fmt.Sprintf(createRoleResponseTpl, "false")))
				// hier wird aktualisiert
			} else {
				//w.Write([]byte(fmt.Sprintf(createRoleResponseTpl, "true")))
				// hier wird erstellt
			}
			f.Roles[""] = body
			return
		case http.MethodPatch:
			if _, found := f.Roles[""]; found {
				w.Write([]byte(fmt.Sprintf(createRoleResponseTpl, "false")))
			} else {
				w.Write([]byte(fmt.Sprintf(createRoleResponseTpl, "true")))
			}
			f.Roles[""] = body
			return
		case http.MethodGet:
			role, found := f.Roles[""]
			if !found {
				w.WriteHeader(404)
				return
			}
			roleJson, _ := json.Marshal(role)
			w.Write([]byte(fmt.Sprintf(getRoleResponseTpl, "", roleJson)))
			return
		case http.MethodDelete:
			if _, found := f.Roles[""]; found {
				w.Write([]byte(fmt.Sprintf(deleteRoleResponseTpl, "true")))
			} else {
				w.Write([]byte(fmt.Sprintf(deleteRoleResponseTpl, "false")))
			}
			delete(f.Roles, "")
			return
		}
	case strings.HasPrefix(r.URL.Path, "/_opendistro/_security/api/rolesmapping/"):
		switch r.Method {
		case http.MethodPost:
			if _, found := f.Users[""]; found {
				w.Write([]byte(fmt.Sprintf(createUserResponseTpl, "false", "false")))
			} else {
				w.Write([]byte(fmt.Sprintf(createUserResponseTpl, "true", "true")))
			}
			f.Users[""] = body
			return
		case http.MethodDelete:
			if _, found := f.Users[""]; found {
				w.Write([]byte(fmt.Sprintf(deleteUserResponseTpl, "true")))
			} else {
				w.Write([]byte(fmt.Sprintf(deleteUserResponseTpl, "false")))
			}
			delete(f.Users, "")
			return
		}
	case strings.HasPrefix(r.URL.Path, "/_opendistro/_security/api/internalusers/"):
		switch r.Method {
		case http.MethodPost:
			if body["password"].(string) == "" {
				w.WriteHeader(400)
				w.Write([]byte("password is required"))
				return
			}
			w.Write([]byte(changePasswordResponse))
			return
		}
	}
	// We received an unexpected request.
	w.WriteHeader(400)
	w.Write([]byte(fmt.Sprintf("\"error\": \"no handler found for uri [%s] and method [%s]\"", r.URL.Path, r.Method)))
}

func (f *FakeOpendistro) Username() string {
	return superUsername
}

func (f *FakeOpendistro) Password() string {
	return superPassword
}
