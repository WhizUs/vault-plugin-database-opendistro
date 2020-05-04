# OpenDistro for Elasticsearch Database Secrets Engine
> based on the original [plugin](https://github.com/hashicorp/vault-plugin-database-elasticsearch)

This plugin provides unique, short-lived credentials for Elasticsearch using OpenDistro.

Tested with Opendistro Security Plugin 1.6.0 and Vault 1.4.1.

## Getting Started

For this plugin to work, you must first install [OpenDistro](https://opendistro.github.io/for-elasticsearch/).

### Build

To build this plugin simply run

```bash
$ go build -o build/vault-plugin-database-opendistro ./cmd/vault-plugin-database-opendistro
```

### Configure

Enable database secrets engine

```bash
$ vault secrets enable -path=example database
```

Configure which roles can be used with 

```bash
$ vault write example/config/opendistro \
    plugin_name="vault-plugin-database-opendistro" \
    allowed_roles="internally-defined-role,externally-defined-role" \
    username=admin \
    password=admin \
    url=http://localhost:9200 \
    insecure=true
```

Define external role which will be used when new users a generated

```bash
vault write example/roles/externally-defined-role \
  db_name=opendistro \
  creation_statements='{ 
                          "opendistro_role_permissions": { 
                            "index_permissions": [ 
                              { 
                                "index_patterns": [ 
                                  "test-index-*" 
                                ], 
                                "allowed_actions": [ 
                                  "unlimited" 
                                ] 
                              } 
                            ] 
                          } 
                        }' \
  default_ttl="10m" \
  max_ttl="30m"
```

### Generate User

Read the cred by previously defined role

```bash
$ vault read example/creds/externally-defined-role
  Key                Value
  ---                -----
  lease_id           example/creds/externally-defined-role/w0MfpmzZ0jkWAyS1rnOvICSg
  lease_duration     10m
  lease_renewable    true
  password           A1a-9TzAGce3tbyePZvZ
  username           v_token_externally-defi_KxTRtdypZt5z4Dpy9AWW_1572991043
```

Try to add a new document with the new user and pass

```bash
$ curl -s -k -X POST http://localhost:9200/test-index-1/_doc \
      -H "Content-Type: application/json" \
      -u v_token_externally-defi_KxTRtdypZt5z4Dpy9AWW_1572991043:A1a-9TzAGce3tbyePZvZ \ 
      -d '{
            "name":"test"
          }' | jq
```

Expected result looks like this

```json
{
  "_index":"test-index-1",
  "_type":"_doc",
  "_id":"__2SPW4Bxqko3nrD2tZW",
  "_version":1,
  "result":"created",
  "_shards":{
    "total":2,
    "successful":2,
    "failed":0
  },
  "_seq_no":3,
  "_primary_term":14
}
```

## Development

The Vault plugin system is documented on the [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the `vault-plugin-database-opendistro` executable generated above in the directory.

Register the plugin using

``` shell script
vault write sys/plugins/catalog/vault-plugin-database-opendistro \
    sha256=$(shasum -a 256 vault-plugin-database-opendistro | cut -d " " -f 1) \
    command="vault-plugin-database-opendistro"
```