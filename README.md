# OpenDistro for Elasticsearch Database Secrets Engine
> based on the original [plugin](https://github.com/hashicorp/vault-plugin-database-elasticsearch)

This plugin provides unique, short-lived credentials for Elasticsearch using OpenDistro.

## Getting Started

For this plugin to work, you must first install [OpenDistro](https://opendistro.github.io/for-elasticsearch/).

### Create a User for Vault

```shell script
$ curl \
    -s \
    -X PUT \
    -H "Content-Type: application/json" \
    -d '{
          "password": "vault"
        }' \
    -u admin:admin \  
    http://localhost:9200/_opendistro/_security/api/internalusers/vault
```

```shell script
$ curl \
    -s \
    -X PUT \
    -H "Content-Type: application/json" \
    -d '{
          "users" : [ "vault" ]
        }' \
    -u admin:admin \
    http://localhost:9200/_opendistro/_security/api/rolesmapping/security_rest_api_access
```

## Enable OpenDistro Plugin in Vault

```shell script
$ vault write sys/plugins/catalog/database/opendistro \
    sha_256=9b9bd77c725a5cdb9bf0a75005b153acb73a66beeb5998a85d902e4af043e705 \
    command=vault-plugin-database-opendistro
```

```shell script
$ vault secrets enable database
```

```shell script
$ vault write configs \
    plugin_name="vault-plugin-database-opendistro" \
    allowed_roles="internally-defined-role,externally-defined-role" \
    username=vault \
    password=vault \
    url=https://localhost:9200 \
    ca_cert=$PWD/root-ca.pem \
    client_cert=$PWD/kirk.pem \
    client_key=$PWD/kirk-key.pem \
    insecure=true
```

```shell script
$ vault write database/roles/externally-defined-role \
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
    default_ttl="1h" \ 
    max_ttl="24h"
```

```shell script
$ vault read database/creds/externally-defined-role                                                                                                                                                                                                              
  Key                Value
  ---                -----
  lease_id           database/creds/externally-defined-role/w0MfpmzZ0jkWAyS1rnOvICSg
  lease_duration     1h
  lease_renewable    true
  password           A1a-9TzAGce3tbyePZvZ
  username           v_token_externally-defi_KxTRtdypZt5z4Dpy9AWW_1572991043
```

```shell script
$ curl -s -k -X POST https://localhost:9200/test-index-1/_doc \
      -H "Content-Type: application/json" \
      -u v_token_externally-defi_KxTRtdypZt5z4Dpy9AWW_1572991043:A1a-9TzAGce3tbyePZvZ \ 
      -d '{
            "name":"test"
          }' | jq
```

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