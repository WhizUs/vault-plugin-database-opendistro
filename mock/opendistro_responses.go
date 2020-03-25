package mock

const (
	healthcheck = `{"message":null,"mode":"strict","status":"UP"}`

	createRoleResponseTpl = `{
		"status": "CREATED",
		"message": "'%s' created."
	}`

	getRoleResponseTpl = `{
		"%s": {
			"reserved": false,
			"hidden": false,
			"cluster_permissions": [
				"cluster_composite_ops",
				"indices_monitor"
			],
			"index_permissions": [
				{
					"index_patterns": [
						"movies*"
					],
					"dls": "",
					"fls": [],
					"masked_fields": [],
					"allowed_actions": [
						"read"
					]
				}
			],
			"tenant_permissions": [
				{
					"tenant_patterns": [
						"human_resources"
					],
					"allowed_actions": [
						"kibana_all_read"
					]
				}
			],
			"static": false
		}
	}`

	deleteRoleResponseTpl = `{
		"status": "OK",
		"message": "'%s' deleted."
	}`

	createUserResponseTpl = `{
		"status": "CREATED",
		"message": "'%s' created."
	}`

	changePasswordResponse = `{}`

	deleteUserResponseTpl = `{
	  "found" : %s
	}`
)
