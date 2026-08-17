package terraform

# Reproduces SCALRCORE-39575: the OPA container must not reach the instance metadata service.
# "raise_error": false keeps the policy evaluable when the request is rejected - OPA then
# returns "status_code": 0 together with an "error" object instead of aborting evaluation.
leak_response := http.send({
	"method": "GET",
	"url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?alt=json",
	"headers": {"Metadata-Flavor": "Google"},
	"raise_error": false,
	"cache": false,
	"timeout": "5s",
})

# Denies only when the metadata service actually answered, so a blocked container passes.
# The response body is deliberately not echoed: on a regression it carries a live access token
# that would then land in CI logs, policy reports and policy impact analysis.
deny[msg] {
	status := object.get(leak_response, "status_code", 0)
	status != 0
	msg := sprintf("Instance metadata service answered with HTTP %v", [status])
}
