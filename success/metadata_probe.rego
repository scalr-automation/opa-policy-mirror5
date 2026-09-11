package terraform

# Same request as metadata_leak.rego, but this policy always denies and reports the outcome.
# It guards against a false-negative "passed" on metadata_leak, where http.send never ran at
# all: the message has to show that the request was attempted and got no HTTP response back.
probe_response := http.send({
	"method": "GET",
	"url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?alt=json",
	"headers": {"Metadata-Flavor": "Google"},
	"raise_error": false,
	"cache": false,
	"timeout": "5s",
})

# "raise_error": false makes http.send return status_code 0 plus an "error" object when the
# request is rejected, so exactly one of the two bodies below holds.
deny[msg] {
	object.get(probe_response, "status_code", 0) == 0
	msg := sprintf("metadata probe: reachable=false error=%v", [object.get(object.get(probe_response, "error", {}), "message", "none")])
}

deny[msg] {
	status := object.get(probe_response, "status_code", 0)
	status != 0
	msg := sprintf("metadata probe: reachable=true status_code=%v", [status])
}

# Trigger the policy impact analysis.
