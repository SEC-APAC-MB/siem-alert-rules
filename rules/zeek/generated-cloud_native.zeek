# Zeek SIEM Alert Rules — generated-cloud_native
# Auto-generated: 2026-10-06T04:05:04.338675Z
# Load in local.zeek: @load ./generated-cloud_native

signature ZK-CLOUD_NATIVE-067 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Container Escape via Privileged Pod"
}

signature ZK-CLOUD_NATIVE-068 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Kubernetes RBAC Privilege Escalation"
}

signature ZK-CLOUD_NATIVE-069 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Serverless Function Injection"
}

signature ZK-CLOUD_NATIVE-070 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Cloud Metadata Service SSRF"
}

signature ZK-CLOUD_NATIVE-071 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "IAM Role Assumption Chain"
}

signature ZK-CLOUD_NATIVE-072 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "S3 Bucket Policy Misconfiguration"
}

signature ZK-CLOUD_NATIVE-073 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "ECS Task Definition Tampering"
}

signature ZK-CLOUD_NATIVE-074 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Lambda Environment Variable Exfiltration"
}

signature ZK-CLOUD_NATIVE-075 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Kubernetes Secret Decryption"
}

signature ZK-CLOUD_NATIVE-076 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cloud_native).*/ regex
	event "Service Mesh Policy Bypass"
}

signature ZK-CLOUD_NATIVE-047 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Container Escape via Privileged Pod"
}

signature ZK-CLOUD_NATIVE-048 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Kubernetes RBAC Privilege Escalation"
}

signature ZK-CLOUD_NATIVE-049 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Serverless Function Injection"
}

signature ZK-CLOUD_NATIVE-050 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Cloud Metadata Service SSRF"
}

signature ZK-CLOUD_NATIVE-051 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "IAM Role Assumption Chain"
}

signature ZK-CLOUD_NATIVE-052 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "S3 Bucket Policy Misconfiguration"
}

signature ZK-CLOUD_NATIVE-053 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "ECS Task Definition Tampering"
}

signature ZK-CLOUD_NATIVE-054 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Lambda Environment Variable Exfiltration"
}

signature ZK-CLOUD_NATIVE-055 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Kubernetes Secret Decryption"
}

signature ZK-CLOUD_NATIVE-056 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)).*/ regex
	event "Service Mesh Policy Bypass"
}
