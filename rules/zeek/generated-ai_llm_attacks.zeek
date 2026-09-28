# Zeek SIEM Alert Rules — generated-ai_llm_attacks
# Auto-generated: 2026-09-25T04:05:13.163236Z
# Load in local.zeek: @load ./generated-ai_llm_attacks

signature ZK-AI_LLM_ATTACKS-041 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Direct Prompt Injection"
}

signature ZK-AI_LLM_ATTACKS-042 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Indirect Prompt Injection"
}

signature ZK-AI_LLM_ATTACKS-043 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "System Prompt Extraction"
}

signature ZK-AI_LLM_ATTACKS-044 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Jailbreak Attempt"
}

signature ZK-AI_LLM_ATTACKS-045 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Token Smuggling"
}

signature ZK-AI_LLM_ATTACKS-046 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Training Data Extraction"
}

signature ZK-AI_LLM_ATTACKS-047 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Model Inversion Attack"
}

signature ZK-AI_LLM_ATTACKS-048 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "PII Disclosure via LLM"
}

signature ZK-AI_LLM_ATTACKS-049 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Credential Leakage in AI Response"
}

signature ZK-AI_LLM_ATTACKS-050 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Temperature Manipulation"
}

signature ZK-AI_LLM_ATTACKS-051 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Max Tokens Abuse"
}

signature ZK-AI_LLM_ATTACKS-052 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Parameter Manipulation"
}

signature ZK-AI_LLM_ATTACKS-053 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "AI Supply Chain Attack"
}

signature ZK-AI_LLM_ATTACKS-054 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "Model Poisoning Detection"
}

signature ZK-AI_LLM_ATTACKS-055 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "AI Governance Policy Violation"
}

signature ZK-AI_LLM_ATTACKS-056 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ai_llm_attacks).*/ regex
	event "AI Bias Detection"
}
