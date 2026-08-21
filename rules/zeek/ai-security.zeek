# =============================================================================
# Zeek Signatures — AI/LLM Security
# Total rules: 42
# MITRE ATT&CK: T1190, T1548, T1567, T1040, T1552
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# Prompt Injection
# =============================================================================

signature ZK-AISEC-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(ignore\s+(previous|above|earlier)\s+(instructions|rules|guidelines)|disregard\s+(all|previous|above)\s+(instructions|safety|guidelines)|forget\s+(your|all|previous)\s+(instructions|rules|guidelines)|you\s+are\s+now\s+(a\s+)?(malicious|harmful|unethical|unfiltered|uncensored|DAN)).*/ regex
	event "AI-SEC-001: Prompt injection - instruction override attempt"
}

signature ZK-AISEC-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(system\s*:\s*you\s+are|<\|system\|>|<\|im_start\|>system|###\s*System|ROLE\s*:\s*(Hacker|Malicious|Unethical)|pretend\s+you\s+(are|can)|act\s+as\s+(if\s+you\s+(are|were|can|could))?a?\s*(malicious|harmful|unethical|criminal)).*/ regex
	event "AI-SEC-002: Prompt injection - role manipulation attempt"
}

signature ZK-AISEC-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(repeat\s+the\s+(above|following|previous)\s+(instructions|prompt|text|message)|output\s+(your|the|all)\s+(instructions|system\s+(message|prompt)|initial\s+(instructions|prompt))|show\s+me\s+(your|the|all)\s+(instructions|system\s+prompt|rules|guidelines)).*/ regex
	event "AI-SEC-003: Prompt injection - system prompt extraction attempt"
}

signature ZK-AISEC-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(translate\s+the\s+following\s+to\s+(pirate|leetspeak|base64|rot13|hex|binary|obfuscated)|respond\s+in\s+(pirate|leetspeak|base64|rot13|hex|binary|obfuscated)\s+language|encode\s+(your|the)\s+(response|answer|output)\s+(in|using|with)\s+(base64|rot13|hex|binary|reverse)).*/ regex
	event "AI-SEC-004: Prompt injection - encoding bypass attempt"
}

signature ZK-AISEC-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(jailbreak|DAN\s+mode|developer\s+mode|admin\s+mode|god\s+mode|unlocked\s+mode|evil\s+mode|shadow\s+mode|bypass\s+(mode|filter|safety|restrictions|guardrails)|hack\s+(mode|the|this|into)).*/ regex
	event "AI-SEC-005: Prompt injection - jailbreak mode activation attempt"
}

# =============================================================================
# Data Exfiltration via LLM
# =============================================================================

signature ZK-AISEC-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(list\s+all\s+(users|customers|patients|employees|records|accounts|emails|phone\s+numbers|ssn|credit\s+card)|dump\s+(the\s+)?(database|table|users|customers|patients)|extract\s+(all\s+)?(user|customer|patient|employee)\s+(data|information|records|details)|show\s+me\s+(the\s+)?(full\s+)?(user|customer|patient|employee)\s+(list|database|table|records)).*/ regex
	event "AI-SEC-006: LLM data exfiltration - bulk PII extraction attempt"
}

signature ZK-AISEC-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(what\s+is\s+(the\s+)?(password|secret|api\s+key|token|private\s+key|encryption\s+key|database\s+password|admin\s+password|root\s+password)|reveal\s+(the\s+)?(password|secret|api\s+key|token|private\s+key|credentials)|give\s+me\s+(the\s+)?(password|secret|api\s+key|token|private\s+key|credentials|connection\s+string)).*/ regex
	event "AI-SEC-007: LLM data exfiltration - credential/secret extraction attempt"
}

signature ZK-AISEC-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(write\s+(a\s+)?(sql|python|javascript|bash|powershell|ruby|php)\s+(query|script|code|command|program)\s+(that|to|which)\s+(drops|deletes|modifies|destroys|corrupts|steals|exfiltrates|encrypts)|create\s+(a\s+)?(malware|virus|trojan|ransomware|keylogger|backdoor|exploit|payload|botnet)).*/ regex
	event "AI-SEC-008: LLM harmful code generation request"
}

# =============================================================================
# AI Model Manipulation
# =============================================================================

signature ZK-AISEC-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(temperature|max_tokens|top_p|top_k|frequency_penalty|presence_penalty)"\s*:\s*(2\.[0-9]+|[3-9][0-9]*|null|-1).*/ regex
	event "AI-SEC-009: LLM parameter manipulation - abnormal temperature/token settings"
}

signature ZK-AISEC-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(model|engine|model_id)"\s*:\s*"(gpt-4-32k|gpt-4-turbo|claude-3-opus|text-davinci-003|claude-instant|meta-llama.*70b|mixtral.*8x7b|command-r-plus)".*/ regex
	event "AI-SEC-010: LLM model substitution - unauthorized model selection"
}

signature ZK-AISEC-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(max_tokens|num_return_sequences|best_of|n)"\s*:\s*[0-9]{5,}.*/ regex
	event "AI-SEC-011: LLM resource exhaustion - excessive token generation request"
}

# =============================================================================
# AI Training Data Extraction
# =============================================================================

signature ZK-AISEC-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(repeat\s+word|repeat\s+the\s+word|say\s+the\s+word|keep\s+repeating|print\s+the\s+word|echo\s+the\s+word)\s+(the|a|and|is|of|to|in|it|for|with|on|at|by)\s+(forever|infinity|unlimited|without\s+stopping|endlessly|continuously|1000\s+times|5000\s+times|10000\s+times).*/ regex
	event "AI-SEC-012: LLM training data extraction - repeat word attack"
}

signature ZK-AISEC-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(complete\s+the\s+following\s+(text|passage|paragraph|sentence|poem|story|article)|continue\s+writing\s+from\s+(where|this|the\s+beginning)|fill\s+in\s+the\s+(rest|remaining|blank)|what\s+comes\s+(after|next)).*/ regex
	event "AI-SEC-013: LLM training data extraction - text continuation attack"
}

# =============================================================================
# AI API Abuse
# =============================================================================

signature ZK-AISEC-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	http-header /Authorization: Bearer .*/ regex
	http-header /!(X-Rate-Limit|X-Request-Id)/ regex
	event "AI-SEC-014: LLM API request without rate limiting headers"
}

signature ZK-AISEC-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|Go-http|node-fetch|axios|aiohttp)/ regex
	event "AI-SEC-015: LLM API automated access from script user-agent"
}

signature ZK-AISEC-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	http-header /Authorization: Bearer sk-[a-zA-Z0-9]{20,}/ regex
	http-header /!(Origin|Referer)/ regex
	event "AI-SEC-016: LLM API key used without origin/referer - potential key leakage"
}

# =============================================================================
# AI Output Manipulation
# =============================================================================

signature ZK-AISEC-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(response_format|output_format|format)"\s*:\s*"(json|xml|html|markdown)".*/ regex
	payload /.*"(stop|stop_sequences)"\s*:\s*\[\].*/ regex
	event "AI-SEC-017: LLM output manipulation - empty stop sequences"
}

signature ZK-AISEC-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(system|system_message|system_prompt)"\s*:\s*"(You\s+are\s+now|From\s+now\s+on|New\s+instruction|Override\s+previous|Priority\s+instruction|IMPORTANT\s*:\s*|CRITICAL\s*:\s*|URGENT\s*:\s*).*/ regex
	event "AI-SEC-018: LLM system prompt override attempt via API parameter"
}

# =============================================================================
# AI Model Poisoning Indicators
# =============================================================================

signature ZK-AISEC-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	payload /.*(I\s+(cannot|can't|won't|will\s+not|must\s+not|should\s+not)\s+(provide|generate|create|write|share|give|reveal|show|discuss|explain|describe|help\s+with|assist\s+with)).*(hack|exploit|vulnerability|malware|phishing|social\s+engineering|attack|bomb|weapon|drug|poison|kill|suicide|self-harm|illegal|fraud).*/ regex
	event "AI-SEC-019: LLM safety filter activation - harmful content blocked"
}

signature ZK-AISEC-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	payload /.*(As\s+an\s+AI|I'm\s+sorry|I\s+cannot|I\s+can't|As\s+a\s+language\s+model|As\s+an\s+AI\s+language\s+model|I\s+do\s+not\s+have|I'm\s+not\s+able).*/ regex
	event "AI-SEC-020: LLM standard refusal response detected"
}

# =============================================================================
# AI-Specific DoS
# =============================================================================

signature ZK-AISEC-021 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.{50000,}/ regex
	event "AI-SEC-021: LLM request with abnormally large payload - DoS risk"
}

signature ZK-AISEC-022 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"messages"\s*:\s*\[.{1,}(\{.*\}){20,}.*/ regex
	event "AI-SEC-022: LLM context window flooding - excessive message history"
}

signature ZK-AISEC-023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(max_tokens|num_return_sequences|best_of|n)"\s*:\s*(4000|[5-9][0-9]{3}|[1-9][0-9]{4,}).*/ regex
	event "AI-SEC-023: LLM resource exhaustion - excessive output token request"
}

# =============================================================================
# AI Embedding/Vector Abuse
# =============================================================================

signature ZK-AISEC-024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(embeddings|vectors|search|similarity|query))/ regex
	payload /.*(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|CREATE\s+TABLE).*/ regex
	event "AI-SEC-024: SQL injection in vector/embedding API request"
}

signature ZK-AISEC-025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(embeddings|vectors|documents|knowledge|ingest|upload))/ regex
	payload /.*"(content|text|document|chunk)"\s*:\s*"((<script|javascript:|onerror|onload|<iframe|<svg|<img).*)".*/ regex
	event "AI-SEC-025: XSS payload in document embedding upload"
}

# =============================================================================
# AI Supply Chain Attacks
# =============================================================================

signature ZK-AISEC-026 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(download\s+and\s+execute|fetch\s+and\s+run|curl\s+.*\|\s*(bash|sh|python|perl|ruby)|wget\s+.*\|\s*(bash|sh|python|perl|ruby)|pip\s+install\s+.*\|\s*(bash|sh)|npm\s+install\s+.*\|\s*(bash|sh)|import\s+os\s*;\s*os\.system|subprocess\.(call|run|Popen)|eval\s*\(|exec\s*\(|__import__|require\s*\().*/ regex
	event "AI-SEC-026: LLM supply chain - code execution in generated response"
}

signature ZK-AISEC-027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(visit\s+(this\s+)?(link|url|website|page)|click\s+(here|on\s+this|the\s+link)|go\s+to\s+(http|https):|open\s+(this\s+)?(link|url|file|attachment)|download\s+(from|this|the\s+file)).*/ regex
	event "AI-SEC-027: LLM phishing - social engineering link generation"
}

# =============================================================================
# AI Hallucination/Confidence Indicators
# =============================================================================

signature ZK-AISEC-028 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	payload /.*(I'm\s+not\s+sure|I\s+think|I\s+believe|probably|likely|possibly|it\s+seems|it\s+appears|as\s+far\s+as\s+I\s+know|to\s+the\s+best\s+of\s+my\s+knowledge).*(password|secret|api_key|token|private_key|credit_card|ssn|social_security|bank_account).*/ regex
	event "AI-SEC-028: LLM hallucinated credential/PII disclosure"
}

signature ZK-AISEC-029 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /X-AI-Confidence: (0\.[0-4]|low|very_low|uncertain)/ regex
	event "AI-SEC-029: LLM low confidence response - potential hallucination"
}

# =============================================================================
# AI Multi-Modal Abuse
# =============================================================================

signature ZK-AISEC-030 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|vision|image|transcribe))/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*filename=".*\.(exe|bat|cmd|sh|py|rb|pl|cgi|dll|so|msi|jar|war|php|jsp|asp|aspx).*/ regex
	event "AI-SEC-030: Malicious file uploaded to AI multi-modal endpoint"
}

signature ZK-AISEC-031 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|vision|image|transcribe))/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*(image\/svg\+xml|text\/html|application\/x-shockwave-flash|text\/x-python|application\/javascript).*/ regex
	event "AI-SEC-031: SVG/HTML/JS content uploaded to AI vision endpoint - XSS risk"
}

# =============================================================================
# AI RAG Poisoning
# =============================================================================

signature ZK-AISEC-032 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(documents|knowledge|ingest|embed|train|fine-tune|update))/ regex
	payload /.*(ignore\s+(all\s+)?(previous|above)\s+(instructions|rules|guidelines|documents)|disregard\s+(all|previous|above)\s+(instructions|rules|guidelines)|this\s+document\s+(is|contains|should\s+be)\s+(ignored|deleted|removed|overridden)).*/ regex
	event "AI-SEC-032: RAG poisoning - document ingestion with instruction override"
}

signature ZK-AISEC-033 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(documents|knowledge|ingest|embed|train|fine-tune|update))/ regex
	payload /.*(DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|UPDATE\s+\w+\s+SET|INSERT\s+INTO|ALTER\s+TABLE|CREATE\s+TABLE).*/ regex
	event "AI-SEC-033: RAG poisoning - SQL injection in document ingestion"
}

# =============================================================================
# AI Agent/Tool Abuse
# =============================================================================

signature ZK-AISEC-034 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|agent))/ regex
	payload /.*"(tool|function|action)"\s*:\s*"(execute|run|eval|system|shell|bash|os|subprocess|popen|exec|command)".*/ regex
	event "AI-SEC-034: AI agent tool abuse - system command execution request"
}

signature ZK-AISEC-035 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|agent))/ regex
	payload /.*"(tool|function|action)"\s*:\s*"(file_read|file_write|file_delete|database_query|api_call|http_request|web_scraper|email_send|sms_send)".*/ regex
	event "AI-SEC-035: AI agent unauthorized tool invocation"
}

# =============================================================================
# AI Bias/Toxicity Detection
# =============================================================================

signature ZK-AISEC-036 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(why\s+(are|is|do)\s+(black|white|asian|hispanic|jewish|muslim|christian|women|men|girls|boys|gay|straight|trans|disabled|old|young)\s+(people|persons|folks|individuals)\s+(so\s+)?(lazy|stupid|violent|criminal|inferior|superior|bad|dangerous|evil|greedy|dishonest)|generate\s+(hate|racist|sexist|homophobic|transphobic|ableist|ageist)\s+(speech|content|text|story|article|essay|comment)).*/ regex
	event "AI-SEC-036: LLM bias/toxicity - hate speech generation request"
}

signature ZK-AISEC-037 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*(write\s+(a\s+)?(phishing|scam|fraud)\s+(email|message|letter|text|page)|create\s+(a\s+)?(phishing|scam|fraud|social\s+engineering)\s+(email|message|campaign|page)|generate\s+(a\s+)?(fake|fraudulent|deceptive)\s+(invoice|receipt|document|certificate|ID|license|passport)).*/ regex
	event "AI-SEC-037: LLM social engineering content generation"
}

# =============================================================================
# AI Monitoring/Logging
# =============================================================================

signature ZK-AISEC-038 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	http-header /!(X-Request-Id|X-Correlation-Id)/ regex
	event "AI-SEC-038: LLM API request without tracing/correlation ID"
}

signature ZK-AISEC-039 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(user_id|user|session_id|conversation_id)"\s*:\s*"(undefined|null|anonymous|test|admin|root|system)".*/ regex
	event "AI-SEC-039: LLM request with anonymous/undefined user identity"
}

signature ZK-AISEC-040 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*"(token_usage|total_tokens|completion_tokens|prompt_tokens)"\s*:\s*[0-9]{5,}.*/ regex
	event "AI-SEC-040: LLM response with excessive token usage - resource exhaustion indicator"
}

signature ZK-AISEC-041 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(chat|completion|generate|prompt|message|inference|ask))/ regex
	payload /.*"(temperature)"\s*:\s*(0|0\.0).*/ regex
	payload /.*"(messages)"\s*:\s*\[.*\{"role"\s*:\s*"system".*\}.*\].*/ regex
	event "AI-SEC-041: LLM zero temperature with system message - deterministic extraction attempt"
}

signature ZK-AISEC-042 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(embeddings|vectors|search|similarity))/ regex
	http-header /Authorization: Bearer .*/ regex
	payload /.*"input"\s*:\s*"\[.*\]".*/ regex
	event "AI-SEC-042: Embedding API with array injection - model probing attempt"
}