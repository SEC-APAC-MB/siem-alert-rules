# =============================================================================
# Zeek Signatures — ai-security-prompt-data-model
# AI/LLM prompt injection, data exfiltration, model abuse, and output attacks.
# Total rules: 45
# MITRE ATT&CK: N/A (emerging domain, maps to ATLAS & OWASP LLM Top 10)
# =============================================================================

# --- Direct Prompt Injection (LLM01) ---

signature ZK-AIPDM001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|direct|system-role-override/
	event "Detect_AI_—_Direct_Prompt_Injection_via_System_Role_Override"
	# OWASP LLM01 - Direct Prompt Injection: Role Override
}

signature ZK-AIPDM002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|direct|ignore-previous/
	event "Detect_AI_—_Direct_Prompt_Injection_via_Ignore_Previous_Instructions"
	# OWASP LLM01 - Direct Prompt Injection: Instruction Override
}

signature ZK-AIPDM003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|direct|base64-encoded/
	event "Detect_AI_—_Direct_Prompt_Injection_via_Base64_Encoded_Payload"
	# OWASP LLM01 - Obfuscated Prompt Injection
}

signature ZK-AIPDM004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|direct|multi-language-evasion/
	event "Detect_AI_—_Direct_Prompt_Injection_via_Multi-Language_Evasion"
	# OWASP LLM01 - Cross-Lingual Injection
}

signature ZK-AIPDM005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|direct|chain-of-thought-manipulation/
	event "Detect_AI_—_Direct_Prompt_Injection_via_Chain-of-Thought_Manipulation"
	# OWASP LLM01 - CoT Manipulation
}

# --- Indirect Prompt Injection (LLM01) ---

signature ZK-AIPDM006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|indirect|web-content-embed/
	event "Detect_AI_—_Indirect_Prompt_Injection_via_Embedded_Web_Content"
	# OWASP LLM01 - Indirect: Web Embed
}

signature ZK-AIPDM007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|indirect|document-upload/
	event "Detect_AI_—_Indirect_Prompt_Injection_via_Document_Upload_Payload"
	# OWASP LLM01 - Indirect: Document Upload
}

signature ZK-AIPDM008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|indirect|email-body-injection/
	event "Detect_AI_—_Indirect_Prompt_Injection_via_Email_Body_Payload"
	# OWASP LLM01 - Indirect: Email Body
}

signature ZK-AIPDM009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|indirect|metadata-steganography/
	event "Detect_AI_—_Indirect_Prompt_Injection_via_Metadata_Steganography"
	# OWASP LLM01 - Indirect: Metadata Stego
}

signature ZK-AIPDM010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|indirect|tool-output-poisoning/
	event "Detect_AI_—_Indirect_Prompt_Injection_via_Tool_Output_Poisoning"
	# OWASP LLM01 - Indirect: Tool Output Poisoning
}

# --- System Prompt Extraction (LLM01) ---

signature ZK-AIPDM011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-extraction|system-prompt|instruction-leak/
	event "Detect_AI_—_System_Prompt_Extraction_via_Instruction_Leakage"
	# OWASP LLM01 - System Prompt Extraction
}

signature ZK-AIPDM012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-extraction|repeat-after-me|echo-attack/
	event "Detect_AI_—_System_Prompt_Extraction_via_Repeat_After_Me_Attack"
	# OWASP LLM01 - Echo Extraction
}

signature ZK-AIPDM013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-extraction|format-manipulation|markdown-output/
	event "Detect_AI_—_System_Prompt_Extraction_via_Format_Manipulation"
	# OWASP LLM01 - Format Manipulation Extraction
}

# --- Jailbreak Techniques ---

signature ZK-AIPDM014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /jailbreak|dan|do-anything-now/
	event "Detect_AI_—_Jailbreak_via_DAN_Do_Anything_Now_Prompt"
	# OWASP LLM01 - DAN Jailbreak
}

signature ZK-AIPDM015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /jailbreak|developer-mode|hypothetical/
	event "Detect_AI_—_Jailbreak_via_Developer_Mode_or_Hypothetical_Scenario"
	# OWASP LLM01 - Developer Mode Jailbreak
}

signature ZK-AIPDM016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /jailbreak|context-dilation|infinite-context/
	event "Detect_AI_—_Jailbreak_via_Context_Dilation_Attack"
	# OWASP LLM01 - Context Dilation
}

signature ZK-AIPDM017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /jailbreak|token-smuggling|adversarial-suffix/
	event "Detect_AI_—_Jailbreak_via_Adversarial_Suffix_Token_Smuggling"
	# OWASP LLM01 - Adversarial Suffix
}

# --- Data Exfiltration via Model (LLM02) ---

signature ZK-AIPDM018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|model-output|sensitive-info-leak/
	event "Detect_AI_—_Data_Exfiltration_via_Model_Output_Sensitive_Info_Leak"
	# OWASP LLM02 - Data Leakage via Output
}

signature ZK-AIPDM019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|pii-leakage|personal-data-extraction/
	event "Detect_AI_—_PII_Exfiltration_via_LLM_Response_Pattern"
	# OWASP LLM02 - PII Leakage
}

signature ZK-AIPDM020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|training-data-extraction|verbatim-recall/
	event "Detect_AI_—_Training_Data_Extraction_via_Verbatim_Recall"
	# OWASP LLM02 - Training Data Extraction
}

signature ZK-AIPDM021 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|covert-channel|steganography-output/
	event "Detect_AI_—_Data_Exfiltration_via_Covert_Channel_in_LLM_Output"
	# OWASP LLM02 - Covert Channel Exfil
}

signature ZK-AIPDM022 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|url-exfiltration|dns-tunneling/
	event "Detect_AI_—_Data_Exfiltration_via_URL_or_DNS_in_LLM_Response"
	# OWASP LLM02 - URL/DNS Exfiltration
}

signature ZK-AIPDM023 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|markdown-injection|image-exfil/
	event "Detect_AI_—_Data_Exfiltration_via_Markdown_Image_Injection"
	# OWASP LLM02 - Markdown Image Exfil
}

# --- Model Abuse & Misuse ---

signature ZK-AIPDM024 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /model-abuse|malware-generation|code-generation/
	event "Detect_AI_—_Malicious_Code_Generation_via_LLM_Prompt"
	# Model Abuse - Malware Generation
}

signature ZK-AIPDM025 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /model-abuse|phishing-generation|social-engineering/
	event "Detect_AI_—_Phishing_Content_Generation_via_LLM"
	# Model Abuse - Phishing Generation
}

signature ZK-AIPDM026 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /model-abuse|disinformation|bulk-content-generation/
	event "Detect_AI_—_Disinformation_Bulk_Generation_via_LLM"
	# Model Abuse - Disinformation
}

signature ZK-AIPDM027 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /model-abuse|exploit-generation|vulnerability-research/
	event "Detect_AI_—_Exploit_Code_Generation_Request_via_LLM"
	# Model Abuse - Exploit Generation
}

signature ZK-AIPDM028 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /model-abuse|unauthorized-finetuning|api-abuse/
	event "Detect_AI_—_Unauthorized_Model_Fine-Tuning_or_API_Abuse"
	# Model Abuse - Unauthorized Fine-Tuning
}

# --- Prompt Leakage & Intellectual Property ---

signature ZK-AIPDM029 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-leakage|proprietary-prompt|template-extraction/
	event "Detect_AI_—_Proprietary_Prompt_Template_Extraction_Attempt"
	# OWASP LLM01 - Prompt Template Leak
}

signature ZK-AIPDM030 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-leakage|few-shot-extraction|example-harvesting/
	event "Detect_AI_—_Few-Shot_Example_Extraction_via_Probing"
	# OWASP LLM01 - Few-Shot Extraction
}

signature ZK-AIPDM031 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-leakage|tool-description|function-leak/
	event "Detect_AI_—_Tool_Function_Description_Leakage_via_LLM"
	# OWASP LLM01 - Tool Description Leak
}

# --- Output Manipulation & Hallucination ---

signature ZK-AIPDM032 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /output-manipulation|hallucination|fabricated-facts/
	event "Detect_AI_—_Hallucinated_Fact_Fabrication_in_LLM_Output"
	# Hallucination Detection
}

signature ZK-AIPDM033 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /output-manipulation|citation-fabrication|fake-references/
	event "Detect_AI_—_Citation_Fabrication_in_LLM_Output"
	# Hallucination - Citation Fabrication
}

signature ZK-AIPDM034 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /output-manipulation|sycophancy|user-pleasing-fabrication/
	event "Detect_AI_—_Sycophantic_Response_Pattern_—_User_Pleasing_Fabrication"
	# Hallucination - Sycophancy
}

signature ZK-AIPDM035 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /output-manipulation|confabulation|gap-filling/
	event "Detect_AI_—_Confabulation_Pattern_—_Knowledge_Gap_Filling"
	# Hallucination - Confabulation
}

# --- Supply Chain & Plugin Attacks (LLM03) ---

signature ZK-AIPDM036 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /supply-chain|plugin-poisoning|malicious-extension/
	event "Detect_AI_—_Supply_Chain_Attack_via_Malicious_LLM_Plugin"
	# OWASP LLM03 - Supply Chain Plugin
}

signature ZK-AIPDM037 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /supply-chain|model-poisoning|pretrained-weights/
	event "Detect_AI_—_Supply_Chain_Attack_via_Poisoned_Pretrained_Model"
	# OWASP LLM03 - Model Poisoning
}

signature ZK-AIPDM038 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /supply-chain|dependency-confusion|package-hallucination/
	event "Detect_AI_—_Supply_Chain_Attack_via_Package_Hallucination_in_LLM_Output"
	# OWASP LLM03 - Dependency Confusion
}

# --- Excessive Agency & Permissions (LLM06) ---

signature ZK-AIPDM039 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /excessive-agency|unauthorized-action|tool-execution/
	event "Detect_AI_—_Excessive_Agency_—_Unauthorized_Tool_Execution_via_LLM"
	# OWASP LLM06 - Excessive Agency
}

signature ZK-AIPDM040 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /excessive-agency|file-system-access|data-deletion/
	event "Detect_AI_—_Excessive_Agency_—_Unauthorized_File_System_Modification"
	# OWASP LLM06 - File System Overreach
}

signature ZK-AIPDM041 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /excessive-agency|api-call-abuse|privilege-escalation/
	event "Detect_AI_—_Excessive_Agency_—_API_Privilege_Escalation_via_LLM"
	# OWASP LLM06 - API Privilege Escalation
}

# --- LLM-Specific Network Attacks ---

signature ZK-AIPDM042 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /llm-api|rate-abuse|token-exhaustion/
	event "Detect_AI_—_LLM_API_Rate_Abuse_and_Token_Exhaustion_Attack"
	# OWASP LLM10 - Unbounded Consumption
}

signature ZK-AIPDM043 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /llm-api|context-window|overflow-attack/
	event "Detect_AI_—_LLM_Context_Window_Overflow_Attack"
	# Context Window Overflow
}

signature ZK-AIPDM044 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /llm-api|model-denial-of-service|resource-exhaustion/
	event "Detect_AI_—_LLM_Model_Denial_of_Service_via_Resource_Exhaustion"
	# OWASP LLM10 - Model DoS
}

signature ZK-AIPDM045 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /llm-api|embedding-inversion|model-inversion/
	event "Detect_AI_—_LLM_Embedding_Inversion_and_Model_Inversion_Attack"
	# Model Inversion Attack
}