# =============================================================================
# Zeek Signatures — ai-security
# Total rules: 27
# =============================================================================

signature ZK-AIPI001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|direct/
	event "Detect_AI_—_Direct_Prompt_Injection"
}

signature ZK-AIPI002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|indirect/
	event "Detect_AI_—_Indirect_Prompt_Injection_via_Exter"
}

signature ZK-AIPI003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-extraction|system-prompt/
	event "Detect_AI_—_System_Prompt_Extraction_Attempt"
}

signature ZK-AIPI004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /jailbreak|role-play/
	event "Detect_AI_—_Jailbreak_via_Role-Play_Persona"
}

signature ZK-AIPI005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /prompt-injection|few-shot/
	event "Detect_AI_—_Prompt_Injection_via_Few-Shot_Manip"
}

signature ZK-AIDEX001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exfiltration|output-leak/
	event "Detect_AI_—_Data_Exfiltration_via_Model_Output"
}

signature ZK-AIDEX002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-extraction|training-data/
	event "Detect_AI_—_Training_Data_Extraction_Attack"
}

signature ZK-AIDEX003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pii-leakage|llm-output/
	event "Detect_AI_—_PII_Leakage_via_LLM_Response"
}

signature ZK-AIMDL001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /model-poisoning|training-data/
	event "Detect_AI_—_Model_Poisoning_via_Training_Data_M"
}

signature ZK-AIMDL002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /backdoor|model-poisoning/
	event "Detect_AI_—_Backdoor_Trigger_Detection_in_LLM_O"
}

signature ZK-AIRAG001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|data-poisoning/
	event "Detect_AI_—_RAG_Pipeline_Data_Poisoning"
}

signature ZK-AIRAG002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|adversarial-docs/
	event "Detect_AI_—_RAG_Retrieval_Manipulation_via_Adve"
}

signature ZK-AIHAL001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /hallucination|fabrication/
	event "Detect_AI_—_Hallucination_Detection_—_Fabricate"
}

signature ZK-AIHAL002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /hallucination|inconsistency/
	event "Detect_AI_—_Hallucination_—_Inconsistent_Factua"
}

signature ZK-AIBIA001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias|fairness/
	event "Detect_AI_—_Bias_Detection_—_Demographic_Dispar"
}

signature ZK-AIGOV001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|risk-assessment/
	event "Detect_AI_—_Governance_—_Missing_Risk_Assessmen"
}

signature ZK-AIGOV002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|human-oversight/
	event "Detect_AI_—_Governance_—_High-Risk_System_Witho"
}

signature ZK-AIGOV003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|transparency/
	event "Detect_AI_—_Governance_—_Missing_Transparency_R"
}

signature ZK-AIRED001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|adversarial-suffix/
	event "Detect_AI_—_Red_Team_—_Adversarial_Suffix_Attac"
}

signature ZK-AIRED002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|token-smuggling/
	event "Detect_AI_—_Red_Team_—_Token_Smuggling_Attack"
}

signature ZK-AIRED003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|multi-turn-jailbreak/
	event "Detect_AI_—_Red_Team_—_Multi-Turn_Jailbreak"
}

signature ZK-AISAF001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|harmful-content/
	event "Detect_AI_—_Safety_—_Harmful_Content_Generation"
}

signature ZK-AISAF002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|self-harm/
	event "Detect_AI_—_Safety_—_Self-Harm_Content_Facilita"
}

signature ZK-AIVEC001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|pinecone/
	event "Detect_AI_—_Vector_DB_—_Pinecone_Namespace_Isol"
}

signature ZK-AIVEC002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|weaviate/
	event "Detect_AI_—_Vector_DB_—_Weaviate_Tenant_Data_Is"
}

signature ZK-AIVEC003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|chromadb/
	event "Detect_AI_—_Vector_DB_—_ChromaDB_Embedding_Pois"
}

signature ZK-AIVEC004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|qdrant/
	event "Detect_AI_—_Vector_DB_—_Qdrant_Payload_Filter_I"
}
