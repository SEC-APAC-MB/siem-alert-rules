# =============================================================================
# Zeek Signatures — ai-security-database-rag-redteam
# AI database attacks, RAG pipeline poisoning, vector DB abuse,
# and red team detection patterns for AI/ML infrastructure.
# Total rules: 45
# MITRE ATT&CK: N/A (ATLAS framework + OWASP LLM Top 10)
# =============================================================================

# --- RAG Pipeline Attacks ---

signature ZK-AIDBR001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|document-injection|malicious-content/
	event "Detect_AI_—_RAG_Document_Injection_via_Malicious_Content_Embedding"
	# OWASP LLM01 via RAG
}

signature ZK-AIDBR002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|retrieval-poisoning|ranking-manipulation/
	event "Detect_AI_—_RAG_Retrieval_Poisoning_via_Ranking_Manipulation"
	# RAG Retrieval Poisoning
}

signature ZK-AIDBR003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|knowledge-base-contamination|backdoor-docs/
	event "Detect_AI_—_RAG_Knowledge_Base_Contamination_via_Backdoor_Documents"
	# RAG KB Contamination
}

signature ZK-AIDBR004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|chunk-boundary|split-attack/
	event "Detect_AI_—_RAG_Chunk_Boundary_Split_Attack"
	# RAG Chunk Boundary Attack
}

signature ZK-AIDBR005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|semantic-injection|embedding-space-manipulation/
	event "Detect_AI_—_RAG_Semantic_Injection_via_Embedding_Space_Manipulation"
	# RAG Semantic Injection
}

signature ZK-AIDBR006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|cross-context|multi-hop-injection/
	event "Detect_AI_—_RAG_Cross-Context_Multi-Hop_Injection"
	# RAG Cross-Context Attack
}

signature ZK-AIDBR007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|retrieval-manipulation|adversarial-queries/
	event "Detect_AI_—_RAG_Adversarial_Query_Retrieval_Manipulation"
	# RAG Adversarial Queries
}

signature ZK-AIDBR008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rag|source-attribution|fabricated-citations/
	event "Detect_AI_—_RAG_Source_Attribution_Fabrication"
	# RAG Citation Fabrication
}

# --- Vector Database Attacks ---

signature ZK-AIDBR009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|embedding-poisoning|centroid-shift/
	event "Detect_AI_—_Vector_DB_Embedding_Poisoning_via_Centroid_Shift_Attack"
	# Vector DB Poisoning
}

signature ZK-AIDBR010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|neighborhood-attack|approximate-nearest-neighbor/
	event "Detect_AI_—_Vector_DB_Neighborhood_Attack_on_ANN_Index"
	# Vector DB ANN Attack
}

signature ZK-AIDBR011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|dimension-attack|high-dimensional-evasion/
	event "Detect_AI_—_Vector_DB_High-Dimensional_Evasion_Attack"
	# Vector DB Dimension Attack
}

signature ZK-AIDBR012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|metadata-injection|filter-bypass/
	event "Detect_AI_—_Vector_DB_Metadata_Injection_and_Filter_Bypass"
	# Vector DB Metadata Injection
}

signature ZK-AIDBR013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|tenant-isolation|cross-tenant-query/
	event "Detect_AI_—_Vector_DB_Cross-Tenant_Query_Isolation_Bypass"
	# Vector DB Tenant Isolation
}

signature ZK-AIDBR014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /vector-db|index-poisoning|hnsw-manipulation/
	event "Detect_AI_—_Vector_DB_Index_Poisoning_via_HNSW_Manipulation"
	# Vector DB Index Poisoning
}

# --- AI Database Security ---

signature ZK-AIDBR015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-database|feature-store-poisoning|data-integrity/
	event "Detect_AI_—_Feature_Store_Data_Poisoning_Attack"
	# AI Feature Store Attack
}

signature ZK-AIDBR016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-database|model-registry-tampering|artifact-manipulation/
	event "Detect_AI_—_Model_Registry_Artifact_Tampering"
	# AI Model Registry Attack
}

signature ZK-AIDBR017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-database|training-pipeline-injection|data-manipulation/
	event "Detect_AI_—_Training_Data_Pipeline_Injection_Attack"
	# AI Pipeline Injection
}

signature ZK-AIDBR018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-database|metadata-store-tampering|lineage-attack/
	event "Detect_AI_—_Metadata_Store_Lineage_Tampering"
	# AI Lineage Attack
}

signature ZK-AIDBR019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-database|experiment-tracking|metric-manipulation/
	event "Detect_AI_—_Experiment_Tracking_Metric_Manipulation"
	# AI Metric Manipulation
}

# --- Red Team Detection: Adversarial Attacks ---

signature ZK-AIDBR020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|adversarial-perturbation|input-noise/
	event "Detect_AI_—_Red_Team_—_Adversarial_Input_Perturbation_Attack"
	# ATLAS Adversarial Perturbation
}

signature ZK-AIDBR021 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|gradient-attack|white-box-extraction/
	event "Detect_AI_—_Red_Team_—_Gradient-Based_White_Box_Attack"
	# ATLAS Gradient Attack
}

signature ZK-AIDBR022 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|model-stealing|extraction-queries/
	event "Detect_AI_—_Red_Team_—_Model_Extraction_via_Systematic_Queries"
	# ATLAS Model Extraction
}

signature ZK-AIDBR023 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|membership-inference|privacy-breach/
	event "Detect_AI_—_Red_Team_—_Membership_Inference_Attack_on_Training_Data"
	# ATLAS Membership Inference
}

signature ZK-AIDBR024 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|backdoor-trigger|trojan-detection/
	event "Detect_AI_—_Red_Team_—_Backdoor_Trojan_Trigger_in_Model_Output"
	# ATLAS Backdoor Trigger
}

signature ZK-AIDBR025 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|evasion-attack|input-preprocessing/
	event "Detect_AI_—_Red_Team_—_Evasion_Attack_via_Input_Preprocessing"
	# ATLAS Evasion Attack
}

signature ZK-AIDBR026 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|multi-modal-injection|image-audio-payload/
	event "Detect_AI_—_Red_Team_—_Multi-Modal_Adversarial_Injection"
	# ATLAS Multi-Modal Attack
}

# --- Red Team Detection: LLM-Specific ---

signature ZK-AIDBR027 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|jailbreak-chain|multi-turn-escalation/
	event "Detect_AI_—_Red_Team_—_Multi-Turn_Jailbreak_Escalation_Chain"
	# LLM Multi-Turn Jailbreak
}

signature ZK-AIDBR028 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|context-caching-abuse|cache-poisoning/
	event "Detect_AI_—_Red_Team_—_LLM_Context_Cache_Poisoning"
	# LLM Cache Poisoning
}

signature ZK-AIDBR029 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|tool-call-manipulation|function-injection/
	event "Detect_AI_—_Red_Team_—_LLM_Tool_Call_Manipulation_via_Function_Injection"
	# LLM Tool Call Manipulation
}

signature ZK-AIDBR030 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /red-team|response-filtering-bypass|output-encoding/
	event "Detect_AI_—_Red_Team_—_LLM_Output_Filter_Bypass_via_Encoding"
	# LLM Output Filter Bypass
}

# --- AI Infrastructure Attacks ---

signature ZK-AIDBR031 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-infra|gpu-resource-exhaustion|compute-abuse/
	event "Detect_AI_—_GPU_Resource_Exhaustion_Attack_on_ML_Infrastructure"
	# ML Infrastructure - GPU Abuse
}

signature ZK-AIDBR032 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-infra|model-serving-api|unauthorized-query/
	event "Detect_AI_—_Unauthorized_Model_Serving_API_Query_Pattern"
	# ML Infrastructure - Unauthorized API Access
}

signature ZK-AIDBR033 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-infra|model-artifact-theft|exfiltration/
	event "Detect_AI_—_Model_Artifact_Theft_and_Exfiltration_Attempt"
	# ML Infrastructure - Model Theft
}

signature ZK-AIDBR034 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-infra|checkpoint-tampering|integrity-violation/
	event "Detect_AI_—_Training_Checkpoint_Integrity_Violation"
	# ML Infrastructure - Checkpoint Tampering
}

signature ZK-AIDBR035 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-infra|data-pipeline-contamination|etl-injection/
	event "Detect_AI_—_Data_Pipeline_ETL_Contamination_Attack"
	# ML Infrastructure - ETL Injection
}

# --- AI Monitoring & Anomaly Detection ---

signature ZK-AIDBR036 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-monitoring|model-drift|distribution-shift/
	event "Detect_AI_—_Model_Drift_Detection_via_Distribution_Shift_Anomaly"
	# AI Monitoring - Drift
}

signature ZK-AIDBR037 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-monitoring|output-anomaly|confidence-drop/
	event "Detect_AI_—_LLM_Output_Anomaly_via_Confidence_Score_Drop"
	# AI Monitoring - Confidence Drop
}

signature ZK-AIDBR038 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-monitoring|query-anomaly|fingerprinting-probe/
	event "Detect_AI_—_Model_Fingerprinting_Probe_via_Anomalous_Query_Patterns"
	# AI Monitoring - Fingerprinting
}

signature ZK-AIDBR039 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-monitoring|latency-anomaly|side-channel-timing/
	event "Detect_AI_—_Model_Timing_Side_Channel_Attack_via_Latency_Anomaly"
	# AI Monitoring - Timing Side Channel
}

signature ZK-AIDBR040 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-monitoring|token-usage-anomaly|extraction-pattern/
	event "Detect_AI_—_Token_Usage_Anomaly_Indicating_Extraction_Attack"
	# AI Monitoring - Token Extraction
}

# --- AI-Specific Supply Chain ---

signature ZK-AIDBR041 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-supply-chain|huggingface-model|malicious-weights/
	event "Detect_AI_—_Supply_Chain_—_Malicious_Weights_in_Hugging_Face_Model"
	# AI Supply Chain - HF Model
}

signature ZK-AIDBR042 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-supply-chain|pickle-deserialization|arbitrary-code-execution/
	event "Detect_AI_—_Supply_Chain_—_Pickle_Deserialization_RCE_via_Model_Artifact"
	# AI Supply Chain - Pickle RCE
}

signature ZK-AIDBR043 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-supply-chain|torchscript-backdoor|malicious-model-file/
	event "Detect_AI_—_Supply_Chain_—_TorchScript_Backdoor_via_Malicious_Model_File"
	# AI Supply Chain - TorchScript Backdoor
}

signature ZK-AIDBR044 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-supply-chain|dependency-confusion|pytorch-hub/
	event "Detect_AI_—_Supply_Chain_—_Dependency_Confusion_via_PyTorch_Hub"
	# AI Supply Chain - PyTorch Hub
}

signature ZK-AIDBR045 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ai-supply-chain|onnx-model-tampering|runtime-manipulation/
	event "Detect_AI_—_Supply_Chain_—_ONNX_Model_Tampering_and_Runtime_Manipulation"
	# AI Supply Chain - ONNX Tampering
}