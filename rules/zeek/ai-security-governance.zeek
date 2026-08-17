# =============================================================================
# Zeek Signatures — ai-security-governance
# AI governance violations, bias detection, policy enforcement,
# regulatory compliance, and responsible AI monitoring.
# Total rules: 35
# Reference: EU AI Act, NIST AI RMF, ISO 42001, OWASP LLM Top 10
# =============================================================================

# --- Governance Policy Violations ---

signature ZK-AIGD001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|policy-violation|unauthorized-model-deployment/
	event "Detect_AI_Governance_—_Unauthorized_Model_Deployment"
	# EU AI Act - Unauthorized Deployment
}

signature ZK-AIGD002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|risk-assessment|missing-evaluation/
	event "Detect_AI_Governance_—_Missing_Risk_Assessment_Before_Deployment"
	# EU AI Act - Risk Assessment Missing
}

signature ZK-AIGD003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|human-oversight|high-risk-no-supervision/
	event "Detect_AI_Governance_—_High_Risk_AI_Without_Human_Oversight"
	# EU AI Act - Missing Human Oversight
}

signature ZK-AIGD004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|transparency|missing-disclosure/
	event "Detect_AI_Governance_—_Missing_AI_Transparency_Disclosure_to_Users"
	# EU AI Act - Transparency Violation
}

signature ZK-AIGD005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|consent|data-processing-without-consent/
	event "Detect_AI_Governance_—_AI_Data_Processing_Without_Valid_Consent"
	# GDPR + EU AI Act - Consent Violation
}

signature ZK-AIGD006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|prohibited-ai|social-scoring/
	event "Detect_AI_Governance_—_Prohibited_AI_Use_—_Social_Scoring_System"
	# EU AI Act - Prohibited Practice
}

signature ZK-AIGD007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /governance|prohibited-ai|manipulative-nudging/
	event "Detect_AI_Governance_—_Prohibited_AI_Use_—_Dark_Pattern_Manipulation"
	# EU AI Act - Dark Patterns
}

# --- Bias & Fairness Detection ---

signature ZK-AIGD008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|demographic-disparity|protected-class/
	event "Detect_AI_Bias_—_Demographic_Disparity_in_Model_Decisions"
	# NIST AI RMF - Bias Detection
}

signature ZK-AIGD009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|racial-bias|ethnicity-discrimination/
	event "Detect_AI_Bias_—_Racial_Ethnicity_Bias_in_AI_Output_Patterns"
	# Fairness - Racial Bias
}

signature ZK-AIGD010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|gender-bias|sexist-output/
	event "Detect_AI_Bias_—_Gender_Bias_in_AI_Response_Patterns"
	# Fairness - Gender Bias
}

signature ZK-AIGD011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|age-discrimination|age-based-filtering/
	event "Detect_AI_Bias_—_Age_Discrimination_in_AI_Filtering_Decisions"
	# Fairness - Age Bias
}

signature ZK-AIGD012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|disability-bias|accessibility-discrimination/
	event "Detect_AI_Bias_—_Disability_Accessibility_Discrimination_in_AI"
	# Fairness - Disability Bias
}

signature ZK-AIGD013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|intersectional|compound-discrimination/
	event "Detect_AI_Bias_—_Intersectional_Compound_Discrimination_Detection"
	# Fairness - Intersectional Bias
}

signature ZK-AIGD014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bias-fairness|feedback-loop|self-reinforcing/
	event "Detect_AI_Bias_—_Self-Reinforcing_Feedback_Loop_Detection"
	# Fairness - Feedback Loop
}

# --- Safety & Harmful Content ---

signature ZK-AIGD015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|harmful-content|violence-generation/
	event "Detect_AI_Safety_—_Violent_Content_Generation_Violation"
	# AI Safety - Violence
}

signature ZK-AIGD016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|harmful-content|self-harm-facilitation/
	event "Detect_AI_Safety_—_Self_Harm_Content_Facilitation_Violation"
	# AI Safety - Self-Harm
}

signature ZK-AIGD017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|csam|child-exploitation/
	event "Detect_AI_Safety_—_Child_Safety_Violation_in_AI_Output"
	# AI Safety - CSAM
}

signature ZK-AIGD018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|hate-speech|discriminatory-output/
	event "Detect_AI_Safety_—_Hate_Speech_and_Discriminatory_Output_Violation"
	# AI Safety - Hate Speech
}

signature ZK-AIGD019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|medical-misinformation|harmful-health-advice/
	event "Detect_AI_Safety_—_Medical_Misinformation_via_AI_Output"
	# AI Safety - Medical Misinfo
}

signature ZK-AIGD020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /safety|election-integrity|voter-manipulation/
	event "Detect_AI_Safety_—_Election_Integrity_Violation_via_AI"
	# AI Safety - Election Integrity
}

# --- Data Governance & Privacy ---

signature ZK-AIGD021 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-governance|training-data-consent|unauthorized-use/
	event "Detect_AI_Data_Governance_—_Unauthorized_Training_Data_Use"
	# GDPR + AI Act - Data Consent
}

signature ZK-AIGD022 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-governance|right-to-explanation|black-box-decision/
	event "Detect_AI_Data_Governance_—_Black_Box_Decision_Without_Explanation"
	# GDPR Art. 22 - Right to Explanation
}

signature ZK-AIGD023 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-governance|right-to-erasure|model-unlearning-failure/
	event "Detect_AI_Data_Governance_—_Model_Unlearning_Failure_on_Right_to_Erasure"
	# GDPR - Right to Erasure
}

signature ZK-AIGD024 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-governance|data-minimization|excessive-collection/
	event "Detect_AI_Data_Governance_—_Excessive_Data_Collection_Violation"
	# GDPR - Data Minimization
}

# --- Audit & Compliance ---

signature ZK-AIGD025 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /audit-compliance|model-documentation|missing-registry/
	event "Detect_AI_Audit_—_Missing_Model_Registry_or_Documentation"
	# ISO 42001 - Documentation
}

signature ZK-AIGD026 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /audit-compliance|impact-assessment|missing-fmea/
	event "Detect_AI_Audit_—_Missing_Failure_Mode_Effect_Analysis_for_AI_System"
	# NIST AI RMF - FMEA
}

signature ZK-AIGD027 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /audit-compliance|logging-gap|audit-trail-missing/
	event "Detect_AI_Audit_—_Missing_AI_Decision_Audit_Trail"
	# EU AI Act - Logging Requirement
}

signature ZK-AIGD028 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /audit-compliance|model-versioning|untracked-deployment/
	event "Detect_AI_Audit_—_Untracked_Model_Version_Deployment"
	# ISO 42001 - Version Control
}

signature ZK-AIGD029 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /audit-compliance|stress-testing|missing-red-team/
	event "Detect_AI_Audit_—_Missing_Red_Team_Stress_Test_Before_Deployment"
	# NIST AI RMF - Red Team
}

# --- Responsible AI Operations ---

signature ZK-AIGD030 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /responsible-ai|automated-decision|no-human-review/
	event "Detect_AI_Governance_—_Automated_Decision_Without_Human_Review"
	# EU AI Act - Human Review
}

signature ZK-AIGD031 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /responsible-ai|shadow-ai|unmonitored-model-usage/
	event "Detect_AI_Governance_—_Shadow_AI_Usage_Without_Monitoring"
	# Governance - Shadow AI
}

signature ZK-AIGD032 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /responsible-ai|model-drift-governance|unmonitored-performance/
	event "Detect_AI_Governance_—_Unmonitored_Model_Performance_Drift"
	# Governance - Drift Monitoring
}

signature ZK-AIGD033 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /responsible-ai|incident-response|missing-kill-switch/
	event "Detect_AI_Governance_—_Missing_AI_Kill_Switch_or_Emergency_Stop"
	# Governance - Kill Switch
}

signature ZK-AIGD034 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /responsible-ai|vendor-risk|third-party-model-risk/
	event "Detect_AI_Governance_—_Third_Party_Model_Risk_Without_Assessment"
	# Governance - Third-Party Risk
}

signature ZK-AIGD035 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /responsible-ai|environmental-impact|compute-carbon-excess/
	event "Detect_AI_Governance_—_Excessive_Compute_Carbon_Footprint_Violation"
	# Governance - Environmental Impact
}