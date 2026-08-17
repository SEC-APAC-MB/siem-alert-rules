# Deployment Guide

This guide covers deploying SIEM alert rules to all 11 supported platforms, including prerequisites, deployment methods, validation, testing, troubleshooting, and performance considerations.

---

## Prerequisites

### Common Prerequisites

- **Bash 4.0+** for validation and deployment scripts
- **jq 1.6+** for JSON processing (used by `validate.sh` and `deploy.sh`)
- **curl** with TLS 1.2+ for API-based deployments
- **git** for repository management
- Appropriate network access to target SIEM platforms
- API credentials or SSH access as described per platform below

### Platform-Specific Prerequisites

#### Elastic Security

| Requirement | Details |
|------------|---------|
| Elastic version | 8.x+ |
| Kibana endpoint | `https://<kibana-host>:5601` |
| API key | Elastic API key with `security_rule` privileges |
| Environment vars | `ELASTIC_HOST`, `ELASTIC_API_KEY` |
| Python | 3.8+ (for deployment helpers) |
| curl | With `-u` authentication support |

#### Splunk Enterprise

| Requirement | Details |
|------------|---------|
| Splunk version | 8.x+ or 9.x |
| REST API endpoint | `https://<splunk-host>:8089` |
| Auth token | Splunk authentication token |
| Environment vars | `SPLUNK_HOST`, `SPLUNK_TOKEN` |
| Search head | Cluster deployer for distributed environments |
| Permissions | `admin` or `power_user` with search capabilities |

#### FortiSIEM

| Requirement | Details |
|------------|---------|
| FortiSIEM version | 6.x+ |
| Web UI access | `https://<fortisiem-host>` |
| CMDB API | Available and authenticated |
| Environment vars | `FORTISIEM_HOST` |
| Super admin | Required for rule import via CMDB API |

#### IBM QRadar

| Requirement | Details |
|------------|---------|
| QRadar version | 7.5+ |
| REST API endpoint | `https://<qradar-host>:443/api` |
| API token | QRadar authorized service token |
| Environment vars | `QRADAR_HOST`, `QRADAR_TOKEN` |
| Permissions | Admin role for custom rule management |

#### Microsoft Sentinel

| Requirement | Details |
|------------|---------|
| Azure subscription | Active subscription with Sentinel enabled |
| Log Analytics workspace | Workspace ID configured |
| Environment vars | `SENTINEL_WORKSPACE`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Azure CLI | `az` CLI 2.40+ with `sentinel` extension |
| Permissions | `Microsoft.SecurityInsights/analticRules/read/write` |

#### Wazuh

| Requirement | Details |
|------------|---------|
| Wazuh version | 4.x+ |
| Manager access | SSH or direct filesystem access to Wazuh manager |
| Rules directory | `/var/ossec/etc/rules/` (default) |
| Environment vars | `WAZUH_MANAGER` (hostname or IP) |
| Permissions | Root or `wazuh` user for file operations |

#### Zeek (Bro)

| Requirement | Details |
|------------|---------|
| Zeek version | 5.x+ or 6.x |
| Site directory | `/opt/zeek/share/zeek/site/` |
| Configuration | `local.zeek` must load custom scripts |
| Environment vars | `ZEEK_SITE_DIR` (override default path) |
| Restart required | Zeek must be restarted after signature changes |

#### Suricata

| Requirement | Details |
|------------|---------|
| Suricata version | 6.x+ or 7.x |
| Rules directory | Configured in `suricata.yaml` (default: `/etc/suricata/rules/`) |
| Configuration | `suricata.yaml` must include custom rule files |
| Environment vars | `SURICATA_RULES_DIR` (override default path) |
| Reload command | `suricatasc reload-rules` or `kill -USR2 $(pidof suricata)` |

#### Oracle Cloud Infrastructure (OCI)

| Requirement | Details |
|------------|---------|
| OCI CLI | Installed and configured (`oci setup config`) |
| Terraform | 1.5+ (for Terraform-based deployment) |
| Environment vars | `OCI_COMPARTMENT_ID`, `OCI_TENANCY`, `OCI_REGION` |
| IAM policies | `Allow group SecurityAdmin to manage alarms in compartment` |
| Notification Topic | OCI Notification Service topic for alarm actions |

#### Microsoft Azure (Non-Sentinel)

| Requirement | Details |
|------------|---------|
| Azure CLI | `az` CLI 2.40+ |
| Subscription | Active Azure subscription |
| Environment vars | `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP` |
| Permissions | `Monitor Contributor` or `Owner` on target resource group |
| Log Analytics workspace | Workspace ID for query rules |

#### AWS

| Requirement | Details |
|------------|---------|
| AWS CLI | 2.x installed and configured |
| CloudFormation | For template-based deployment |
| AWS CDK | 2.x+ (if using CDK deployment) |
| IAM permissions | `cloudwatch:PutMetricAlarm`, `events:PutRule`, `guardduty:CreateDetector` |
| Environment vars | `AWS_REGION`, `AWS_PROFILE` (or use instance profile) |

---

## Deployment Methods

### Using deploy.sh

The repository includes a deployment script that supports all platforms:

```bash
# Dry run (validate without making changes)
./scripts/deploy.sh elastic --dry-run
./scripts/deploy.sh splunk --dry-run

# Deploy to a single platform
./scripts/deploy.sh elastic
./scripts/deploy.sh splunk
./scripts/deploy.sh fortisiem
./scripts/deploy.sh qradar
./scripts/deploy.sh sentinel
./scripts/deploy.sh wazuh
./scripts/deploy.sh zeek
./scripts/deploy.sh suricata
./scripts/deploy.sh oracle
./scripts/deploy.sh azure
./scripts/deploy.sh aws

# Deploy to all platforms
./scripts/deploy.sh all
```

The script checks for required environment variables before each deployment and reports errors clearly.

---

### Elastic Security

#### Method 1: Kibana Rule API (Recommended)

```bash
# Set credentials
export ELASTIC_HOST="https://kibana.example.com:5601"
export ELASTIC_API_KEY="your-api-key-here"

# Deploy each rule file
for rule_file in rules/elastic/*.json; do
  # Extract individual rules and create via API
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    curl -s -X POST \
      "${ELASTIC_HOST}/api/detection_engine/rules" \
      -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "kbn-xsrf: true" \
      -d "$rule"
  done
done
```

#### Method 2: Elastic Security CLI

```bash
# Using elastic-security-cli (if installed)
for rule_file in rules/elastic/*.json; do
  elastic-security-cli rule create --file "$rule_file"
done
```

#### Method 3: Kibana GUI Import

1. Navigate to **Security → Rules and Custom Rules**
2. Click **Create rule → Import**
3. Upload the JSON file
4. Review and confirm each rule

#### Elastic-Specific Notes

- Rules use KQL (Kibana Query Language) or EQL (Event Query Language) in the `query` field
- `risk_score` maps directly to Elastic's risk score (1-100)
- `interval` defaults to `5m` for near-real-time detection
- Index patterns like `logs-*` should be adjusted to match your environment
- Enable **rule execution** after import; rules are created in a disabled state by default

---

### Splunk Enterprise

#### Method 1: savedsearches.conf (Recommended for Distributed Environments)

1. Copy rule files to the search head deployer:

```bash
# On the deployer
scp rules/splunk/*.conf splunk-deployer:/opt/splunk/etc/apps/siem_alert_rules/default/

# Apply via deployer
ssh splunk-deployer "/opt/splunk/bin/splunk apply cluster-bundle"
```

2. For standalone search heads, copy directly:

```bash
scp rules/splunk/*.conf splunk-sh:/opt/splunk/etc/apps/siem_alert_rules/default/
ssh splunk-sh "/opt/splunk/bin/splunk restart"
```

#### Method 2: REST API

```bash
export SPLUNK_HOST="https://splunk.example.com:8089"
export SPLUNK_TOKEN="your-auth-token"

for rule_file in rules/splunk/*.conf; do
  # Parse each stanza from the .conf file
  while IFS= read -r stanza; do
    rule_name=$(echo "$stanza" | sed 's/\[//;s/\]//')
    # Create saved search via REST API
    curl -s -X POST \
      "${SPLUNK_HOST}/services/saved/searches" \
      -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
      -d name="${rule_name}" \
      --data-urlencode "search=$(grep -A20 "\\[${rule_name}\\]" "$rule_file" | grep '^search' | cut -d= -f2-)" \
      --data-urlencode "actions=$(grep -A20 "\\[${rule_name}\\]" "$rule_file" | grep '^action' | cut -d= -f2-)"
  done < <(grep '^\[' "$rule_file")
done
```

#### Method 3: Splunk CLI

```bash
# Add saved searches via Splunk CLI
/opt/splunk/bin/splunk add saved-search \
  -name "SPL-AI-PI-001" \
  -search 'index=* ("prompt-injection" OR "direct" OR "llm") | stats count by rule_id, rule_name | where count > 5' \
  -action email \
  -auth admin:password
```

#### Splunk-Specific Notes

- Rules use SPL (Search Processing Language)
- `sourcetype` fields should match your environment's source types
- Adjust `where count > 5` thresholds for your traffic volumes
- `action = email` can be changed to `action = notable` for ES customers
- Correlation searches should be scheduled with appropriate time windows (default: 5m)

---

### FortiSIEM

#### Method 1: GUI Import (Recommended for Small Deployments)

1. Log in to FortiSIEM **Admin → Configuration → Incident Policy**
2. Click **Import** and upload the XML rule file
3. Map event types to your FortiSIEM event taxonomy
4. Review imported rules and adjust patterns for your environment
5. Click **Apply** to activate

#### Method 2: CMDB API

```bash
export FORTISIEM_HOST="https://fortisiem.example.com"

for rule_file in rules/fortisiem/*.xml; do
  curl -s -X POST \
    "${FORTISIEM_HOST}/phoenix/rest/cmdb/rule" \
    -H "Content-Type: application/xml" \
    -u "admin:password" \
    -d @"$rule_file"
done
```

#### FortiSIEM-Specific Notes

- XML `<Pattern>` elements use FortiSIEM pattern syntax
- `<EventType>` must match FortiSIEM's built-in event types or custom event types you've defined
- `<Severity>` values: `Critical`, `High`, `Medium`, `Low`, `Info`
- Import the most critical categories first (ai-security, lateral-movement) before lower-severity rules
- Test pattern matching against your event taxonomy before bulk deployment

---

### IBM QRadar

#### Method 1: QRadar App (Recommended)

1. Install the **Custom Rules** app from the IBM App Exchange
2. Navigate to **Custom Rules → Import**
3. Upload the JSON rule file
4. Review and map log sources to your QRadar configuration
5. Deploy to QRadar

#### Method 2: REST API

```bash
export QRADAR_HOST="https://qradar.example.com"
export QRADAR_TOKEN="your-auth-token"

for rule_file in rules/qradar/*.json; do
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    rule_id=$(echo "$rule" | jq -r '.rule_id')
    aql_query=$(echo "$rule" | jq -r '.aql_query')
    severity=$(echo "$rule" | jq -r '.severity')
    
    curl -s -X POST \
      "${QRADAR_HOST}/api/custom_rule" \
      -H "SEC: ${QRADAR_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{
        \"name\": \"${rule_id}\",
        \"severity\": ${severity},
        \"query\": \"${aql_query}\"
      }"
  done
done
```

#### QRadar-Specific Notes

- Rules use AQL (Ariel Query Language)
- `severity` uses numeric scale 1-10 (not text labels)
- `credibility` and `relevance` both contribute to the final offense severity
- `log_source` should be mapped to your QRadar log source types
- AQL queries include time windows (`LAST 15 MINUTES`); adjust for your retention
- Deploy in order: most critical severity first to prioritize offense creation

---

### Microsoft Sentinel

#### Method 1: Azure CLI (Recommended)

```bash
# Authenticate
az login --service-principal \
  -u "${AZURE_CLIENT_ID}" \
  -p "${AZURE_CLIENT_SECRET}" \
  --tenant "${AZURE_TENANT_ID}"

export SENTINEL_WORKSPACE="your-workspace-id"
export RESOURCE_GROUP="your-resource-group"

for rule_file in rules/sentinel/*.json; do
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    rule_name=$(echo "$rule" | jq -r '.rule_id')
    query=$(echo "$rule" | jq -r '.query')
    severity=$(echo "$rule" | jq -r '.severity')
    tactics=$(echo "$rule" | jq -r '.tactics | join(",")')
    
    az sentinel analytics rule create \
      --resource-group "${RESOURCE_GROUP}" \
      --workspace-name "${SENTINEL_WORKSPACE}" \
      --rule-name "${rule_name}" \
      --query "${query}" \
      --severity "${severity}" \
      --tactics "${tactics}"
  done
done
```

#### Method 2: ARM Template Deployment

```bash
# Generate ARM template from rule files (manual step)
# Then deploy:
az deployment group create \
  --resource-group "${RESOURCE_GROUP}" \
  --template-file sentinel-rules-arm.json \
  --parameters @parameters.json
```

#### Method 3: Microsoft Sentinel API

```bash
for rule_file in rules/sentinel/*.json; do
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    curl -s -X PUT \
      "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.SecurityInsights/analyticsRules/$(echo "$rule" | jq -r '.rule_id')?api-version=2023-02-01" \
      -H "Authorization: Bearer $(az account get-access-token --query accessToken -o tsv)" \
      -H "Content-Type: application/json" \
      -d "$(echo "$rule" | jq '{
        properties: {
          displayName: .name,
          description: .description,
          severity: .severity,
          query: .query,
          queryFrequency: .queryFrequency,
          queryPeriod: .queryPeriod,
          triggerOperator: .triggerOperator,
          triggerThreshold: .triggerThreshold,
          tactics: .tactics,
          techniques: .techniques,
          tags: [.tags[] | {key: ., value: .}]
        }
      }}')"
  done
done
```

#### Sentinel-Specific Notes

- Rules use KQL (Kusto Query Language) — the same language as Log Analytics
- `severity` uses Sentinel labels: `High`, `Medium`, `Low`, `Informational`
- `queryFrequency` and `queryPeriod` use ISO 8601 durations (e.g., `PT5M`)
- `triggerOperator` and `triggerThreshold` control when the alert fires
- Tactics map directly to MITRE ATT&CK tactic names (e.g., `InitialAccess`, `CredentialAccess`)

---

### Wazuh

#### Method 1: Direct File Copy (Recommended)

```bash
# Copy rule files to Wazuh manager
scp rules/wazuh/*.xml wazuh-manager:/var/ossec/etc/rules/

# Restart Wazuh manager to load new rules
ssh wazuh-manager "systemctl restart wazuh-manager"
# or on older systems:
ssh wazuh-manager "/var/ossec/bin/wazuh-control restart"
```

#### Method 2: Ansible Playbook

```yaml
---
- name: Deploy Wazuh SIEM alert rules
  hosts: wazuh_managers
  become: yes
  tasks:
    - name: Copy rule files
      copy:
        src: "rules/wazuh/{{ item }}"
        dest: "/var/ossec/etc/rules/{{ item }}"
        owner: wazuh
        group: wazuh
        mode: '0640'
      loop: "{{ lookup('fileglob', 'rules/wazuh/*.xml', wantlist=True) }}"
      notify: restart wazuh

  handlers:
    - name: restart wazuh
      service:
        name: wazuh-manager
        state: restarted
```

#### Wazuh-Specific Notes

- Rule IDs must be unique and numeric (Wazuh constraint). The format `WZ-AIPI001` is a display ID; the actual `id` attribute must be numeric
- `level` maps: 9-10 = critical, 7-8 = high, 5-6 = medium, 3-4 = low, 0-2 = informational
- `decoded_as` must match a Wazuh decoder in your configuration
- `match` patterns use pipe-separated (`|`) keyword matching
- Rules are loaded in order — place more specific rules before general ones
- After adding rules, verify syntax with: `/var/ossec/bin/wazuh-analysisd -t`

---

### Zeek (Bro)

#### Method 1: File Copy + Local Configuration

```bash
# Copy signature files to Zeek site directory
scp rules/zeek/*.zeek zeek-node:/opt/zeek/share/zeek/site/

# Register signatures in local.zeek
cat >> /opt/zeek/share/zeek/site/local.zeek << 'EOF'
@load ./api-security
@load ./lateral-movement
# Add other signature files as needed
EOF

# Restart Zeek
ssh zeek-node "zeekctl deploy"
# or for containerized Zeek:
kubectl rollout restart daemonset/zeek -n monitoring
```

#### Method 2: Zeek Package Manager

```bash
# If packaging as a Zeek package
zeek-pkg install siem-alert-rules
```

#### Zeek-Specific Notes

- Signatures use the Zeek signature format with `ip-proto`, `src-ip`, `dst-port`, `payload`, and `event`
- `$HOME_NET` is resolved from Zeek's network configuration
- Payload patterns use regex syntax `/pattern/`
- Deployed files must be loaded in `local.zeek` with `@load` directives
- Zeek must be restarted (`zeekctl deploy`) after adding new signatures
- Signatures work best when combined with Zeek scripts for correlation

---

### Suricata

#### Method 1: Rule File Copy (Recommended)

```bash
# Copy rule files to Suricata rules directory
scp rules/suricata/*.rules suricata-host:/etc/suricata/rules/

# Update suricata.yaml to include custom rule files
# Add to suricata.yaml under rule-files:
#   - ai-security.rules
#   - api-security.rules
#   - etc.

# Reload rules (non-disruptive)
ssh suricata-host "suricatasc reload-rules"
# Alternative: kill -USR2 $(pidof suricata)
```

#### Method 2: Suricata-Update Integration

```bash
# Add local rules directory to suricata-update
suricata-update add-source siem-alert-rules /path/to/siem-alert-rules/rules/suricata/
suricata-update enable-source siem-alert-rules
suricata-update
```

#### Suricata-Specific Notes

- Rules use standard Suricata rule format: `action protocol source_ip source_port -> dest_ip dest_port (options;)`
- `sid` values start at 3000000 for custom rules (avoids conflict with Emerging Threats)
- `severity`: 1 = critical, 2 = high, 3 = medium, 4 = low
- `classtype` must be defined in `classification.config`
- `metadata` includes MITRE technique reference
- Rule reload can be done without restart using `suricatasc reload-rules` or `kill -USR2`

---

### Oracle Cloud Infrastructure (OCI)

#### Method 1: OCI CLI (Recommended)

```bash
export OCI_COMPARTMENT_ID="ocid1.compartment.oc1..your-compartment-id"

for rule_file in rules/oracle/*.json; do
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    rule_name=$(echo "$rule" | jq -r '.rule_id')
    severity=$(echo "$rule" | jq -r '.severity')
    metric=$(echo "$rule" | jq -r '.condition.metric')
    threshold=$(echo "$rule" | jq -r '.condition.threshold')
    
    # Create OCI alarm
    oci monitoring alarm create \
      --display-name "${rule_name}" \
      --compartment-id "${OCI_COMPARTMENT_ID}" \
      --metric-compartment-id "${OCI_COMPARTMENT_ID}" \
      --namespace "SIEM/Security" \
      --query-text "SELECT metric VALUE FROM SIEM/Security WHERE metric = '${metric}'" \
      --severity "${severity}" \
      --threshold "${threshold}" \
      --comparison-type "GT"
  done
done
```

#### Method 2: Terraform

```hcl
# Example Terraform resource for an OCI alarm
resource "oci_monitoring_alarm" "ai_prompt_injection" {
  compartment_id   = var.compartment_id
  display_name     = "OCI-AI-PI-001"
  severity         = "CRITICAL"
  namespace        = "SIEM/Security"
  query            = "SELECT metric VALUE FROM SIEM/Security WHERE metric = 'prompt_injection'"
  threshold_type   = "GT"
  threshold        = 5
  
  destinations     = [oci_ons_notification_topic.alerts.id]
  
  metric_compartment_id           = var.compartment_id
  metric_compartment_id_in_subtree = false
  
  resolution       = "PT5M"
  pending_duration  = "PT5M"
}
```

#### Method 3: OCI Events API

For Event rules (Cloud Guard integration):

```bash
oci events rule create \
  --display-name "OCI-AI-PI-001" \
  --compartment-id "${OCI_COMPARTMENT_ID}" \
  --actions file://actions.json \
  --condition file://condition.json
```

#### OCI-Specific Notes

- `$COMPARTMENT_ID` in rules is a placeholder — replace with your compartment OCID before deployment
- OCI uses numeric severity in Alarms: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- Notification topics (ONS) must be pre-created before deployment
- Consider using Terraform for production deployments to maintain state
- Event rules use OCI Events service (similar to AWS EventBridge)

---

### Microsoft Azure (Non-Sentinel)

#### Method 1: Azure CLI (Recommended)

```bash
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group"

for rule_file in rules/azure/*.json; do
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    rule_name=$(echo "$rule" | jq -r '.rule_id')
    query=$(echo "$rule" | jq -r '.query')
    severity=$(echo "$rule" | jq -r '.severity')
    
    az monitor scheduled-query create \
      --resource-group "${AZURE_RESOURCE_GROUP}" \
      --name "${rule_name}" \
      --scopes "/subscriptions/${AZURE_SUBSCRIPTION_ID}" \
      --condition "count '${query}' > $(echo "$rule" | jq -r '.triggerThreshold')" \
      --condition-query "${query}" \
      --severity "${severity}" \
      --frequency "$(echo "$rule" | jq -r '.queryFrequency')" \
      --window-size "$(echo "$rule" | jq -r '.queryPeriod')"
  done
done
```

#### Method 2: ARM/Bicep Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "parameters": {
    "workspaceLocation": { "type": "string" },
    "workspaceName": { "type": "string" }
  },
  "resources": [
    {
      "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
      "apiVersion": "2020-08-01",
      "name": "[concat(parameters('workspaceName'), '/AZ-AI-PI-001')]",
      "properties": {
        "category": "SIEM Alert Rules",
        "displayName": "AI — Direct Prompt Injection",
        "query": "AzureDiagnostics | where Category contains 'prompt_injection' | summarize count() by bin(TimeGenerated, 5m), resource_group | where count_ > 5"
      }
    }
  ]
}
```

#### Azure-Specific Notes

- Azure severity uses numeric scale: 0 = Critical, 1 = High, 2 = Medium, 3 = Low, 4 = Informational
- Queries use KQL (same as Sentinel)
- `queryFrequency` and `queryPeriod` use ISO 8601 durations
- Monitor scheduled query rules require a Log Analytics workspace
- Consider using Policy definitions for organizational enforcement

---

### AWS

#### Method 1: CloudFormation (Recommended for Production)

```yaml
# CloudFormation template for CloudWatch alarm + EventBridge rule
AWSTemplateFormatVersion: '2010-09-09'
Description: SIEM Alert Rules - AI Security

Resources:
  AIPromptInjectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: AWS-AI-PI-001
      AlarmDescription: "AI — Direct Prompt Injection"
      Namespace: SIEM/Security
      MetricName: prompt_injection
      Dimensions:
        - Name: RuleId
          Value: AWS-AI-PI-001
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      Severity: critical
      TreatMissingData: notBreaching

  AIPromptInjectionEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: AWS-AI-PI-001-Event
      Description: "Detect direct prompt injection events"
      EventPattern:
        source:
          - aws.security
          - aws.guardduty
          - aws.cloudtrail
        detail-type:
          - AWS API Call via CloudTrail
          - GuardDuty Finding
        detail:
          eventSource:
            - cloudtrail.amazonaws.com
          eventName:
            - prompt_injection
      State: ENABLED
      Targets:
        - Arn: !Ref SNSTopicArn
          Id: AlertNotification
```

#### Method 2: AWS CDK

```python
from aws_cdk import (
    aws_cloudwatch as cloudwatch,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
    Stack
)

class SIEMAlertRulesStack(Stack):
    def __init__(self, scope, id, **kwargs):
        super().__init__(scope, id, **kwargs)
        
        topic = sns.Topic(self, "SIEMAlertTopic")
        
        # CloudWatch alarm
        alarm = cloudwatch.Alarm(
            self, "AIPromptInjectionAlarm",
            alarm_name="AWS-AI-PI-001",
            alarm_description="AI — Direct Prompt Injection",
            metric=cloudwatch.Metric(
                namespace="SIEM/Security",
                metric_name="prompt_injection",
                dimensions_map={"RuleId": "AWS-AI-PI-001"},
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=5,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
```

#### Method 3: AWS CLI

```bash
export AWS_REGION="us-east-1"

for rule_file in rules/aws/*.json; do
  jq -c '.rules[]' "$rule_file" | while read -r rule; do
    rule_name=$(echo "$rule" | jq -r '.rule_id')
    namespace=$(echo "$rule" | jq -r '.cloudwatch_metric.namespace')
    metric_name=$(echo "$rule" | jq -r '.cloudwatch_metric.metricName')
    threshold=$(echo "$rule" | jq -r '.cloudwatch_metric.threshold')
    
    # Create CloudWatch alarm
    aws cloudwatch put-metric-alarm \
      --alarm-name "${rule_name}" \
      --alarm-description "$(echo "$rule" | jq -r '.description')" \
      --namespace "${namespace}" \
      --metric-name "${metric_name}" \
      --dimensions "RuleId=${rule_name}" \
      --statistic Sum \
      --period 300 \
      --evaluation-periods 1 \
      --threshold "${threshold}" \
      --comparison-operator GreaterThanThreshold
    
    # Create EventBridge rule
    pattern=$(echo "$rule" | jq -r '.eventbridge_pattern')
    aws events put-rule \
      --name "${rule_name}-Event" \
      --event-pattern "${pattern}"
  done
done
```

#### AWS-Specific Notes

- Each rule creates three resources: CloudWatch alarm, EventBridge rule, and optionally a GuardDuty finding class
- `cloudwatch_metric.threshold` values should be tuned to your traffic volumes
- EventBridge patterns use AWS event format
- Consider using CloudFormation or CDK for production to maintain state and enable drift detection
- For GuardDuty custom findings, you need a custom finding provider

---

## Using validate.sh

The validation script checks rule integrity across all platforms:

```bash
./scripts/validate.sh
```

### What It Checks

1. **Rule count per platform**: Verifies rule files exist and counts rules per platform
2. **Rule format validation**: Checks for valid JSON, XML, conf, zeek, and rules syntax
3. **Mapping completeness**: Counts mappings in each mapping file
4. **Missing platform directories**: Warns if any platform directory is missing

### Expected Output

```
🔍 SIEM Alert Rules Validator
==============================

  elastic: 10 files, 500 rules
  splunk: 10 files, 500 rules
  fortisiem: 10 files, 500 rules
  qradar: 12 files, 500 rules
  sentinel: 10 files, 500 rules
  wazuh: 15 files, 500 rules
  zeek: 2 files, 20 rules
  suricata: 10 files, 500 rules

📊 Total rules found: 3520

🔗 Checking mappings...
  elastic: 188 mappings
  splunk: 188 mappings
  fortisiem: 188 mappings
  qradar: 188 mappings
  sentinel: 188 mappings
  wazuh: 188 mappings
  zeek: 188 mappings
  suricata: 188 mappings
  oracle: 188 mappings
  azure: 188 mappings
  aws: 188 mappings

✅ Validation complete. 3520 rules, 0 warnings, 0 errors
```

### Extending Validation

Add custom checks by modifying `validate.sh` or creating a wrapper:

```bash
#!/bin/bash
# Custom validation wrapper
./scripts/validate.sh || exit 1

# Additional: Check all test IDs have mappings
echo "Checking cross-reference integrity..."
for test_id in $(jq -r '.mappings[].test_id' mappings/test-to-siem.json); do
  for platform in elastic splunk fortisiem qradar sentinel wazuh zeek suricata oracle azure aws; do
    rule_id=$(jq -r ".mappings[] | select(.test_id==\"$test_id\") | .siem_rules.$platform" mappings/test-to-siem.json)
    if [ "$rule_id" = "null" ] || [ -z "$rule_id" ]; then
      echo "⚠️  Missing $platform mapping for test_id: $test_id"
    fi
  done
done
```

---

## Testing Rules Before Deployment

### Step 1: Syntax Validation

```bash
# Validate JSON files
for f in rules/elastic/*.json rules/qradar/*.json rules/sentinel/*.json rules/oracle/*.json rules/azure/*.json rules/aws/*.json; do
  jq empty "$f" 2>/dev/null || echo "Invalid JSON: $f"
done

# Validate XML files
for f in rules/fortisiem/*.xml rules/wazuh/*.xml; do
  xmllint --noout "$f" 2>/dev/null || echo "Invalid XML: $f"
done

# Validate Suricata rule syntax (requires suricata binary)
suricata -T -c /etc/suricata/suricata.yaml -l /tmp/suricata-test
```

### Step 2: Dry-Run Deployment

Always run `--dry-run` before actual deployment:

```bash
./scripts/deploy.sh elastic --dry-run
./scripts/deploy.sh splunk --dry-run
# ... for each platform
```

### Step 3: Single-Rule Testing

Deploy a single rule first to verify the integration:

```bash
# Elastic: Create one rule via API
jq '.rules[0]' rules/elastic/ai-security.json | \
  curl -s -X POST "${ELASTIC_HOST}/api/detection_engine/rules" \
    -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @-

# Splunk: Create one saved search
splunk add saved-search -name "SPL-AI-PI-001" \
  -search 'index=* ("prompt-injection" OR "direct" OR "llm") | stats count by rule_id, rule_name | where count > 5'
```

### Step 4: Query Testing

For each deployed rule, test the detection logic against known-good data:

| Platform | Test Method |
|----------|------------|
| Elastic | Use Kibana Dev Tools to run the KQL query with `logs-*` index |
| Splunk | Run the SPL search in the Search app with time range |
| Sentinel | Use Log Analytics to run the KQL query |
| QRadar | Use AQL in the search interface with the log source |
| Wazuh | Send a test log event matching the rule pattern |
| Zeek | Replay a PCAP with known malicious traffic |
| Suricata | Replay a PCAP with Suricata in test mode |

---

## Troubleshooting Common Issues

### Elastic Security

| Issue | Cause | Solution |
|-------|-------|----------|
| `401 Unauthorized` | Invalid API key | Regenerate API key in Kibana → Management → API Keys |
| `403 Forbidden` | Insufficient privileges | Assign `security_rule` and `security_rule_read` privileges |
| Rule not triggering | Index pattern mismatch | Verify `index` patterns match your data indices |
| `400 Bad Request` | Invalid KQL syntax | Test query in Kibana Dev Tools first |
| Duplicate rule ID | Rule already exists | Use PUT to update, or DELETE then POST |

### Splunk

| Issue | Cause | Solution |
|-------|-------|----------|
| Saved search not visible | App context issue | Verify the app is visible and the user has access |
| Search returns no results | Index/sourcetype mismatch | Adjust `index=*` to your actual index name |
| Alert not firing | Threshold too high | Reduce `where count > 5` to match your traffic |
| REST API 403 | Token lacks capabilities | Assign `edit_search`, `run_search`, `list_search` capabilities |

### FortiSIEM

| Issue | Cause | Solution |
|-------|-------|----------|
| Pattern not matching | Event type mismatch | Verify `<EventType>` matches your FortiSIEM event taxonomy |
| Import fails | XML validation error | Check for special characters in descriptions |
| Rule not triggering | Pattern too specific | Broaden pattern matching keywords |
| CMDB API 401 | Authentication failure | Verify admin credentials and session token |

### QRadar

| Issue | Cause | Solution |
|-------|-------|----------|
| AQL syntax error | Reserved keyword conflict | Escape column names with double quotes |
| No offenses created | Credibility too low | Increase `credibility` to 7+ |
| Low severity offenses | Relevance score too low | Verify `relevance` matches the intended severity |
| Log source not found | Unmapped log source | Map log source type in QRadar admin |

### Sentinel

| Issue | Cause | Solution |
|-------|-------|----------|
| `InvalidQuery` | KQL syntax error | Test query in Log Analytics workspace |
| No alerts firing | Threshold too high | Reduce `triggerThreshold` or adjust `queryFrequency` |
| `AuthorizationFailed` | Insufficient RBAC | Assign `Microsoft.SecurityInsights/analyticsRules/write` |
| Duplicate rule name | Rule already exists | Use unique `rule_id` per workspace |

### Wazuh

| Issue | Cause | Solution |
|-------|-------|----------|
| Rules not loading | XML syntax error | Verify with `/var/ossec/bin/wazuh-analysisd -t` |
| Rule ID conflict | Overlapping numeric IDs | Ensure unique numeric IDs (check `ossec.conf` for `rule_dir`) |
| No alerts | Decoder mismatch | Verify `decoded_as` matches your Wazuh decoders |
| Level not matching | Level mapping difference | Wazuh uses 0-14 level scale; map correctly |

### Zeek

| Issue | Cause | Solution |
|-------|-------|----------|
| Signature not loading | Syntax error in `.zeek` file | Check `zeekctl deploy` output for errors |
| No events firing | Pattern not matching traffic | Verify payload regex matches your log format |
| `$HOME_NET` incorrect | Network configuration mismatch | Update `zeekctl configure` with correct networks |
| Missing `@load` | Script not loaded in `local.zeek` | Add `@load ./script-name` to `local.zeek` |

### Suricata

| Issue | Cause | Solution |
|-------|-------|----------|
| Rule file not loaded | Not referenced in `suricata.yaml` | Add rule file to `rule-files:` section |
| `sid` conflict | Duplicate `sid` values | Ensure custom rules use `sid >= 3000000` |
| Rules not reloading | Need explicit reload | Run `suricatasc reload-rules` or `kill -USR2` |
| False positives | Pattern too broad | Add more `content:` matches or use `pcre:` for precision |

### Cloud Platforms (OCI, Azure, AWS)

| Issue | Cause | Solution |
|-------|-------|----------|
| Alarm not creating | Insufficient IAM permissions | Verify `Monitor Contributor` (Azure), `AlarmCreate` (OCI), `cloudwatch:PutMetricAlarm` (AWS) |
| Alarm not triggering | Metric not publishing | Verify your application is publishing to the correct metric namespace |
| EventBridge rule not matching | Pattern mismatch | Test with `aws events test-event-pattern` |
| Terraform drift | Manual changes outside IaC | Always manage alarms/rules through Terraform or CloudFormation |

---

## Performance Considerations

### Rule Count and Index Patterns

| Platform | Recommended Max Active Rules | Notes |
|----------|------------------------------|-------|
| Elastic Security | 3,000-5,000 | Above 5,000, consider splitting across rule types |
| Splunk Enterprise | 2,000-3,000 | Correlation searches are more expensive than saved searches |
| FortiSIEM | 5,000-10,000 | Pattern-based rules are lightweight; adjust event type mapping |
| QRadar | 2,000-3,000 | Custom rules are expensive; use building blocks for common logic |
| Microsoft Sentinel | 1,000-2,000 | Analytics rules count against workspace query limits |
| Wazuh | 5,000-10,000 | XML rules are lightweight; ensure proper rule ordering |
| Zeek | 500-1,000 signatures | Each signature adds packet inspection overhead |
| Suricata | 5,000-30,000 | Engine handles large rule counts well; use `threshold` and `rate_filter` |
| OCI | 500-1,000 alarms | OCI Alarm limits; use Event rules for high-volume detection |
| Azure | 5,000-10,000 | Monitor scheduled query rules have per-subscription limits |
| AWS | 5,000-10,000 | CloudWatch alarm limits per region; use EventBridge for high-volume |

### Aggregation and Threshold Tuning

Rules include default thresholds (e.g., `where count > 5`, `threshold: 5`). These must be tuned to your environment:

1. **Start high**: Deploy with conservative thresholds, then lower them
2. **Monitor noise**: Track false positive rates in the first 48 hours
3. **Adjust per-category**: AI/LLM security rules may need lower thresholds than recon rules
4. **Consider time windows**: Short windows (1-5m) catch active attacks; longer windows (1h) catch slow exfiltration
5. **Use aggregation wisely**: `stats count by src_ip` reduces noise; `stats count by src_ip, dest_ip` increases specificity

### Index Pattern Optimization (Elastic)

- Use specific index patterns (e.g., `logs-authentication-*`) over broad patterns (`logs-*`) when possible
- Each rule's `index` field narrows the search scope
- Consider creating dedicated indices for AI/LLM security logs

### Search Optimization (Splunk)

- Replace `index=*` with specific index names in production
- Add `sourcetype` filters for faster searches
- Use `tstats` for high-volume fields
- Schedule searches during off-peak hours for low-priority rules

### Query Optimization (Sentinel)

- Use `summarize` instead of raw `where` for large datasets
- Set appropriate `queryFrequency` (don't run critical queries every 1 minute)
- Use `bin()` for time bucketing to reduce data volume
- Consider materialized views for frequently-run queries

### Resource Impact (Wazuh)

- Rules with `match` patterns are evaluated on every log event
- Order rules from most specific to least specific
- Use `<if_sid>` for rule chaining instead of broad `<match>` patterns

### Packet Inspection (Zeek, Suricata)

- Each Zeek signature adds to the packet inspection path
- Suricata's Hyperscan engine handles large rule counts efficiently
- Use `threshold` and `rate_filter` in Suricata to reduce alert noise
- Consider separate Suricata instances for different traffic types