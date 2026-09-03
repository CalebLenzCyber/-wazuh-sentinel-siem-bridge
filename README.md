# -wazuh-sentinel-siem-bridge
Integrating an on-premises Wazuh SIEM with Microsoft Sentinel via Azure Arc, featuring cost-optimized KQL data collection rules and programmatic REST API incident automation.

# Hybrid SIEM Automation: Integrating On-Premises Wazuh with Azure Monitor & Microsoft Sentinel

## Project Overview
This project demonstrates the engineering and implementation of a hybrid enterprise security architecture. It establishes a real-time telemetry pipeline connecting an on-premises **Wazuh SIEM Manager (Linux Virtual Machine)** to **Azure Log Analytics** and **Microsoft Sentinel**. 

The entire ecosystem was deployed inside a strict cloud environment utilizing specialized programmatic access methods, custom ingestion filters, and raw REST API deployments to bypass standard portal constraints. The resulting architecture provides an enterprise-grade security operations dashboard while remaining entirely cost-optimized within the Azure Free Tier.

---

## Architectural Blueprint

[On-Premises Linux VM]
│
▼ 
(Wazuh Engine generates logs at /var/ossec/logs/alerts/alerts.json)[Azure Monitor Agent (AMA)]
│
▼ 
(Authenticates via Device-Less Azure Arc Managed Identity)[Azure Data Collection Endpoint (DCE)]
│
▼ 
(Data Collection Rule applies KQL String Filters & Discards Noise)[Azure Log Analytics Workspace] (Custom Table: WazuhAlerts_CL)
│
▼ 
(Scheduled Analytics Rule scans data-plane via REST API)[Microsoft Sentinel & Defender XDR] ──► [Interactive SOC Analyst Workbook Dashboard]


---

## Core Engineering Phases & Implementations

### Phase 1: Interactive Login Bypass & Azure Arc Onboarding
* **Challenge:** Multi-Factor Authentication (MFA) parameters and Security Defaults in the Entra ID tenant blocked standard interactive command-line browser device logins during agent enrollment.
* **Solution:** Engineered a programmatic **Azure Service Principal** configured with scoped permissions inside a dedicated resource group (`RG-Security-Labs`). Bypassed interactive screens using a hardware-less cryptographic handshake:
  ```bash
  sudo azcmagent connect \
    --service-principal-id "<Application-ID>" \
    --service-principal-secret "<Secret>" \
    --resource-group "RG-Security-Labs" \
    --tenant-id "<Tenant-ID>" \
    --location "eastus" \
    --subscription-id "<Subscription-ID>"
  ```
* **Outcome:** Securely projected the local virtual machine into the Azure Arc control plane. The machine shed the Service Principal credentials immediately post-onboarding and transitions to a unique, self-authenticating **Azure Managed Identity**.

### Phase 2: Ingestion-Cap Optimization & Custom Schema Engineering
* **Challenge:** Wazuh engine initialization dumps massive background scans—specifically **File Integrity Monitoring (FIM)** and **Security Configuration Assessment (SCA)** metrics. These logs generate thousands of redundant records daily, threatening to blow through the tenant's free ingestion cap.
* **Solution:** Bypassed the standard Linux Syslog collector completely and created a **Custom Data Collection Rule (DCR)** matching the explicit local file pattern layout. Implemented an aggressive string-matching filter at the *machine layer* using an inline transformation query.
* **The Telemetry Filter Configuration:**
  ```kql
  source 
  | where RawData !contains "Integrity checksum changed" 
  | where RawData !contains "File added to the system" 
  | where RawData !contains "File deleted" 
  | extend parsed = parse_json(RawData) 
  | extend RuleLevel = toint(parsed.rule.level) 
  | where RuleLevel >= 5
  ```
* **Outcome:** Completely eliminated baseline system noise before it left the server's hard drive. Telemetry was restricted strictly to actionable security warnings (Wazuh Rule Level 5+), safely dropping daily ingestion metrics to **0.0 GB** within the workspace quota dashboard.

### Phase 3: Programmatic SIEM Analytics Deployment (API Overwrite)
* **Challenge:** A cross-platform permission sync issue within the unified Microsoft Defender Portal (`://microsoft.com`) caused a sticky redirect loop, locking out access to the visual Analytics Rule wizard interface.
* **Solution:** Bypassed the broken browser UI components completely by leveraging the native **Azure Cloud Shell API** interface. Hand-crafted a raw REST deployment script to push a scheduled detection query directly to the `Microsoft.SecurityInsights` provider backend.
* **The REST API Ingestion Payload:**
  ```bash
  az rest --method put \
    --uri "/subscriptions/70530b32-1817-4c76-bc66-43cda9e1e92f/resourceGroups/RG-Security-Labs/providers/Microsoft.OperationalInsights/workspaces/Wazuh-Cloud-Repo/providers/Microsoft.SecurityInsights/alertRules/WazuhCriticalThreatAlert?api-version=2023-02-01" \
    --body '{"kind":"Scheduled","properties":{"displayName":"Wazuh Critical Severity Alert","description":"Triggers an incident whenever a Level 7+ alert hits the server.","severity":"High","enabled":true,"query":"WazuhAlerts_CL | extend parsed = parse_json(RawData) | extend RuleLevel = toint(parsed.rule.level) | where RuleLevel >= 7","queryFrequency":"PT5M","queryPeriod":"PT5M","triggerOperator":"GreaterThan","triggerThreshold":0,"suppressionDuration":"PT1H","suppressionEnabled":false,"incidentConfiguration":{"createIncident":true,"groupingConfiguration":{"enabled":false,"reopenClosedIncident":false,"lookbackDuration":"PT5M","matchingMethod":"AllEntities"}}}}'
  ```

---

## Validation Testing & Incident Response Simulation

To validate the end-to-end telemetry and alert routing logic, a high-severity threat alert string was appended directly to the monitored Wazuh file system directory using a dynamic local time parameter:

```bash
echo "{\"timestamp\":\"\$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)\",\"rule\":{\"level\":10,\"description\":\"CRITICAL ATTACK: Live SIEM Correlation Validation\",\"id\":\"99999\"},\"agent\":{\"name\":\"wazuh-siem\"},\"manager\":{\"name\":\"wazuh-siem\"},\"full_log\":\"Testing background automation rules\"}" | sudo tee -a /var/ossec/logs/alerts/alerts.json
```

### Operational Results
1. **Agent Capture:** The local Azure Monitor Agent instantly identified the file update.
2. **Ingestion Loop:** The record passed through the string-exclusion filters and landed successfully inside the cloud `WazuhAlerts_CL` logging table.
3. **Correlation Match:** Microsoft Sentinel's scheduled analytics engine processed the log entry within its 5-minute sliding evaluation window.
4. **Incident Creation:** The system successfully generated **Incident #1: Wazuh Critical Severity Alert**, mapping it directly onto the centralized analyst operations triage grid.

---

## Interactive SOC Triage Dashboard

An advanced **Azure Monitor Workbook** was built from scratch to act as the primary interface for a security analyst. It features a complete multi-widget workflow panel:

* **Incident Queue Display:** A top-tier monitoring grid that reads out active, high-priority incident status columns (`IncidentNumber`, `Title`, `Severity`, `Status`).
* **Real-Time Data Distribution:** A dynamic pie chart breakdown tracking current rule severity volume percentages.
* **JSON Field-Extraction Engine:** Converts dense raw strings into separate, structured investigation columns:
  ```kql
  WazuhAlerts_CL
  | extend parsed = parse_json(RawData)
  | extend RuleId = tostring(parsed.rule.id),
           Description = tostring(parsed.rule.description),
           SeverityLevel = toint(parsed.rule.level)
  | project TimeGenerated, SeverityLevel, RuleId, Description
  | order by TimeGenerated desc
  ```

---

## Skills Verified Throughout Project
* **Hybrid Cloud Security Architecture** (Azure Arc Core Services)
* **Identity & Access Management** (App Registrations, Service Principals, Scoped Azure RBAC)
* **SIEM Engineering & Telemetry Management** (Wazuh Core Architecture, Azure Monitor Agent Pipelines)
* **Advanced Threat Analysis & Log Querying** (Kusto Query Language - KQL)
* **DevSecOps & Automation Tools** (Azure CLI, REST APIs, JSON Scheme Injection Parsing)
* **Data Budgeting & Cost Control** (Data Collection Rules, Daily Ingestion Caps, Log Retention Policies)

