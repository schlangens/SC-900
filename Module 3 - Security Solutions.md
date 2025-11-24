# Module 3: Microsoft Security Solutions
**Weight**: 30-35% of exam (HIGHEST WEIGHT)

---

## 3.1 Azure Network Security

### Azure DDoS Protection

**What is DDoS?**: Distributed Denial of Service attacks attempt to overwhelm a system by flooding it with traffic from multiple sources, making resources unavailable to legitimate users.

**Azure DDoS Protection Tiers**:

| Feature | Basic | Standard |
|---------|-------|----------|
| **Cost** | Free (included with Azure) | Pay per protected resource |
| **Protection Level** | Infrastructure layer (L3/L4) | Infrastructure + Application layer |
| **Monitoring** | Basic metrics | Real-time attack metrics & logs |
| **Support** | None | DDoS Rapid Response team |
| **Application Insights** | No | Yes - attack analytics |
| **Cost Protection** | No | Yes - resource scaling credits |

**When to Use**:
- **Basic**: Default protection for all Azure resources, suitable for non-critical workloads
- **Standard**: Mission-critical applications, public IPs requiring advanced protection, compliance requirements

### Azure Firewall

**What it is**: A cloud-native, stateful firewall-as-a-service that provides network and application-level protection for Azure resources across multiple subscriptions and virtual networks.

**Key Features**:
- [x] Stateful firewall - tracks connection state
- [x] Built-in high availability - no additional load balancers needed
- [x] Threat intelligence - block traffic from known malicious IPs/domains
- [x] Application/Network filtering rules - L3-L7 filtering
- [x] FQDN filtering - filter by fully qualified domain names
- [x] NAT rules - inbound/outbound network address translation

**Azure Firewall Tiers**:

| Feature | Standard | Premium |
|---------|----------|---------|
| **IDPS** | No | Yes - Intrusion Detection & Prevention |
| **TLS Inspection** | No | Yes - decrypt/inspect encrypted traffic |
| **URL Filtering** | No | Yes - filter based on full URL |
| **Web Categories** | No | Yes - allow/deny by category |
| **Cost** | Lower | Higher (advanced features) |

**Use Cases**:
- Centralized network security for hub-and-spoke architectures
- Outbound filtering to control what resources can access on the internet

### Web Application Firewall (WAF)

**What it is**: A layer 7 (application layer) firewall that protects web applications from common exploits and vulnerabilities. Focuses on HTTP/HTTPS traffic.

**Where it runs**:
- Azure Application Gateway - regional service
- Azure Front Door - global service
- Azure CDN - content delivery with protection

**Protection Against**:
- [x] SQL injection - malicious SQL code in inputs
- [x] Cross-site scripting (XSS) - injecting malicious scripts
- [x] OWASP Top 10 vulnerabilities - common web exploits
- [x] Bot attacks - malicious automated traffic

**Rule Types**:
1. **Managed Rules**: Pre-configured rulesets maintained by Microsoft (based on OWASP core rule sets)
2. **Custom Rules**: User-defined rules for specific application needs (IP allow/block lists, rate limiting, geo-filtering)

### Network Security Groups (NSGs)

**What they are**: Virtual firewalls that filter network traffic to and from Azure resources within a virtual network. Act at the network interface and subnet level.

**How they work**: Process rules in priority order (lowest number = highest priority). First matching rule is applied, then processing stops.

**Rules Components**:
- Priority: Number 100-4096 (lower = higher priority)
- Source/Destination: IP address, CIDR, service tag, or application security group
- Protocol: TCP, UDP, ICMP, or Any
- Port: Single port, range, or * (any)
- Action: Allow or Deny

**NSG vs Firewall**:

| Feature | NSG | Azure Firewall |
|---------|-----|----------------|
| **Scope** | Subnet/NIC level | Centralized for entire VNet |
| **Complexity** | Simple allow/deny rules | Advanced filtering with FQDN/threat intelligence |
| **Filtering Type** | Layer 3-4 (Network layer) | Layer 3-7 (Network + Application) |
| **Cost** | Free | Paid service |
| **Best For** | Basic traffic filtering | Advanced security, centralized management |

### Azure Bastion

**What it is**: A fully managed PaaS service that provides secure RDP/SSH connectivity to virtual machines directly through the Azure portal over SSL, without exposing VMs through public IP addresses.

**Benefits**:
- No need for public IPs on VMs (reduces attack surface)
- No need to manage/patch bastion hosts
- Protection against port scanning (RDP/SSH ports not exposed)
- Integrated with Azure portal (seamless access)
- Protection against zero-day exploits
- NSG hardening (can restrict to only Azure Bastion subnet)

**How it works**:
1. Deploy Azure Bastion into a dedicated subnet (AzureBastionSubnet) in your VNet
2. User connects to Azure portal and selects VM
3. Azure Bastion provides RDP/SSH session through browser using HTML5
4. Traffic flows over SSL (443) to Azure Bastion, then to VM over private IP
5. No agent or client software needed

**Use Case**: Secure remote access to Azure VMs without exposing them to the internet, ideal for jump box replacement and compliance requirements.

---

## 3.2 Microsoft Defender for Cloud

### Overview

**What is Defender for Cloud?**: A cloud-native application protection platform (CNAPP) that provides security posture management and threat protection across Azure, hybrid, and multi-cloud environments (AWS, GCP).

**Key Pillars**:
1. **Cloud Security Posture Management (CSPM)**: Continuously assesses configurations against best practices, provides security recommendations, and compliance tracking. Available for FREE.
2. **Cloud Workload Protection Platform (CWPP)**: Advanced threat protection for specific workload types (VMs, containers, databases, etc.). Requires paid Defender plans.

### Secure Score

**What it is**: A numerical representation (0-100%) of your security posture based on security recommendations. Higher score = better security.

**How it works**:
- Defender for Cloud continuously assesses your resources
- Generates security recommendations with point values
- Your score = (Implemented security controls points / Total available points) × 100

**Score Calculation**:
Score = (Sum of secure resource points / Sum of all resource points) × 100

**Example Recommendations**:
- Enable MFA for accounts with owner permissions (8 points)
- System updates should be installed on machines (6 points)
- Storage accounts should restrict network access (4 points)
- Enable encryption at rest (3 points)

**How to Improve**: Implement security recommendations, prioritize high-impact actions, use automated remediation, and regularly review compliance standards.

### Security Posture Management

**Features**:
- [x] Continuous assessment - real-time security evaluation
- [x] Security recommendations - prioritized actionable guidance
- [x] Azure, AWS, GCP support - multi-cloud protection
- [x] Compliance dashboard - track regulatory requirements
- [x] Network map - visualize topology and vulnerabilities

**Regulatory Compliance**:
- Available standards:
  - Azure Security Benchmark (default)
  - PCI DSS 3.2.1 / 4.0
  - ISO 27001
  - NIST SP 800-53
  - SOC 2 Type 2
  - HIPAA/HITRUST
  - CIS Benchmarks

### Workload Protections

**Defender Plans**:

| Workload | Protection | Key Features |
|----------|------------|--------------|
| **Servers** | Defender for Servers | Vulnerability assessment, JIT access, file integrity monitoring |
| **App Service** | Defender for App Service | Detects attacks targeting web apps, monitors requests/responses |
| **Storage** | Defender for Storage | Malware scanning, anomalous access detection |
| **SQL** | Defender for SQL | Vulnerability assessment, threat detection, SQL injection protection |
| **Kubernetes** | Defender for Containers | Runtime threat detection, vulnerability scanning, policy enforcement |
| **Container Registries** | Defender for Container Registries | Image vulnerability scanning, registry protection |
| **Key Vault** | Defender for Key Vault | Unusual access patterns, suspicious operations detection |
| **Resource Manager** | Defender for ARM | Suspicious management operations, admin layer protection |

### Threat Protection Features

**Security Alerts**: Notifications triggered when Defender detects threats to resources. Include description, affected resources, remediation steps, and MITRE ATT&CK tactics.

**Alert Severity Levels**:
- High: Immediate action required; definite malicious activity detected
- Medium: Suspicious activity that may indicate compromise; should be investigated
- Low: Potentially malicious activity or security violation; may be benign
- Informational: Security-relevant information that doesn't indicate threat

**Just-in-Time VM Access**:
- Reduces exposure to attacks by blocking persistent access to management ports (RDP 3389, SSH 22)
- Opens ports only when needed, for limited time, from specific IP addresses
- Requires NSG or Azure Firewall rules to be configured
- Audit trail of all access requests

**Adaptive Application Controls**:
- Uses machine learning to define allow lists of safe applications for VMs
- Monitors application execution and alerts on violations
- Helps prevent malware execution
- Enforced through Windows AppLocker or Linux audit mode

---

## 3.3 Microsoft 365 Defender

### Overview

**What is Microsoft 365 Defender?**: A unified pre- and post-breach enterprise defense suite that coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications.

**XDR Platform**: Extended Detection and Response - automatically collects, correlates, and analyzes threat data from multiple sources to provide comprehensive attack visibility and automated response.

**Key Components**:
1. Defender for Office 365 - Email and collaboration protection
2. Defender for Endpoint - Device/endpoint protection
3. Defender for Identity - Identity and Active Directory protection
4. Defender for Cloud Apps - Cloud application security (CASB)

### Microsoft 365 Defender Portal

**URL**: https://security.microsoft.com

**Key Sections**:
- [x] Incidents & Alerts - Aggregated security events across all Defender products
- [x] Hunting - Proactive threat hunting with KQL queries
- [x] Threat Analytics - Intelligence reports on active threat campaigns
- [x] Secure Score - Security posture measurement for Microsoft 365
- [x] Reports - Comprehensive security reporting and trends

**Incident Management**: Automatically correlates related alerts across products into a single incident, provides unified investigation experience, and enables coordinated response actions.

---

## 3.4 Microsoft Defender for Office 365

### Overview

**What it protects**: Email and collaboration tools (Outlook, Teams, SharePoint, OneDrive) from advanced threats like phishing, business email compromise, malware, and malicious URLs.

**Plans**:

| Feature | Plan 1 | Plan 2 |
|---------|--------|--------|
| **Safe Attachments** | Yes | Yes |
| **Safe Links** | Yes | Yes |
| **Anti-phishing** | Yes | Yes (enhanced) |
| **Threat Investigation** | No | Yes - Threat Explorer |
| **Automated Investigation** | No | Yes - AIR |
| **Threat Hunting** | No | Yes - Advanced hunting |

### Key Protection Features

#### Safe Attachments
**What it does**: Opens email attachments in a protected sandbox environment (detonation chamber) to detect malicious behavior before delivering to users.

**How it works**:
1. Email arrives with attachment
2. Attachment is opened in isolated virtual environment
3. Behavior is analyzed for malicious activity (file operations, registry changes, network calls)
4. If safe, delivered to user; if malicious, blocked

**Policies**: Configure actions (Block, Monitor, Replace, Dynamic Delivery), scope, and exceptions.

#### Safe Links
**What it does**: Rewrites URLs in emails and Office documents to route through Microsoft servers for real-time scanning at time-of-click.

**How it works**: URL is rewritten to Microsoft protection service → User clicks → Microsoft checks URL reputation → If safe, redirects to original URL; if malicious, shows warning page

**Time-of-click protection**: Verifies URL safety each time it's clicked, not just when email received, protecting against links that become malicious after delivery.

#### Anti-Phishing
**Protection against**:
- Impersonation attacks - protects specific users and domains from being impersonated
- Spoofing - validates sender authentication (SPF, DKIM, DMARC)
- Mailbox intelligence - uses AI to learn communication patterns and detect anomalies

**Policies**: Define protected users/domains, set impersonation thresholds, configure actions (quarantine, move to junk, add warning).

#### Anti-Spam
**Filtering**: Uses machine learning, reputation analysis, and content filtering to identify spam and bulk email.

**Actions**:
- Move to Junk Email folder
- Quarantine (admin/user release)
- Delete
- Add X-header or modify subject

### Threat Investigation Tools

**Threat Explorer** (Plan 2): Real-time reporting tool to identify and analyze threats. View email threats, malware campaigns, and phishing attempts with detailed filtering and analysis.

**Automated Investigation & Response (AIR)**: Automatically investigates alerts, examines evidence, and recommends or takes remediation actions (quarantine emails, block URLs, disable user accounts).

**Attack Simulation Training**:
- Simulate phishing, password spray, and brute force attacks
- Train users to recognize threats through realistic scenarios
- Track results and provide targeted training

---

## 3.5 Microsoft Defender for Endpoint

### Overview

**What it is**: An enterprise endpoint security platform designed to help prevent, detect, investigate, and respond to advanced threats across Windows, macOS, Linux, iOS, and Android devices.

**Supported Platforms**:
- [x] Windows 10/11, Windows Server 2012 R2+
- [x] macOS (last 3 releases)
- [x] Linux (RHEL, CentOS, Ubuntu, SLES, Debian)
- [x] iOS (mobile threat defense)
- [x] Android (mobile threat defense)

### Core Capabilities

#### Threat & Vulnerability Management
**What it does**: Built-in capability that discovers vulnerabilities and misconfigurations in real-time, prioritizes based on threat landscape and business context.

**Features**:
- Continuous asset discovery and vulnerability scanning (no additional agents needed)
- Risk-based prioritization using threat intelligence
- Remediation recommendations and tracking
- Security baselines assessment

#### Attack Surface Reduction (ASR)
**What it is**: Set of configurable rules that help prevent actions and behaviors commonly used by malware to compromise devices.

**ASR Rules Examples**:
- Block executable content from email and webmail
- Block Office applications from creating child processes
- Block credential stealing from Windows Local Security Authority (lsass.exe)
- Block persistence through WMI event subscription
- Block untrusted/unsigned processes from USB

#### Endpoint Detection & Response (EDR)
**What it does**: Provides advanced attack detection, investigation, and response capabilities through behavioral sensors and cloud analytics.

**Capabilities**:
- Behavioral sensors - monitor and collect OS behaviors
- Cloud analytics - big data analytics turn behaviors into insights and detections
- Threat intelligence - identifies attacker tools, techniques, and generates alerts

#### Automated Investigation & Response
**How it works**:
1. Alert triggered by detection engine
2. Automated investigation examines evidence and related entities
3. Remediation actions recommended or automatically taken
4. Investigation results and actions logged in Action Center

**Automation Levels**:
- Full automation - remediation actions taken automatically
- Semi-automation - requires approval before remediation
- No automation - manual investigation and response only

#### Advanced Hunting
**What it is**: Query-based threat hunting tool that lets you proactively inspect events in your network to locate threat indicators and entities.

**Query Language**: Kusto Query Language (KQL)

**Use Cases**:
- Search for indicators of compromise (IOCs)
- Hunt for specific behaviors or patterns
- Investigate security incidents
- Validate detection rules

### Device Management Integration

**Microsoft Intune Integration**: Defender for Endpoint integrates with Intune for unified endpoint management, enabling conditional access based on device risk level.

**Compliance Policies**: Device threat level from Defender can be used in Intune compliance policies to block risky devices from accessing corporate resources.

---

## 3.6 Microsoft Defender for Cloud Apps

### Overview

**What it is**: Cloud Access Security Broker (CASB)

**What is a CASB?**: A security solution that sits between users and cloud services to provide visibility, data security, threat protection, and compliance for cloud applications.

**Four Pillars**:
1. **Visibility**: Discover cloud apps being used (including shadow IT)
2. **Data Security**: Protect sensitive data with DLP and classification
3. **Threat Protection**: Detect threats and anomalous behavior
4. **Compliance**: Meet compliance requirements and assess cloud app risk

### Key Features

#### Cloud Discovery
**What it does**: Analyzes traffic logs to discover cloud apps being used in your organization, including unsanctioned apps (shadow IT).

**Shadow IT**: Cloud services used without IT department approval or knowledge. Cloud Discovery identifies these to help assess risk.

**App Risk Score**: Evaluates apps against 80+ risk factors including compliance certifications, data location, security measures, and vendor reputation (scored 0-10).

#### App Connectors
**What they are**: API-based connections to cloud apps that provide deep visibility and control. Require admin permissions to the target app.

**Connected Apps Examples**:
- Microsoft 365 (native integration)
- Salesforce, ServiceNow, Box, Dropbox
- AWS, Azure, GCP
- Slack, Zoom, GitHub

**API vs Log Collectors**: API connectors provide real-time, deep visibility and control. Log collectors analyze firewall/proxy logs for app discovery but provide less detail.

#### Conditional Access App Control
**What it is**: Integrates with Azure AD Conditional Access to provide real-time session monitoring and control for cloud apps, even those not natively supported.

**Use Cases**:
- Block downloads of sensitive data to unmanaged devices
- Protect on download (apply encryption/watermarks)
- Monitor user sessions for risky behavior
- Block copy/paste of sensitive information
- Block upload of unlabeled/sensitive documents

#### Information Protection
**Integration with**: Microsoft Purview Information Protection (formerly Azure Information Protection)

**Capabilities**:
- Automatically detect and classify sensitive data in cloud apps
- Apply protection policies based on sensitivity labels
- Scan files in cloud storage for sensitive content
- Control data sharing and external collaboration

#### Threat Detection
**Anomaly Detection**:
- Impossible travel (activity from geographically distant locations in short time)
- Activity from suspicious IP addresses (anonymous proxies, Tor, botnets)
- Unusual file downloads/sharing patterns
- Ransomware activity detection

**Activity Policies**: Define rules to trigger alerts or actions based on user activities (e.g., mass download detection, admin activity from risky locations).

---

## 3.7 Microsoft Defender for Identity

### Overview

**What it is**: Cloud-based security solution that leverages on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions.

**What it protects**: On-premises Active Directory and AD FS (Active Directory Federation Services)

**Architecture**:
- Sensor on domain controllers - lightweight agent that monitors domain controller traffic
- Cloud service - analyzes signals, detects threats, provides insights

### Key Capabilities

#### Identity Security Posture
**Assessments**:
- Identifies security weaknesses in AD configuration (weak passwords, exposed credentials, legacy protocols)
- Provides remediation recommendations for identity security issues
- Lateral movement path analysis to identify exposure
- Unsecure account attributes detection

#### Threat Detection
**Attacks Detected**:
- [x] Pass-the-hash - using stolen password hash for authentication
- [x] Pass-the-ticket - using stolen Kerberos ticket for authentication
- [x] Reconnaissance - attackers gathering information about the environment
- [x] Lateral movement - moving through network to access additional systems
- [x] Domain dominance - attempts to gain persistent admin access (Golden Ticket, DCSync)

#### Investigation
**Attack Timeline**: Visual representation of the attack kill chain showing sequence of suspicious activities, affected entities, and timeline.

**Lateral Movement Paths**: Shows potential paths attackers could use to move through network and compromise sensitive accounts, helping prioritize remediation.

#### Integration
**SIEM Integration**: Sends alerts to SIEM solutions via Syslog for centralized security monitoring.

**Microsoft 365 Defender Integration**: Alerts and data automatically shared with Microsoft 365 Defender portal for unified XDR experience and cross-domain incident correlation.

---

## 3.8 Microsoft Sentinel

### Overview

**What is Sentinel?**:
- SIEM: Security Information and Event Management - collects, analyzes, and correlates security data
- SOAR: Security Orchestration, Automation, and Response - automates incident response

**Cloud-Native Benefits**:
- Eliminate infrastructure overhead (no servers to manage)
- Scale elastically to handle data volume spikes
- Pay-as-you-go pricing model
- Rapid deployment and integration

### Architecture Components

#### Data Connectors

**What they are**: Pre-built integrations that ingest data from various sources into Sentinel for analysis. Enable connection to Microsoft and third-party solutions.

**Key Capability: Collect Data**

Azure Sentinel collects data at cloud scale from all users, devices, applications, and infrastructure—both on-premises and in multiple clouds. This provides the foundation for effective threat detection and response.

**Data Collection Methods**:

1. **Service-to-Service Connectors**
   - **How it works**: Direct API integration with Microsoft services (no agent required)
   - **Data flow**: Real-time streaming of logs and alerts directly to Sentinel workspace
   - **Examples**:
     * Microsoft 365 (audit logs, alerts)
     * Azure AD (sign-ins, audit logs, risky users)
     * Azure Activity (subscription-level operations)
     * Microsoft Defender products (all variants - Office, Endpoint, Identity, Cloud Apps)
   - **Benefits**: Instant connectivity, no infrastructure overhead, automatic schema mapping
   - **Setup**: One-click enablement through Sentinel portal

2. **Agent-Based Collection**
   - **Log Analytics Agent**:
     * Installed on Windows and Linux servers/VMs
     * Collects events from Windows Event Logs, Syslog, performance counters
     * Supports custom log files and IIS logs
     * Sends data to Log Analytics workspace that Sentinel uses
   - **Azure Monitor Agent (AMA)**:
     * Next-generation agent replacing Log Analytics agent
     * Better performance and easier management
     * Supports data collection rules for granular control
   - **Use cases**: On-premises servers, Azure VMs, hybrid environments

3. **Common Event Format (CEF) via Syslog**
   - **How it works**:
     * Third-party appliances send CEF-formatted logs via Syslog
     * Linux machine with Syslog daemon receives and forwards to Sentinel
     * Sentinel parses CEF format into structured data
   - **Supported appliances**:
     * Firewalls (Palo Alto, Check Point, Cisco ASA, Fortinet)
     * Proxies (Zscaler, Squid)
     * Security appliances (F5, Barracuda)
   - **Architecture**: Appliance → Syslog forwarder (Linux VM) → Sentinel

4. **Syslog**
   - **Standard Syslog format**: For devices that don't support CEF
   - **Examples**:
     * Linux servers
     * Network devices (routers, switches)
     * IoT devices
   - **Parsing**: May require custom parsers to structure the data

5. **External Platform Connectors**
   - **AWS CloudTrail**: API calls and account activity from AWS
   - **Google Cloud Platform**: Audit logs and security findings
   - **Data collection via API**: Pulls logs from cloud platforms
   - **Polling frequency**: Configurable based on requirements

6. **Custom Data Connectors**
   - **HTTP Data Collector API**:
     * Custom applications send JSON data via REST API
     * Flexible schema definition
     * Use case: Proprietary applications, custom security tools
   - **Logic Apps**:
     * Build custom connectors using Azure Logic Apps
     * Connect to services without native connectors
     * Schedule-based or trigger-based collection

**Data Ingestion Best Practices**:
- [x] Enable connectors for all critical data sources
- [x] Start with high-value data (identity logs, security alerts, firewall logs)
- [x] Monitor ingestion volume and costs (Sentinel pricing based on data volume)
- [x] Filter unnecessary data at source to reduce costs
- [x] Use data transformation rules to normalize formats
- [x] Configure appropriate log retention policies (90 days default, up to 12 years)

**Common Data Sources by Category**:

| Category | Data Sources | Purpose |
|----------|--------------|---------|
| **Identity** | Azure AD sign-ins, audit logs, risky users | Detect account compromise, suspicious sign-ins |
| **Endpoints** | Defender for Endpoint, Windows Security Events | Malware detection, process execution, file operations |
| **Email** | Defender for Office 365 | Phishing, malicious attachments, email threats |
| **Cloud Apps** | Defender for Cloud Apps, Office 365 activity | Data exfiltration, cloud app abuse, shadow IT |
| **Network** | Firewall logs, NSG flow logs, DNS logs | Lateral movement, C2 communication, data exfiltration |
| **Applications** | Application logs, IIS logs, custom apps | Application-level threats, abuse patterns |
| **Infrastructure** | Azure Activity, AWS CloudTrail, GCP Audit | Unauthorized changes, privilege escalation |

#### Workbooks
**What they are**: Interactive dashboards that visualize data from connected sources using Azure Monitor Workbooks. Provide insights and reporting.

**Use Cases**:
- Security operations overview dashboard
- Incident response metrics and trends
- Compliance reporting
- Threat intelligence visualization

#### Analytics Rules

**What they do**: Define logic to detect threats and generate alerts by analyzing ingested data. When triggered, create security alerts and incidents.

**Key Capability: Detect Threats**

Azure Sentinel uses built-in analytics and custom rules to detect threats across your entire environment. It minimizes false positives while ensuring real threats are identified quickly.

**Detection Approaches**:

1. **Scheduled Query Rules**
   - **How it works**:
     * Write KQL queries that run on a defined schedule (every 5 minutes to 14 days)
     * Query searches historical data in Log Analytics workspace
     * When query returns results, creates alert and/or incident
   - **Configuration**:
     * Query logic (KQL)
     * Entity mapping (identify users, IPs, hosts, etc.)
     * Alert grouping (group related alerts into single incident)
     * Alert threshold (number of results to trigger alert)
     * Query frequency and lookback period
   - **Example Rule**: "Detect brute force attack - 10+ failed logins from same IP in 5 minutes"
     ```kql
     SigninLogs
     | where ResultType != "0"
     | summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
     | where FailedAttempts >= 10
     ```
   - **Use cases**:
     * Custom detection logic for organization-specific threats
     * Detection based on known attack patterns
     * Compliance-based monitoring rules

2. **Microsoft Security Rules**
   - **How it works**:
     * Automatically imports alerts from connected Microsoft security services
     * No query writing needed
     * One rule can import all alerts from a specific service
   - **Supported services**:
     * Microsoft Defender for Cloud
     * Microsoft 365 Defender (includes Office 365, Endpoint, Identity, Cloud Apps)
     * Azure AD Identity Protection
     * Microsoft Defender for IoT
   - **Benefits**:
     * Instant detection without configuration
     * Leverage existing Microsoft security investments
     * Automatic updates as Microsoft adds new detections
   - **Example**: Create single rule to import all Defender for Endpoint alerts

3. **Fusion (Advanced Multistage Attack Detection)**
   - **How it works**:
     * Machine learning engine correlates low-fidelity signals from multiple sources
     * Identifies attack patterns spanning multiple stages (kill chain)
     * Reduces alert fatigue by connecting related weak signals into high-confidence incidents
   - **Detection scenarios**:
     * Multiple failed login attempts → successful login from anomalous location → mass file download
     * Anomalous Azure resource access → suspicious PowerShell execution → data exfiltration
     * Impossible travel → suspicious inbox manipulation → mass email deletion
   - **Key advantage**:
     * Detects sophisticated attacks that evade single-signal detection
     * No configuration required—automatically enabled
     * Learns and improves over time with ML
   - **Example detection**:
     * User travels impossibly (detected by Cloud Apps)
     * Then executes suspicious commands (detected by Defender for Endpoint)
     * Fusion correlates both as coordinated attack

4. **Anomaly Detection Rules**
   - **How it works**:
     * Machine learning establishes baselines of normal behavior
     * Automatically detects deviations from established patterns
     * Adapts to changing environment over time
   - **Detection types**:
     * Unusual user behavior (atypical access patterns, unusual resource usage)
     * Anomalous Azure activity (unusual VM creation, storage access)
     * Abnormal authentication patterns
     * Suspicious network connections
   - **Configuration**:
     * Thresholds adjustable for sensitivity
     * Initially in "flighting mode" to learn environment
     * Can tune based on false positives
   - **Benefits**:
     * Discovers unknown threats without pre-defined rules
     * Adapts to your specific environment
     * Reduces need for manual rule creation

5. **Near-Real-Time (NRT) Rules**
   - **How it works**:
     * Runs every minute for ultra-fast detection
     * Lower latency than scheduled rules (which run every 5+ minutes)
   - **Use cases**:
     * Time-sensitive threats requiring immediate response
     * Critical security events (admin account creation, privilege escalation)
   - **Limitations**:
     * 1-minute lookback period only
     * Cannot use certain KQL functions
     * Higher resource consumption

**Rule Templates**:
- **Built-in templates**: 250+ pre-built detection rules from Microsoft and partners
- **Categories**:
  * Initial Access (phishing, brute force)
  * Execution (malicious scripts, suspicious processes)
  * Persistence (new scheduled tasks, registry changes)
  * Privilege Escalation (admin role assignments)
  * Defense Evasion (log deletion, AV tampering)
  * Credential Access (password spray, credential dumping)
  * Discovery (account enumeration, network scanning)
  * Lateral Movement (remote execution, Pass-the-Hash)
  * Collection (data staging, email collection)
  * Exfiltration (large data transfers, unusual uploads)
  * Command & Control (C2 communication, beaconing)
  * Impact (data destruction, ransomware)

**MITRE ATT&CK Framework Integration**:
- All rules mapped to MITRE ATT&CK tactics and techniques
- View coverage across the attack lifecycle
- Identify gaps in detection capabilities
- Prioritize rule deployment based on relevant threats

**Detection Tuning Best Practices**:
- [x] Start with high-fidelity rules (low false positives)
- [x] Enable Microsoft security rules first (automatic, high quality)
- [x] Add scheduled rules for organization-specific threats
- [x] Use Fusion for advanced attack detection
- [x] Enable anomaly detection to discover unknown threats
- [x] Review rule performance regularly and tune thresholds
- [x] Suppress known false positives with automation rules
- [x] Test rules in test environment before production deployment

**Alert Quality Management**:
- **Alert enrichment**: Add context from threat intelligence, asset information, user data
- **Alert grouping**: Combine related alerts into single incident to reduce noise
- **Alert suppression**: Temporarily disable rules during maintenance or known issues
- **Tuning**: Adjust thresholds, add exceptions, refine queries based on results
- **Automation rules**: Auto-triage alerts, close false positives, assign to analysts

**Detection Metrics to Monitor**:
- Alert volume and trends over time
- False positive rate per rule
- Mean time to detect (MTTD)
- Alert-to-incident ratio
- Coverage across MITRE ATT&CK framework
- Rules triggering most frequently

#### Incidents & Investigations
**Incident**: Group of related alerts that together indicate a potential security event requiring investigation. Can contain alerts from multiple sources.

**Investigation Graph**: Visual representation showing entities involved in incident (users, IPs, devices) and relationships between them.

**Investigation Steps**:
1. Review incident details, severity, and associated alerts
2. Examine investigation graph to understand scope and relationships
3. Use hunting queries to gather additional context
4. Take response actions (manual or automated via playbooks)
5. Document findings and close incident

#### Automation (SOAR)
**Playbooks**:
- Based on Azure Logic Apps - workflow automation platform
- Automated response to incidents triggered by analytics rules
- Can include conditional logic and multi-step workflows

**Common Automation**:
- Send notifications (email, Teams, Slack)
- Block IP addresses at firewall/network level
- Isolate endpoints via Defender for Endpoint
- Create tickets in ServiceNow/JIRA
- Enrich alerts with threat intelligence
- Disable compromised user accounts

#### Threat Hunting
**What it is**: Proactively searching for threats that have evaded automated detection by writing custom queries against collected data.

**Kusto Query Language (KQL)**: Query language used to search and analyze log data in Sentinel.

**Hunting Queries**:
- Built-in queries - pre-written by Microsoft for common threats
- Custom queries - organization-specific threat hunting
- Can be saved and scheduled

**Bookmarks**: Save interesting results from hunting queries for later investigation or to include in incidents.

### UEBA (User and Entity Behavior Analytics)
**What it is**: Machine learning-based analytics that establishes behavioral baselines for users and entities, then detects anomalies that may indicate compromise.

**Use Cases**:
- Detect compromised accounts through unusual access patterns
- Identify insider threats via abnormal data access
- Detect lateral movement by analyzing entity relationships
- Anomalous resource usage patterns

### Threat Intelligence
**Integration**: Connect threat intelligence platforms (TIPs) to import indicators of compromise (IOCs) like malicious IPs, domains, file hashes.

**Use Cases**: Enrich alerts with threat context, create analytics rules based on IOCs, correlate internal events with external threat data.

---

## 3.9 Microsoft Secure Score

### Overview

**What it is**: A measurement of an organization's security posture across Microsoft 365, expressed as a number representing improvement actions completed vs. available. Higher score = better security.

**Where Available**:
- Microsoft 365 Defender portal (security.microsoft.com)
- Defender for Cloud (Azure security posture)
- Microsoft Entra (identity-specific score)

**Score Calculation**: (Your points achieved / Total available points) × 100 = Score percentage

### Improvement Actions

**Categories**:
- [x] Identity - MFA, password policies, privileged access
- [x] Device - Endpoint protection, device compliance, encryption
- [x] Apps - Application security, OAuth permissions, app governance
- [x] Data - DLP, information protection, retention policies

**Example Actions**:
- Enable MFA for all users (9 points)
- Turn on Microsoft Defender for Office 365 (8 points)
- Require managed devices for access (6 points)
- Enable safe attachments policy (5 points)
- Apply sensitivity labels to documents (4 points)

**Points System**:
- Each action has point value based on impact
- Implemented = points added to your score
- Some actions automatically scored, others require manual validation

### Best Practices
- Prioritize high-impact actions first (sorted by score impact)
- Use comparison tools to benchmark against similar organizations
- Review score history to track security posture trends over time
- Don't sacrifice usability - balance security with user productivity
- Document exceptions for actions marked "Risk accepted"

---

## 3.10 Azure Encryption

### Overview

**Encryption Purpose**: Protects data confidentiality by converting readable data (plaintext) into unreadable format (ciphertext) that can only be accessed with the correct decryption key.

**Azure Encryption Layers**: Azure provides multiple encryption options to protect data at different stages and locations.

### Encryption at Rest

**What it is**: Protects data stored on physical media (disks, databases, storage accounts) by encrypting it when saved.

**Azure Storage Service Encryption (SSE)**:
- **Automatic**: Enabled by default for all Azure Storage accounts (cannot be disabled)
- **Scope**: Encrypts all data in Blob, File, Queue, and Table storage
- **Key Management**: Microsoft-managed keys by default, or customer-managed keys in Azure Key Vault
- **Algorithm**: AES 256-bit encryption
- **No Performance Impact**: Encryption/decryption handled transparently

**Azure Disk Encryption**:
- **For VMs**: Encrypts OS and data disks of Azure virtual machines
- **Windows**: Uses BitLocker
- **Linux**: Uses dm-crypt
- **Integration**: Keys stored in Azure Key Vault
- **Use Case**: Compliance requirements, protect data on VM disks

**Azure SQL Database Transparent Data Encryption (TDE)**:
- **What it does**: Automatically encrypts database files, backups, and transaction logs at rest
- **Real-time**: Encryption/decryption happens automatically without application changes
- **Enabled by default**: All new Azure SQL databases
- **Key options**: Service-managed or customer-managed (Bring Your Own Key - BYOK)

### Encryption in Transit

**What it is**: Protects data while moving between locations (over networks) to prevent interception or tampering.

**Transport Layer Security (TLS)**:
- **Default Protocol**: All Azure services support TLS 1.2+ for secure communication
- **HTTPS**: Web traffic to Azure services encrypted by default
- **Application**: Portal access, API calls, service-to-service communication

**VPN Encryption**:
- **Azure VPN Gateway**: Encrypts traffic between on-premises networks and Azure (IPsec/IKE protocols)
- **Point-to-Site VPN**: Encrypts connections from individual devices to Azure (SSTP, OpenVPN, IKEv2)
- **Site-to-Site VPN**: Encrypted tunnel between on-premises network and Azure VNet

**Azure ExpressRoute**:
- **Private Connection**: Doesn't traverse public internet (inherently more secure)
- **Optional Encryption**: Can add IPsec VPN over ExpressRoute for additional encryption layer
- **MACsec**: Media Access Control Security for Layer 2 encryption on ExpressRoute Direct

### Key Management

**Azure Key Vault**:
- **Centralized Secrets Management**: Store and control access to encryption keys, certificates, secrets, and passwords
- **Hardware Security Modules (HSMs)**: Premium tier uses FIPS 140-2 Level 2 validated HSMs
- **Key Rotation**: Supports automated key rotation for compliance
- **Access Control**: Integration with Azure RBAC and access policies
- **Auditing**: All key access logged for compliance monitoring

**Key Management Options**:

| Option | Who Manages | Control Level | Compliance |
|--------|-------------|---------------|------------|
| **Microsoft-managed keys** | Microsoft | Low (automatic) | Standard compliance |
| **Customer-managed keys (CMK)** | Customer via Key Vault | High (full control) | Enhanced compliance, BYOK |
| **Customer-provided keys** | Customer (not stored in Azure) | Highest (keys never leave customer) | Maximum compliance |

**Azure Dedicated HSM**:
- **FIPS 140-2 Level 3**: Higher security than Key Vault Premium
- **Single-tenant**: Dedicated hardware for customer use only
- **Full Control**: Customer has complete administrative control
- **Use Case**: Highly regulated industries, specific compliance requirements

### Encryption Features by Service

**Azure Storage**:
- [x] Encryption at rest (automatic with SSE)
- [x] Encryption in transit (TLS for all connections)
- [x] Client-side encryption (encrypt before uploading)
- [x] Infrastructure encryption (double encryption - both service and infrastructure layers)

**Azure Virtual Machines**:
- [x] Azure Disk Encryption (BitLocker/dm-crypt)
- [x] Encryption at host (encrypts temp disks and OS/data disk caches)
- [x] Server-side encryption of managed disks
- [x] Confidential computing (encrypts data in use with secure enclaves)

**Azure SQL/Databases**:
- [x] Transparent Data Encryption (TDE) for data at rest
- [x] Always Encrypted (column-level encryption, data encrypted in client applications)
- [x] TLS encryption for connections
- [x] Dynamic Data Masking (limits sensitive data exposure to non-privileged users)

**Azure Backup**:
- [x] Backup data encrypted at rest automatically
- [x] Passphrase-based encryption for additional protection
- [x] Encrypted during transfer to Azure

### Double Encryption

**What it is**: Applies two layers of encryption to protect against scenarios where one encryption layer might be compromised.

**Azure Storage Infrastructure Encryption**:
- **Layer 1**: Service-level encryption (SSE) at the storage service layer
- **Layer 2**: Infrastructure encryption at the platform layer below the service
- **Different Keys**: Uses different encryption keys for each layer
- **Use Case**: Compliance requirements demanding defense-in-depth encryption strategy

### Encryption in Use (Confidential Computing)

**What it is**: Protects data while it's being processed in memory (not just at rest or in transit).

**Azure Confidential Computing**:
- **Technology**: Uses hardware-based Trusted Execution Environments (TEEs) like Intel SGX
- **Secure Enclaves**: Data processed in isolated, encrypted memory regions
- **Protection**: Even cloud administrators cannot access data being processed
- **Use Cases**: Processing highly sensitive data (healthcare, financial services, government)

**Confidential VMs**:
- Encrypts entire VM memory using AMD SEV-SNP technology
- Protects workloads from cloud operator access
- Supports lift-and-shift of sensitive workloads to cloud

### Best Practices

**Encryption Strategy**:
1. Use encryption at rest for all stored data (enabled by default in most Azure services)
2. Enforce encryption in transit (require TLS 1.2+, disable older protocols)
3. Consider customer-managed keys for regulatory compliance requirements
4. Implement key rotation policies for enhanced security
5. Use Azure Policy to enforce encryption requirements across subscriptions
6. Audit and monitor key access through Azure Monitor and Key Vault logs

**Compliance Considerations**:
- GDPR: Requires encryption of personal data
- HIPAA: Mandates encryption for healthcare data
- PCI DSS: Requires encryption of cardholder data
- Many regulations require customer control over encryption keys (CMK)

### Azure Policy for Encryption

**Enforce Encryption**: Use Azure Policy to:
- Require storage accounts to use customer-managed keys
- Audit unencrypted storage accounts
- Enforce TLS 1.2 minimum version
- Require disk encryption on VMs
- Deny deployment of resources without encryption

**Example Policies**:
- "Storage accounts should use customer-managed key for encryption"
- "Virtual machines should encrypt temp disks, caches, and data flows"
- "Transparent Data Encryption on SQL databases should be enabled"

---

## Comparison Tables

### Microsoft Defender Products Overview

| Product | Protects | Key Feature | License |
|---------|----------|-------------|---------|
| **Defender for Office 365** | Email & collaboration | Safe Attachments/Links, anti-phishing | Microsoft 365 E5 or add-on |
| **Defender for Endpoint** | Devices/endpoints | EDR, vulnerability management, ASR | Microsoft 365 E5 or standalone |
| **Defender for Identity** | On-prem Active Directory | Detects identity attacks, lateral movement | Microsoft 365 E5 or standalone |
| **Defender for Cloud Apps** | Cloud applications | CASB, cloud discovery, app control | Microsoft 365 E5 or standalone |
| **Defender for Cloud** | Azure/hybrid/multi-cloud | CSPM, workload protection plans | Free CSPM, paid workload plans |

### SIEM vs SOAR

| Feature | SIEM | SOAR |
|---------|------|------|
| **Primary Function** | Collect, analyze, correlate security data | Orchestrate and automate response |
| **Key Activities** | Log aggregation, threat detection, alerting | Workflow automation, playbook execution |
| **Sentinel Feature** | Analytics rules, workbooks, hunting | Playbooks (Azure Logic Apps), automation |

---

## Practice Questions

### Azure Network Security

#### Question 1: DDoS Protection
**Q**: Your organization hosts a mission-critical e-commerce application on Azure with public IPs. You need advanced DDoS protection with real-time attack metrics and access to the DDoS Rapid Response team. Which Azure DDoS Protection tier should you implement?

**Answer**: Azure DDoS Protection Standard
**Explanation**: DDoS Protection Standard provides infrastructure + application layer protection, real-time attack metrics, access to the DDoS Rapid Response team, and cost protection for resource scaling. The Basic tier only provides infrastructure layer (L3/L4) protection without advanced monitoring or support.

#### Question 2: Azure Firewall vs NSG
**Q**: You need to filter outbound traffic from multiple Azure virtual networks based on fully qualified domain names (FQDNs) and block traffic to known malicious IPs. Should you use Network Security Groups or Azure Firewall?

**Answer**: Azure Firewall
**Explanation**: Azure Firewall supports FQDN filtering, threat intelligence-based filtering, and centralized management across multiple VNets. NSGs only support Layer 3-4 filtering with IP addresses, ports, and protocols—they cannot filter by FQDN or use threat intelligence.

#### Question 3: Web Application Firewall
**Q**: Your company deploys a web application that handles credit card transactions. You need protection against SQL injection and cross-site scripting attacks. Which Azure service should you deploy?

**Answer**: Web Application Firewall (WAF)
**Explanation**: WAF provides Layer 7 (application layer) protection specifically designed to protect web applications from OWASP Top 10 vulnerabilities including SQL injection and XSS. It can be deployed on Azure Application Gateway, Azure Front Door, or Azure CDN.

#### Question 4: Azure Bastion
**Q**: Which statement about Azure Bastion is correct?
A) Requires public IP addresses on target VMs
B) Requires installing RDP/SSH client software
C) Provides connectivity through the Azure portal over SSL (port 443)
D) Requires you to manage and patch bastion host servers

**Answer**: C) Provides connectivity through the Azure portal over SSL (port 443)
**Explanation**: Azure Bastion is a fully managed PaaS service that provides secure RDP/SSH connectivity through the Azure portal over SSL without requiring public IPs on VMs, without client software, and without managing infrastructure.

#### Question 5: NSG Rules
**Q**: You create two NSG rules: Rule 1 has priority 200 and denies RDP traffic, Rule 2 has priority 150 and allows RDP traffic. What happens when RDP traffic arrives?

**Answer**: RDP traffic is allowed
**Explanation**: NSG rules are processed by priority where lower numbers = higher priority. Rule 2 (priority 150) is evaluated first and allows the traffic. Processing stops after the first matching rule, so Rule 1 is never evaluated.

### Microsoft Defender for Cloud

#### Question 6: CSPM vs CWPP
**Q**: Which of the following requires paid Defender plans in Microsoft Defender for Cloud?
A) Security recommendations
B) Secure Score
C) Compliance dashboard
D) Threat protection for SQL databases

**Answer**: D) Threat protection for SQL databases
**Explanation**: CSPM features (security recommendations, Secure Score, compliance dashboard) are FREE. CWPP features that provide threat protection for specific workloads like SQL, containers, servers, etc. require paid Defender plans.

#### Question 7: Secure Score Calculation
**Q**: Your organization has 100 total available security points in Defender for Cloud. You've implemented recommendations worth 65 points. What is your Secure Score percentage?

**Answer**: 65%
**Explanation**: Secure Score = (Points achieved / Total available points) × 100 = (65/100) × 100 = 65%

#### Question 8: Just-in-Time VM Access
**Q**: What is the primary benefit of Just-in-Time (JIT) VM Access in Defender for Cloud?

**Answer**: Reduces exposure to brute force attacks by limiting time windows for management port access
**Explanation**: JIT VM Access blocks persistent access to management ports (RDP 3389, SSH 22) and only opens them when needed, for a limited time, from specific IP addresses. This significantly reduces the attack surface for brute force attacks.

#### Question 9: Defender Plans
**Q**: Which Defender for Cloud plan provides runtime threat detection and vulnerability scanning for containerized workloads in Azure Kubernetes Service (AKS)?

**Answer**: Defender for Containers (formerly Defender for Kubernetes)
**Explanation**: Defender for Containers provides comprehensive container security including runtime threat detection, vulnerability scanning, and policy enforcement for Kubernetes workloads.

#### Question 10: Security Alerts
**Q**: You receive a security alert in Defender for Cloud with severity level "High". What does this indicate?

**Answer**: Immediate action required; definite malicious activity detected
**Explanation**: High severity alerts indicate confirmed malicious activity requiring immediate investigation and response. Medium = suspicious activity, Low = potentially malicious, Informational = security-relevant info without direct threat indication.

### Microsoft 365 Defender

#### Question 11: XDR Platform
**Q**: What does XDR stand for in the context of Microsoft 365 Defender, and what is its primary purpose?

**Answer**: Extended Detection and Response - automatically collects, correlates, and analyzes threat data from multiple sources (endpoints, identities, email, apps) to provide comprehensive attack visibility
**Explanation**: XDR goes beyond traditional EDR by correlating signals across multiple domains (email, endpoints, identities, cloud apps) to detect sophisticated multi-stage attacks that might evade single-domain detection.

#### Question 12: Microsoft 365 Defender Portal
**Q**: Where do you access the unified Microsoft 365 Defender portal?

**Answer**: https://security.microsoft.com
**Explanation**: The Microsoft 365 Defender portal at security.microsoft.com provides unified access to incidents, alerts, hunting, threat analytics, and secure score across all Microsoft 365 Defender products.

#### Question 13: Incident Management
**Q**: How does Microsoft 365 Defender handle alerts from different products (e.g., Defender for Endpoint and Defender for Office 365)?

**Answer**: Automatically correlates related alerts into a single incident
**Explanation**: Microsoft 365 Defender's incident management automatically groups related alerts from different products into unified incidents, providing a complete picture of an attack and enabling coordinated response.

### Microsoft Defender for Office 365

#### Question 14: Safe Attachments
**Q**: An email arrives with a PDF attachment. What happens when Safe Attachments is enabled with the "Block" action?

**Answer**: The attachment is opened in an isolated virtual environment (sandbox), behavior is analyzed, and if malicious, the email is blocked before delivery
**Explanation**: Safe Attachments uses a detonation chamber to execute attachments in isolation, analyzing file operations, registry changes, and network calls to detect malicious behavior before delivering to users.

#### Question 15: Plan 1 vs Plan 2
**Q**: Which feature is only available in Defender for Office 365 Plan 2?
A) Safe Attachments
B) Safe Links
C) Threat Explorer
D) Anti-phishing

**Answer**: C) Threat Explorer
**Explanation**: Plan 1 includes Safe Attachments, Safe Links, and anti-phishing. Plan 2 adds advanced features like Threat Explorer, Automated Investigation & Response (AIR), and threat hunting capabilities.

#### Question 16: Safe Links Time-of-Click
**Q**: Why is time-of-click protection in Safe Links important?

**Answer**: It scans URLs every time they're clicked, protecting against links that become malicious after email delivery
**Explanation**: Attackers often use legitimate URLs initially, then weaponize them later to bypass security scans at delivery time. Time-of-click protection verifies URL safety at every click.

#### Question 17: Anti-Phishing
**Q**: Which Defender for Office 365 anti-phishing feature uses AI to learn normal communication patterns and detect anomalies?

**Answer**: Mailbox intelligence
**Explanation**: Mailbox intelligence uses machine learning to understand typical email patterns for each user and detects anomalous communications that may indicate phishing or business email compromise.

#### Question 18: Attack Simulation Training
**Q**: What is the purpose of Attack Simulation Training in Defender for Office 365?

**Answer**: Simulate realistic phishing and attack scenarios to train users to recognize and report threats
**Explanation**: Attack Simulation Training allows organizations to run simulated phishing, password spray, and brute force attacks, then provide targeted training to users who fall for the simulations.

### Microsoft Defender for Endpoint

#### Question 19: Supported Platforms
**Q**: Which platforms are supported by Microsoft Defender for Endpoint? (Select all that apply)
A) Windows 10/11
B) macOS
C) Linux
D) iOS
E) Android

**Answer**: All of the above (A, B, C, D, E)
**Explanation**: Defender for Endpoint supports Windows (10/11 and Server 2012 R2+), macOS (last 3 releases), Linux (multiple distributions), iOS, and Android for comprehensive cross-platform protection.

#### Question 20: Attack Surface Reduction
**Q**: What is the purpose of Attack Surface Reduction (ASR) rules in Defender for Endpoint?

**Answer**: Prevent actions and behaviors commonly used by malware to compromise devices
**Explanation**: ASR rules block specific behaviors like executable content from email, Office apps creating child processes, and credential theft from lsass.exe—proactively preventing exploitation techniques.

#### Question 21: EDR Capabilities
**Q**: What are the three core capabilities that enable Endpoint Detection and Response (EDR)?

**Answer**: Behavioral sensors, cloud analytics, and threat intelligence
**Explanation**: EDR combines behavioral sensors (monitoring OS activities), cloud analytics (big data analysis), and threat intelligence (known attacker tools/techniques) to detect and respond to advanced threats.

#### Question 22: Advanced Hunting
**Q**: Which query language is used for advanced hunting in Microsoft Defender for Endpoint?

**Answer**: Kusto Query Language (KQL)
**Explanation**: KQL is the query language used across Microsoft security products (Defender for Endpoint, Sentinel, etc.) for threat hunting and log analysis.

#### Question 23: Threat & Vulnerability Management
**Q**: Does Threat & Vulnerability Management in Defender for Endpoint require additional agents?

**Answer**: No, it's built-in with no additional agents needed
**Explanation**: Threat & Vulnerability Management is a built-in capability that uses the existing Defender for Endpoint agent to continuously discover vulnerabilities and misconfigurations without requiring separate vulnerability scanners.

#### Question 24: Intune Integration
**Q**: How can Defender for Endpoint integrate with Microsoft Intune?

**Answer**: Device risk levels from Defender can be used in Intune compliance policies to block risky devices from accessing corporate resources
**Explanation**: The integration enables conditional access based on device threat level, allowing organizations to enforce that only compliant, low-risk devices can access corporate data.

### Microsoft Defender for Cloud Apps

#### Question 25: CASB Definition
**Q**: What does CASB stand for, and what is its primary function?

**Answer**: Cloud Access Security Broker - a security solution that sits between users and cloud services to provide visibility, data security, threat protection, and compliance
**Explanation**: CASB provides a control point for cloud application security, addressing the four pillars: visibility (including shadow IT), data security, threat protection, and compliance.

#### Question 26: Shadow IT
**Q**: What is "shadow IT" and how does Defender for Cloud Apps help address it?

**Answer**: Shadow IT refers to cloud services used without IT approval/knowledge. Cloud Discovery analyzes traffic logs to identify all cloud apps being used, including unsanctioned ones
**Explanation**: Shadow IT creates security risks because unapproved apps may not meet security/compliance standards. Cloud Discovery provides visibility into all cloud app usage for risk assessment.

#### Question 27: App Risk Score
**Q**: How many risk factors does Defender for Cloud Apps evaluate when calculating an app's risk score?

**Answer**: 80+ risk factors including compliance certifications, data location, security measures, and vendor reputation (scored 0-10)
**Explanation**: The comprehensive risk scoring helps organizations make informed decisions about which cloud apps to approve or block based on detailed security and compliance assessments.

#### Question 28: Conditional Access App Control
**Q**: Your organization wants to allow users to access a SaaS application but prevent them from downloading sensitive files to unmanaged devices. Which Defender for Cloud Apps feature should you use?

**Answer**: Conditional Access App Control
**Explanation**: Conditional Access App Control integrates with Azure AD Conditional Access to provide real-time session monitoring and control, including blocking downloads to unmanaged devices while still allowing app access.

#### Question 29: Anomaly Detection
**Q**: Which of the following is an example of anomaly detection in Defender for Cloud Apps?
A) Impossible travel
B) SQL injection
C) Malware in email
D) Failed login attempts

**Answer**: A) Impossible travel
**Explanation**: Impossible travel (activity from geographically distant locations in an impossibly short time) is a behavioral anomaly. It also detects suspicious IPs, unusual file downloads, and ransomware activity patterns.

#### Question 30: App Connectors
**Q**: What is the difference between API connectors and log collectors in Defender for Cloud Apps?

**Answer**: API connectors provide real-time, deep visibility and control. Log collectors analyze firewall/proxy logs for app discovery but provide less detail
**Explanation**: API connectors require admin permissions and offer comprehensive monitoring and control. Log collectors are useful for discovery but provide limited visibility compared to API connections.

### Microsoft Defender for Identity

#### Question 31: What It Protects
**Q**: Which environment does Microsoft Defender for Identity primarily protect?

**Answer**: On-premises Active Directory and AD FS
**Explanation**: Defender for Identity is specifically designed to protect on-premises Active Directory by monitoring domain controller traffic and detecting identity-based attacks. For cloud identities, use Azure AD Identity Protection.

#### Question 32: Architecture
**Q**: How is Microsoft Defender for Identity deployed?

**Answer**: Lightweight sensor on domain controllers + cloud service for analysis
**Explanation**: The architecture consists of sensors installed on domain controllers that monitor traffic and send signals to a cloud service that analyzes the data, detects threats, and provides insights.

#### Question 33: Attack Detection
**Q**: Which of the following attacks can Defender for Identity detect? (Select all that apply)
A) Pass-the-hash
B) DDoS attack
C) Lateral movement
D) Golden Ticket
E) Ransomware

**Answer**: A, C, D (Pass-the-hash, Lateral movement, Golden Ticket)
**Explanation**: Defender for Identity specializes in identity-based attacks: pass-the-hash, pass-the-ticket, reconnaissance, lateral movement, and domain dominance attacks like Golden Ticket and DCSync. DDoS and ransomware are detected by other Defender products.

#### Question 34: Lateral Movement Paths
**Q**: What is the purpose of the Lateral Movement Paths feature in Defender for Identity?

**Answer**: Shows potential paths attackers could use to move through the network and compromise sensitive accounts
**Explanation**: Lateral Movement Paths provide visual representation of attack paths, helping security teams prioritize remediation of accounts and systems that, if compromised, could lead to broader network compromise.

#### Question 35: SIEM Integration
**Q**: How can Defender for Identity alerts be sent to third-party SIEM solutions?

**Answer**: Via Syslog
**Explanation**: Defender for Identity can send alerts to SIEM solutions via Syslog for centralized security monitoring and correlation with other security events.

### Microsoft Sentinel

#### Question 36: SIEM + SOAR
**Q**: What do SIEM and SOAR stand for, and how does Microsoft Sentinel combine both?

**Answer**: SIEM = Security Information and Event Management (collects/analyzes data); SOAR = Security Orchestration, Automation, and Response (automates response). Sentinel provides both capabilities in one platform
**Explanation**: Sentinel acts as both SIEM (analytics rules, workbooks, hunting) and SOAR (playbooks for automated response), providing comprehensive security operations capabilities.

#### Question 37: Data Connectors
**Q**: Which type of Sentinel data connector provides direct API integration with Microsoft services without requiring agents?

**Answer**: Service-to-service connectors
**Explanation**: Service-to-service connectors use direct API integration for Microsoft services like Microsoft 365, Azure AD, and Defender products. External solutions use CEF/Syslog, and agent-based connectors use the Log Analytics agent.

#### Question 38: Analytics Rules - Fusion
**Q**: What makes Fusion analytics rules unique in Microsoft Sentinel?

**Answer**: ML-based correlation that detects multi-stage attacks across multiple data sources
**Explanation**: Fusion uses machine learning to correlate low-fidelity signals from different sources to identify sophisticated multi-stage attacks that would be missed by single-signal detection.

#### Question 39: Workbooks
**Q**: What is the purpose of workbooks in Microsoft Sentinel?

**Answer**: Interactive dashboards that visualize data from connected sources for insights and reporting
**Explanation**: Workbooks (based on Azure Monitor Workbooks) provide visual representation of security data for security operations overview, incident metrics, compliance reporting, and threat intelligence visualization.

#### Question 40: Playbooks
**Q**: What Azure service are Microsoft Sentinel playbooks based on?

**Answer**: Azure Logic Apps
**Explanation**: Playbooks use Azure Logic Apps to automate incident response workflows, including sending notifications, blocking IPs, isolating endpoints, creating tickets, and enriching alerts with threat intelligence.

#### Question 41: KQL
**Q**: You want to proactively search for threats in Microsoft Sentinel by writing custom queries. What query language should you use?

**Answer**: Kusto Query Language (KQL)
**Explanation**: KQL is the query language used in Sentinel for threat hunting, analytics rules, and log analysis. It's also used across other Microsoft security products for consistency.

#### Question 42: Investigation Graph
**Q**: What does the Investigation Graph in Sentinel display?

**Answer**: Visual representation showing entities involved in an incident (users, IPs, devices) and their relationships
**Explanation**: The Investigation Graph helps security analysts understand the scope and connections between different entities in a security incident, making it easier to identify the full extent of an attack.

#### Question 43: UEBA
**Q**: What does UEBA stand for and what does it do in Microsoft Sentinel?

**Answer**: User and Entity Behavior Analytics - uses machine learning to establish behavioral baselines and detect anomalies that may indicate compromise
**Explanation**: UEBA helps detect compromised accounts, insider threats, lateral movement, and unusual resource usage by identifying deviations from normal behavior patterns.

#### Question 44: Threat Intelligence
**Q**: How can Microsoft Sentinel use threat intelligence?

**Answer**: Import IOCs (indicators of compromise) like malicious IPs, domains, and file hashes to enrich alerts and create analytics rules
**Explanation**: Threat intelligence integration allows Sentinel to correlate internal events with external threat data, identify known bad actors, and automate responses to known threats.

#### Question 45: Cloud-Native Benefits
**Q**: Which of the following is a benefit of Sentinel being cloud-native? (Select all that apply)
A) No infrastructure to manage
B) Elastic scaling
C) Pay-as-you-go pricing
D) Requires on-premises servers

**Answer**: A, B, C (No infrastructure to manage, Elastic scaling, Pay-as-you-go pricing)
**Explanation**: As a cloud-native SIEM/SOAR, Sentinel eliminates infrastructure overhead, scales elastically to handle data volume spikes, and uses a consumption-based pricing model. It does NOT require on-premises servers.

### Microsoft Secure Score

#### Question 46: Secure Score Definition
**Q**: What does Microsoft Secure Score measure?

**Answer**: An organization's security posture expressed as a percentage of completed security improvement actions vs. available actions
**Explanation**: Secure Score = (Points achieved / Total available points) × 100. Higher score indicates better security posture across Microsoft 365, Azure (Defender for Cloud), and Microsoft Entra.

#### Question 47: Score Locations
**Q**: Where can you view Microsoft Secure Score? (Select all that apply)
A) Microsoft 365 Defender portal
B) Azure portal
C) Defender for Cloud
D) Microsoft Entra

**Answer**: A, C, D (Microsoft 365 Defender portal, Defender for Cloud, Microsoft Entra)
**Explanation**: Secure Score is available in multiple locations: Microsoft 365 Defender portal (security.microsoft.com) for M365 security, Defender for Cloud for Azure security posture, and Microsoft Entra for identity-specific score.

#### Question 48: Improvement Actions Categories
**Q**: Secure Score improvement actions are organized into which four categories?

**Answer**: Identity, Device, Apps, and Data
**Explanation**: The four categories cover comprehensive security: Identity (MFA, password policies), Device (endpoint protection, compliance), Apps (application security, permissions), and Data (DLP, information protection, retention).

#### Question 49: High-Value Action
**Q**: Which improvement action typically has one of the highest point values in Microsoft Secure Score?

**Answer**: Enable MFA for all users (9 points)
**Explanation**: MFA is one of the most impactful security controls, protecting against password-based attacks. Other high-value actions include enabling Defender products and requiring managed devices.

#### Question 50: Best Practice
**Q**: Your organization's Secure Score is lower than similar organizations. What should you do first?

**Answer**: Prioritize high-impact actions first (sorted by score impact)
**Explanation**: Focus on actions with the highest point values and security impact first. Also use comparison tools to benchmark, review score history for trends, and balance security with usability—don't sacrifice user productivity.

### Cross-Product Scenarios

#### Question 51: Multi-Product Detection
**Q**: A user's password is compromised. An attacker logs in from an unusual location, accesses sensitive SharePoint files, and attempts lateral movement in your on-premises network. Which Defender products would detect these activities?

**Answer**: Defender for Identity (lateral movement), Defender for Cloud Apps (suspicious access to SharePoint), Azure AD Identity Protection (sign-in from unusual location)
**Explanation**: This scenario demonstrates XDR value—multiple Defender products detect different attack stages, with Microsoft 365 Defender correlating them into a unified incident.

#### Question 52: Email to Endpoint
**Q**: A phishing email with a malicious attachment reaches a user, who downloads and executes it. The malware attempts to steal credentials. Which Defender products provide protection at each stage?

**Answer**: Defender for Office 365 (Safe Attachments blocks email), Defender for Endpoint (EDR detects execution, ASR rules block credential theft)
**Explanation**: Layered defense: Office 365 should catch the email, but if it reaches the user, Endpoint protects the device, and Identity/Cloud Apps can detect abnormal behavior from compromised credentials.

#### Question 53: Cloud App to Sentinel
**Q**: Defender for Cloud Apps detects impossible travel for a user. You want this to automatically trigger a Sentinel investigation and create a ServiceNow ticket. How do you accomplish this?

**Answer**: Connect Defender for Cloud Apps to Sentinel via data connector, create analytics rule to detect impossible travel alerts, configure playbook to investigate and create ServiceNow ticket
**Explanation**: This demonstrates Sentinel's SOAR capabilities—ingesting alerts from other products, applying additional detection logic, and orchestrating automated response across multiple systems.

#### Question 54: Compliance Across Products
**Q**: Your organization needs to demonstrate compliance with PCI DSS. Which Microsoft security products can help track compliance? (Select all that apply)
A) Defender for Cloud
B) Microsoft Purview
C) Defender for Office 365
D) Microsoft Secure Score

**Answer**: A, B, D (Defender for Cloud, Microsoft Purview, Microsoft Secure Score)
**Explanation**: Defender for Cloud has a compliance dashboard with PCI DSS standards, Microsoft Purview provides compliance and data governance, and Secure Score includes compliance-related improvement actions. Defender for Office 365 provides security but not compliance tracking.

#### Question 55: Licensing Question
**Q**: Your organization wants Defender for Office 365 Plan 2, Defender for Endpoint, Defender for Identity, and Defender for Cloud Apps. Which license provides all of these?

**Answer**: Microsoft 365 E5
**Explanation**: Microsoft 365 E5 includes all four Defender products with advanced features. Alternatively, these can be purchased as standalone licenses, but E5 provides the most comprehensive bundle.

---

## Key Terms Glossary

| Term | Definition |
|------|------------|
| DDoS | Distributed Denial of Service - attack that overwhelms systems with traffic |
| WAF | Web Application Firewall - Layer 7 firewall protecting web apps |
| NSG | Network Security Group - Azure virtual firewall for subnet/NIC level filtering |
| CASB | Cloud Access Security Broker - security layer between users and cloud services |
| XDR | Extended Detection and Response - unified threat detection across multiple domains |
| EDR | Endpoint Detection and Response - advanced endpoint threat detection and investigation |
| SIEM | Security Information and Event Management - log aggregation and threat detection |
| SOAR | Security Orchestration, Automation, and Response - automated incident response |
| UEBA | User and Entity Behavior Analytics - ML-based anomaly detection |
| KQL | Kusto Query Language - query language for log analytics and hunting |
| ASR | Attack Surface Reduction - rules to prevent common malware behaviors |
| AIR | Automated Investigation and Response - automated threat remediation |
| CSPM | Cloud Security Posture Management - assess and improve cloud security configuration |
| CWPP | Cloud Workload Protection Platform - threat protection for specific cloud workloads |

---

## Visual Summary

### Microsoft 365 Defender Stack
```
┌─────────────────────────────────────┐
│    Microsoft 365 Defender Portal    │
│         (Unified XDR)               │
├─────────────────────────────────────┤
│  Defender    │  Defender  │ Defender│
│  for Office  │    for     │   for   │
│     365      │  Endpoint  │ Identity│
├──────────────┴────────────┴─────────┤
│      Defender for Cloud Apps        │
└─────────────────────────────────────┘
```

### Sentinel Workflow
```
Data Sources → Connectors → Analytics → Incidents → Investigation → Response
                              ↓
                         Workbooks
                              ↓
                        Threat Hunting
```



