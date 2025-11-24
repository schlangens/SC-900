# SC-900: Microsoft Security, Compliance, and Identity Fundamentals
## Comprehensive Practice Exams

**Exam Overview**:
- **Number of questions**: 40-60 questions
- **Duration**: 60 minutes
- **Passing score**: 700/1000 (approximately 70%)
- **Question types**: Multiple choice, multiple select, drag-and-drop, scenario-based
- **Language**: Available in multiple languages

**Module Weight Distribution**:
- Module 1: Identity and Access Management (25-30%)
- Module 2: Security, Compliance, and Identity Concepts (5-10%)
- Module 3: Microsoft Security Solutions (30-35%)
- Module 4: Microsoft Compliance Solutions (25-30%)

---

## Practice Exam 1: Full SC-900 Simulation (50 Questions)

### Module 1: Identity and Access Management (13 questions)

#### Question 1
Which authentication method provides the strongest security against phishing attacks?
- A) SMS text message
- B) Microsoft Authenticator (notification mode)
- C) Security key (FIDO2)
- D) Voice call

**Correct Answer**: C
**Explanation**: FIDO2 security keys are phishing-resistant because they use cryptographic challenge-response authentication tied to the origin, making them immune to phishing sites.

#### Question 2
Your organization wants users to sign in once and access all cloud and on-premises applications without re-entering credentials. What should you implement?
- A) Multi-factor authentication
- B) Single Sign-On (SSO)
- C) Conditional Access
- D) Password hash synchronization

**Correct Answer**: B
**Explanation**: SSO allows users to authenticate once and access multiple applications without repeated sign-ins, improving user experience and security.

#### Question 3
What is the primary difference between authentication and authorization?
- A) Authentication verifies identity, authorization determines access permissions
- B) Authorization verifies identity, authentication determines permissions
- C) They are the same thing
- D) Authentication is for users, authorization is for devices

**Correct Answer**: A
**Explanation**: Authentication proves who you are (identity verification), authorization determines what you can do (access rights).

#### Question 4
Which Azure AD feature allows you to require MFA only when users sign in from outside the corporate network?
- A) Identity Protection
- B) Conditional Access
- C) Privileged Identity Management
- D) Access Reviews

**Correct Answer**: B
**Explanation**: Conditional Access policies can evaluate conditions like location, device state, and risk level to dynamically enforce controls like MFA.

#### Question 5
A user is signing in from an unusual location with impossible travel detected. Which Azure AD feature would detect this?
- A) Azure AD Connect
- B) Azure AD Identity Protection
- C) Azure AD Domain Services
- D) Azure AD B2C

**Correct Answer**: B
**Explanation**: Identity Protection uses ML to detect risk events like impossible travel, leaked credentials, and anonymous IP addresses.

#### Question 6
What type of identity would you use for a mobile application that needs to authenticate to Azure resources?
- A) User identity
- B) Group identity
- C) Service principal (application identity)
- D) Device identity

**Correct Answer**: C
**Explanation**: Service principals (application identities) are used for applications and services to authenticate and access resources without user credentials.

#### Question 7
Which Azure AD license tier is required for Conditional Access policies?
- A) Free
- B) Office 365
- C) Premium P1
- D) Premium P2

**Correct Answer**: C
**Explanation**: Conditional Access requires Azure AD Premium P1 or P2 license. Free and Office 365 tiers don't include this feature.

#### Question 8
Your organization needs temporary, time-limited administrative access with approval workflow. What should you use?
- A) Azure AD roles
- B) Privileged Identity Management (PIM)
- C) Conditional Access
- D) Identity Protection

**Correct Answer**: B
**Explanation**: PIM provides just-in-time privileged access with approval workflows, time limits, and justification requirements.

#### Question 9
Which feature would you use to regularly review who has access to sensitive applications?
- A) Conditional Access
- B) Access Reviews
- C) Identity Protection
- D) Entitlement Management

**Correct Answer**: B
**Explanation**: Access Reviews provide periodic certification of group memberships, application access, and Azure AD role assignments.

#### Question 10
What is the main benefit of passwordless authentication?
- A) It's faster than passwords
- B) It eliminates password-based attacks (phishing, password spray, credential stuffing)
- C) It requires no user training
- D) It works on all devices

**Correct Answer**: B
**Explanation**: Passwordless authentication removes passwords as an attack vector, eliminating phishing, password spray, and credential stuffing attacks.

#### Question 11
Which identity model uses claims-based tokens for authentication across different systems?
- A) Kerberos
- B) NTLM
- C) Federation (SAML, OAuth, OpenID Connect)
- D) Basic authentication

**Correct Answer**: C
**Explanation**: Federation uses claims-based tokens (SAML assertions, OAuth tokens, OIDC ID tokens) to establish trust between identity providers and applications.

#### Question 12
Your organization wants to allow external partners to access specific resources without creating internal accounts. What should you implement?
- A) Azure AD Domain Services
- B) Azure AD B2C
- C) Azure AD B2B (guest access)
- D) Azure AD Connect

**Correct Answer**: C
**Explanation**: Azure AD B2B allows external users to access your resources using their own credentials from their organization's identity provider.

#### Question 13
What does adaptive MFA in Identity Protection do?
- A) Requires MFA for all users all the time
- B) Dynamically requires MFA based on calculated risk level
- C) Allows users to choose their MFA method
- D) Automatically enrolls users in MFA

**Correct Answer**: B
**Explanation**: Adaptive (risk-based) MFA triggers authentication challenges only when risk is elevated, balancing security with user experience.

---

### Module 2: Security, Compliance, and Identity Concepts (4 questions)

#### Question 14
Which of the following is an example of defense in depth?
- A) Using only a firewall for network security
- B) Implementing multiple security layers: firewall, IDS/IPS, endpoint protection, access controls
- C) Having a strong perimeter security
- D) Using single sign-on

**Correct Answer**: B
**Explanation**: Defense in depth uses multiple layers of security controls so if one layer fails, others provide protection.

#### Question 15
What is the Zero Trust security principle?
- A) Trust but verify
- B) Trust the network perimeter
- C) Never trust, always verify
- D) Trust internal users

**Correct Answer**: C
**Explanation**: Zero Trust assumes breach and explicitly verifies every request regardless of source location (internal or external).

#### Question 16
Which regulation focuses on data protection and privacy for EU residents?
- A) HIPAA
- B) GDPR
- C) PCI DSS
- D) SOX

**Correct Answer**: B
**Explanation**: GDPR (General Data Protection Regulation) governs data protection and privacy for individuals in the European Union.

#### Question 17
What is the principle of least privilege?
- A) Give users maximum access for flexibility
- B) Grant only the minimum permissions needed to perform job functions
- C) Restrict all access by default
- D) Give temporary access to all resources

**Correct Answer**: B
**Explanation**: Least privilege means users should have only the minimum access rights necessary to perform their jobs, reducing attack surface and potential damage from compromised accounts.

---

### Module 3: Microsoft Security Solutions (17 questions)

#### Question 18
Which Azure service provides Layer 7 (application layer) protection for web applications?
- A) Azure Firewall
- B) Network Security Groups (NSGs)
- C) Web Application Firewall (WAF)
- D) Azure DDoS Protection

**Correct Answer**: C
**Explanation**: WAF operates at Layer 7 (application layer) to protect web applications from OWASP Top 10 vulnerabilities like SQL injection and XSS.

#### Question 19
What is the primary benefit of Azure Bastion?
- A) Provides VPN connectivity
- B) Provides secure RDP/SSH access to VMs without exposing them to the internet
- C) Provides load balancing
- D) Provides firewall protection

**Correct Answer**: B
**Explanation**: Azure Bastion provides secure RDP/SSH connectivity through the Azure portal over SSL, eliminating the need for public IPs on VMs.

#### Question 20
Which Microsoft Defender for Cloud feature provides a score from 0-100% representing your security posture?
- A) Compliance Manager
- B) Secure Score
- C) Security Alerts
- D) Vulnerability Assessment

**Correct Answer**: B
**Explanation**: Secure Score measures security posture as a percentage based on implemented security recommendations vs. available recommendations.

#### Question 21
What type of service is Microsoft Defender for Cloud?
- A) SIEM
- B) CNAPP (Cloud-Native Application Protection Platform)
- C) CASB
- D) EDR

**Correct Answer**: B
**Explanation**: Defender for Cloud is a CNAPP providing CSPM (Cloud Security Posture Management) and CWPP (Cloud Workload Protection Platform).

#### Question 22
Which Defender product protects email and collaboration tools from phishing and malware?
- A) Defender for Endpoint
- B) Defender for Office 365
- C) Defender for Identity
- D) Defender for Cloud Apps

**Correct Answer**: B
**Explanation**: Defender for Office 365 protects email (Exchange), Teams, SharePoint, and OneDrive with Safe Attachments, Safe Links, and anti-phishing.

#### Question 23
What does Safe Links in Defender for Office 365 do?
- A) Scans attachments for malware
- B) Rewrites URLs and scans them at time-of-click
- C) Blocks spam email
- D) Encrypts emails

**Correct Answer**: B
**Explanation**: Safe Links rewrites URLs to route through Microsoft protection, scanning them each time clicked (time-of-click protection).

#### Question 24
Which Defender product would detect pass-the-hash attacks in on-premises Active Directory?
- A) Defender for Office 365
- B) Defender for Endpoint
- C) Defender for Identity
- D) Defender for Cloud Apps

**Correct Answer**: C
**Explanation**: Defender for Identity monitors domain controllers to detect identity-based attacks like pass-the-hash, pass-the-ticket, and lateral movement.

#### Question 25
What does CASB stand for in Microsoft Defender for Cloud Apps?
- A) Cloud Application Security Baseline
- B) Cloud Access Security Broker
- C) Certified Application Security Browser
- D) Cloud Authentication Security Boundary

**Correct Answer**: B
**Explanation**: CASB (Cloud Access Security Broker) sits between users and cloud services to provide visibility, threat protection, and data security.

#### Question 26
Which Defender for Cloud Apps feature discovers unsanctioned cloud applications (shadow IT)?
- A) App Connectors
- B) Cloud Discovery
- C) Conditional Access App Control
- D) Information Protection

**Correct Answer**: B
**Explanation**: Cloud Discovery analyzes traffic logs to identify all cloud apps being used, including unsanctioned apps (shadow IT).

#### Question 27
What is XDR in Microsoft 365 Defender?
- A) Extended Data Recovery
- B) Extended Detection and Response
- C) External Device Recognition
- D) Extra Defense Resources

**Correct Answer**: B
**Explanation**: XDR (Extended Detection and Response) automatically collects, correlates, and analyzes threat data across multiple domains (email, endpoints, identities, cloud apps).

#### Question 28
Which Microsoft Sentinel component ingests data from various sources?
- A) Workbooks
- B) Analytics Rules
- C) Data Connectors
- D) Playbooks

**Correct Answer**: C
**Explanation**: Data Connectors are pre-built integrations that ingest logs and alerts from Microsoft services, third-party solutions, and custom sources.

#### Question 29
What does SIEM stand for in Microsoft Sentinel?
- A) Security Integration and Event Manager
- B) Security Information and Event Management
- C) System Integration Event Monitor
- D) Secure Internet Event Management

**Correct Answer**: B
**Explanation**: SIEM (Security Information and Event Management) collects, analyzes, and correlates security data for threat detection.

#### Question 30
What query language is used for threat hunting in Microsoft Sentinel?
- A) SQL
- B) PowerShell
- C) KQL (Kusto Query Language)
- D) Python

**Correct Answer**: C
**Explanation**: KQL (Kusto Query Language) is used in Sentinel for hunting queries, analytics rules, and log analysis.

#### Question 31
What are Playbooks in Microsoft Sentinel based on?
- A) PowerShell scripts
- B) Azure Logic Apps
- C) Azure Functions
- D) Power Automate

**Correct Answer**: B
**Explanation**: Playbooks use Azure Logic Apps to automate incident response workflows (SOAR capabilities).

#### Question 32
Which analytics rule type in Sentinel uses machine learning to detect multi-stage attacks?
- A) Scheduled
- B) Microsoft Security
- C) Fusion
- D) Anomaly

**Correct Answer**: C
**Explanation**: Fusion rules use ML to correlate low-fidelity signals across multiple data sources to detect sophisticated multi-stage attacks.

#### Question 33
What does encryption at rest protect?
- A) Data while being transmitted over networks
- B) Data stored on physical media (disks, databases)
- C) Data being processed in memory
- D) Data in transit between users

**Correct Answer**: B
**Explanation**: Encryption at rest protects data stored on physical media (storage accounts, databases, VM disks).

#### Question 34
Which Azure service provides centralized secrets management with HSM-backed security?
- A) Azure Storage
- B) Azure Key Vault
- C) Azure Backup
- D) Azure Site Recovery

**Correct Answer**: B
**Explanation**: Azure Key Vault stores and controls access to encryption keys, certificates, secrets, and passwords with HSM backing.

---

### Module 4: Microsoft Compliance Solutions (16 questions)

#### Question 35
What does Compliance Manager in Microsoft Purview measure?
- A) Network security
- B) Compliance posture across regulations and standards
- C) User activity
- D) Application performance

**Correct Answer**: B
**Explanation**: Compliance Manager assesses compliance posture against regulations (GDPR, ISO 27001, etc.) with a score and improvement actions.

#### Question 36
What is the primary purpose of sensitivity labels?
- A) Delete old data
- B) Protect data with encryption, marking, and access controls
- C) Archive data
- D) Backup data

**Correct Answer**: B
**Explanation**: Sensitivity labels protect data by applying encryption, visual markings, access restrictions, and content controls.

#### Question 37
Can you apply both a sensitivity label and a retention label to the same document?
- A) No, only one label type allowed
- B) Yes, they serve different purposes (protect vs. govern)
- C) Only in SharePoint
- D) Only with admin permissions

**Correct Answer**: B
**Explanation**: Sensitivity labels protect data, retention labels govern lifecycle. Both can be applied together for comprehensive data management.

#### Question 38
What is the main difference between a retention policy and a retention label?
- A) Policies are manual, labels are automatic
- B) Policies apply location-wide, labels apply item-level
- C) Policies are permanent, labels are temporary
- D) No difference

**Correct Answer**: B
**Explanation**: Retention policies apply automatically to all content in selected locations (Exchange, SharePoint). Retention labels apply to individual items (documents, emails).

#### Question 39
What happens when you mark content as a regulatory record?
- A) Content can be edited by anyone
- B) Content can be deleted by users
- C) Content cannot be edited or deleted, even by admins
- D) Content is automatically shared

**Correct Answer**: C
**Explanation**: Regulatory records are immutable—cannot be edited, deleted, or have labels removed, even by Global Admins.

#### Question 40
Which DLP location allows monitoring of files copied to USB drives?
- A) Exchange Online
- B) SharePoint Online
- C) Endpoint DLP (Windows/macOS devices)
- D) Teams

**Correct Answer**: C
**Explanation**: Endpoint DLP monitors local device activities including USB copying, printing, cloud uploads, and clipboard operations.

#### Question 41
What is the purpose of policy tips in DLP?
- A) Delete sensitive data
- B) Educate users about policy violations at the moment they occur
- C) Block all file operations
- D) Encrypt all emails

**Correct Answer**: B
**Explanation**: Policy tips appear when users violate DLP policies, explaining the violation and suggesting correct behavior (educational).

#### Question 42
What does Insider Risk Management use to protect user privacy?
- A) Encryption
- B) Pseudonymization (User1, User2)
- C) Deletion of logs
- D) Anonymous reporting

**Correct Answer**: B
**Explanation**: Insider Risk Management shows user identities as pseudonyms (User1, User2) by default. Only authorized investigators can reveal actual identities.

#### Question 43
Which template in Insider Risk Management would you use to monitor employees before they leave the company?
- A) General data leaks
- B) Data theft by departing users
- C) Security policy violations
- D) Offensive language

**Correct Answer**: B
**Explanation**: "Data theft by departing users" template monitors employees with termination dates or resignations for data exfiltration activities.

#### Question 44
What does Communication Compliance primarily monitor?
- A) File downloads
- B) USB activities
- C) Message content in Teams, email, Yammer
- D) Network traffic

**Correct Answer**: C
**Explanation**: Communication Compliance monitors communications (Teams, Exchange, Yammer) for inappropriate content and regulatory violations.

#### Question 45
What is the purpose of Information Barriers?
- A) Block external threats
- B) Prevent conflicts of interest by restricting communication between specific groups
- C) Encrypt all data
- D) Monitor user activities

**Correct Answer**: B
**Explanation**: Information Barriers create "Chinese Walls" to prevent communication between groups (e.g., competing deal teams, conflicting client matters).

#### Question 46
Which eDiscovery feature is only available in eDiscovery Premium?
- A) Legal holds
- B) Content search
- C) Predictive coding (ML-based relevance)
- D) Export results

**Correct Answer**: C
**Explanation**: Predictive coding uses machine learning to identify relevant documents and is a Premium-only feature.

#### Question 47
What is a custodian in eDiscovery?
- A) A storage location
- B) An individual and their associated data sources under investigation
- C) An admin who manages cases
- D) A type of legal hold

**Correct Answer**: B
**Explanation**: A custodian is a person of interest in an investigation along with their data sources (mailbox, OneDrive, devices).

#### Question 48
How long does Audit (Standard) retain audit logs?
- A) 30 days
- B) 90 days
- C) 1 year
- D) 10 years

**Correct Answer**: B
**Explanation**: Audit (Standard) provides 90-day retention. Audit (Premium) offers 1-year default with up to 10-year options.

#### Question 49
Which audit event (Premium only) tracks every time a mailbox item is accessed?
- A) FileAccessed
- B) MailItemsAccessed
- C) UserLoggedIn
- D) SendAs

**Correct Answer**: B
**Explanation**: MailItemsAccessed is a high-value Premium event critical for breach investigations, showing exactly which emails were accessed.

#### Question 50
What is disposition in retention management?
- A) Initial classification of data
- B) Process that occurs at end of retention period (delete, review, extend)
- C) Applying sensitivity labels
- D) Creating retention policies

**Correct Answer**: B
**Explanation**: Disposition is what happens at the end of a retention period—content can be automatically deleted, reviewed before deletion, or extended.

---

## Practice Exam 2: Focused Scenarios (40 Questions)

### Scenario 1: Identity and Access
**Context**: Contoso Corporation is implementing Zero Trust with Azure AD for 5,000 users across 3 global offices.

#### Question 51
Contoso wants to require MFA only when users sign in from outside the corporate network or from unmanaged devices. What should they implement?
- A) Azure AD Identity Protection
- B) Conditional Access policies
- C) Azure AD Connect
- D) PIM

**Answer**: B - Conditional Access policies can evaluate conditions (location, device state) and require MFA accordingly.

#### Question 52
A contractor needs temporary access to specific Azure resources for 3 months. What identity type should Contoso use?
- A) Full employee account
- B) Guest account (B2B)
- C) Service principal
- D) Managed identity

**Answer**: B - Guest accounts (B2B) allow external users to access specific resources using their own credentials.

#### Question 53
Contoso's CEO account was compromised and used to approve fraudulent wire transfers. What feature could have prevented this?
- A) Password complexity requirements
- B) Privileged Identity Management with approval workflow
- C) Azure AD Connect
- D) Self-service password reset

**Answer**: B - PIM requires approval and justification for activating privileged roles, preventing unauthorized use of elevated permissions.

---

### Scenario 2: Microsoft Defender Suite
**Context**: Fabrikam wants comprehensive threat protection across email, endpoints, identities, and cloud apps.

#### Question 54
A phishing email with a malicious Excel file reaches a user's inbox. Which Defender product should detect and block it?
- A) Defender for Endpoint
- B) Defender for Office 365
- C) Defender for Identity
- D) Defender for Cloud Apps

**Answer**: B - Defender for Office 365 Safe Attachments detonates email attachments in sandbox to detect malicious behavior.

#### Question 55
After the user opens the file, malware attempts to execute. Which Defender product provides endpoint protection?
- A) Defender for Office 365
- B) Defender for Endpoint
- C) Defender for Identity
- D) Defender for Cloud

**Answer**: B - Defender for Endpoint provides EDR capabilities, detecting and blocking malware execution on devices.

#### Question 56
The malware attempts a pass-the-hash attack against Active Directory. Which product detects this?
- A) Defender for Office 365
- B) Defender for Endpoint
- C) Defender for Identity
- D) Defender for Cloud Apps

**Answer**: C - Defender for Identity monitors domain controllers and detects identity attacks like pass-the-hash.

#### Question 57
Where would Fabrikam see all related alerts from these Defender products correlated into a single incident?
- A) Azure portal
- B) Microsoft 365 Defender portal (security.microsoft.com)
- C) Microsoft Sentinel
- D) Azure Security Center

**Answer**: B - Microsoft 365 Defender portal provides unified XDR with automatic alert correlation across all Defender products.

---

### Scenario 3: Cloud Security
**Context**: Adventure Works needs to secure Azure workloads and meet PCI DSS compliance requirements.

#### Question 58
Adventure Works wants to assess their Azure resources against PCI DSS standards. Where should they go?
- A) Azure Advisor
- B) Microsoft Defender for Cloud Compliance Dashboard
- C) Microsoft Purview Compliance Manager
- D) Azure Monitor

**Answer**: B - Defender for Cloud includes a compliance dashboard with PCI DSS and other regulatory standards for Azure resources.

#### Question 59
They need to protect a public-facing web application from SQL injection attacks. What should they deploy?
- A) Network Security Group
- B) Azure Firewall
- C) Web Application Firewall (WAF)
- D) Azure DDoS Protection

**Answer**: C - WAF provides Layer 7 protection against OWASP Top 10 vulnerabilities including SQL injection.

#### Question 60
Adventure Works wants to know their security posture as a percentage score. Which feature provides this?
- A) Azure Advisor Score
- B) Secure Score in Defender for Cloud
- C) Compliance Score
- D) Cost Analysis

**Answer**: B - Secure Score measures security posture as a percentage (0-100%) based on implemented recommendations.

---

### Scenario 4: SIEM and SOAR
**Context**: Tailspin Toys is implementing Microsoft Sentinel for security monitoring across Microsoft 365, Azure, AWS, and on-premises firewalls.

#### Question 61
What components does Tailspin need to configure first to ingest data into Sentinel?
- A) Playbooks
- B) Workbooks
- C) Data Connectors
- D) Hunting queries

**Answer**: C - Data Connectors must be configured first to ingest logs and alerts from various sources into Sentinel.

#### Question 62
Tailspin wants to automatically isolate endpoints when high-severity alerts are triggered. What should they create?
- A) Analytics rule
- B) Playbook (using Azure Logic Apps)
- C) Workbook
- D) Data connector

**Answer**: B - Playbooks provide SOAR capabilities, automating responses like endpoint isolation via Logic Apps workflows.

#### Question 63
They need to detect brute force attacks (10+ failed logins from same IP in 5 minutes). What should they create?
- A) Data connector
- B) Scheduled analytics rule (KQL query)
- C) Workbook
- D) Hunting query

**Answer**: B - Scheduled analytics rules run KQL queries on a schedule to detect threats and create incidents.

#### Question 64
What ML-based analytics rule type automatically correlates weak signals across multiple data sources?
- A) Scheduled
- B) Microsoft Security
- C) Fusion
- D) Anomaly

**Answer**: C - Fusion rules use ML to correlate low-fidelity signals and detect multi-stage attacks.

---

### Scenario 5: Data Protection and Compliance
**Context**: Northwind Traders handles customer PII and needs to implement data protection and compliance controls.

#### Question 65
Northwind wants to automatically encrypt documents containing 10+ credit card numbers. What should they create?
- A) DLP policy
- B) Sensitivity label with auto-labeling and encryption
- C) Retention policy
- D) Communication compliance policy

**Answer**: B - Sensitivity labels can auto-apply based on content (credit cards) and enforce encryption.

#### Question 66
They need to prevent employees from emailing credit card data to external recipients. What should they implement?
- A) Sensitivity label
- B) Retention policy
- C) DLP policy for Exchange with block action
- D) Insider Risk policy

**Answer**: C - DLP policies detect sensitive data (credit cards) in emails and can block external sharing.

#### Question 67
Financial records must be kept for 7 years then deleted. What should Northwind create?
- A) Sensitivity label
- B) DLP policy
- C) Retention label (retain 7 years, then delete)
- D) eDiscovery hold

**Answer**: C - Retention labels govern data lifecycle, specifying how long to keep and when to delete.

#### Question 68
Northwind wants to make certain audit records immutable and prevent even admins from deleting them. What should they use?
- A) Sensitivity label
- B) Retention label
- C) Regulatory record label
- D) DLP policy

**Answer**: C - Regulatory records are completely immutable—cannot be edited, deleted, or have labels removed even by Global Admins.

---

### Scenario 6: Insider Risk and Communication Compliance
**Context**: Wide World Importers needs to detect data theft and monitor communications for regulatory compliance (SEC/FINRA).

#### Question 69
A departing employee starts downloading large amounts of customer data. Which solution should detect this?
- A) DLP
- B) Insider Risk Management
- C) Communication Compliance
- D) Information Barriers

**Answer**: B - Insider Risk Management detects behavioral anomalies like unusual downloads, especially for departing users.

#### Question 70
They need to monitor trader communications for violations like sharing inside information. What should they implement?
- A) DLP
- B) Insider Risk Management
- C) Communication Compliance
- D) Sensitivity labels

**Answer**: C - Communication Compliance monitors message content for regulatory violations, inappropriate content, and policy breaches.

#### Question 71
How does Insider Risk Management protect user privacy?
- A) Deletes logs after 30 days
- B) Shows users as User1, User2 (pseudonymization)
- C) Encrypts all data
- D) Only tracks anonymous data

**Answer**: B - Pseudonymization hides actual identities by default; only authorized investigators can reveal real names.

#### Question 72
Wide World needs to prevent M&A Team A from communicating with M&A Team B (competing deals). What should they implement?
- A) DLP policy
- B) Sensitivity labels
- C) Information Barriers
- D) Conditional Access

**Answer**: C - Information Barriers restrict communication between specific segments to prevent conflicts of interest.

---

### Scenario 7: eDiscovery and Audit
**Context**: Lucerne Publishing faces litigation and needs to preserve and search email and documents from 10 employees for the past 2 years.

#### Question 73
What should Lucerne create first?
- A) DLP policy
- B) Retention policy
- C) eDiscovery case with legal holds
- D) Audit search

**Answer**: C - eDiscovery cases manage investigations with legal holds to preserve content and searches to collect evidence.

#### Question 74
They need to prevent the 10 employees from deleting any content during the investigation. What should they place?
- A) Retention label
- B) Legal hold (eDiscovery hold)
- C) Sensitivity label
- D) DLP policy

**Answer**: B - Legal holds preserve content in place, preventing deletion while allowing users to continue working normally.

#### Question 75
Lucerne's attorney needs near-duplicate detection and email threading to reduce review time. Which eDiscovery version do they need?
- A) Content Search
- B) eDiscovery (Standard)
- C) eDiscovery (Premium)
- D) Both Standard and Premium have these features

**Answer**: C - eDiscovery Premium provides advanced analytics including near-duplicate detection, email threading, and predictive coding.

#### Question 76
An employee's account was compromised. Which audit event (Premium) shows exactly what emails the attacker read?
- A) UserLoggedIn
- B) MailItemsAccessed
- C) FileDownloaded
- D) SendAs

**Answer**: B - MailItemsAccessed (Premium high-value event) tracks every mailbox item access, critical for breach investigations.

---

### Scenario 8: Multi-Cloud Security
**Context**: Fourth Coffee operates in Azure, AWS, and GCP and needs unified security monitoring.

#### Question 77
Which solution provides unified CSPM (Cloud Security Posture Management) across Azure, AWS, and GCP?
- A) Azure Security Center
- B) Microsoft Defender for Cloud
- C) Azure Monitor
- D) Microsoft Sentinel

**Answer**: B - Defender for Cloud provides CSPM and threat protection across Azure, hybrid, and multi-cloud environments (AWS, GCP).

#### Question 78
Fourth Coffee wants to collect security logs from all three clouds into a single SIEM. What should they use?
- A) Azure Monitor
- B) Microsoft Defender for Cloud
- C) Microsoft Sentinel
- D) Log Analytics

**Answer**: C - Sentinel is a cloud-native SIEM that can ingest data from Azure, AWS, GCP, and third-party sources.

#### Question 79
They need to automate incident response across all three clouds (isolate VMs, block IPs, create tickets). What Sentinel feature provides this?
- A) Data connectors
- B) Workbooks
- C) Playbooks (Azure Logic Apps)
- D) Hunting queries

**Answer**: C - Playbooks provide SOAR capabilities, automating response actions across multiple platforms using Logic Apps.

---

### Scenario 9: Encryption and Key Management
**Context**: Proseware Inc. has strict compliance requirements for encryption and key management.

#### Question 80
Proseware needs to use their own encryption keys stored in their Azure environment. What option should they choose?
- A) Microsoft-managed keys
- B) Customer-managed keys (CMK) in Azure Key Vault
- C) No encryption
- D) Platform-managed encryption only

**Answer**: B - Customer-managed keys (CMK) allow organizations to control their encryption keys in Azure Key Vault for compliance.

#### Question 81
They need FIPS 140-2 Level 3 HSM protection for highly sensitive data. What should they use?
- A) Azure Key Vault Basic
- B) Azure Key Vault Premium
- C) Azure Dedicated HSM
- D) Azure Storage encryption

**Answer**: C - Azure Dedicated HSM provides FIPS 140-2 Level 3 single-tenant HSMs with full customer control.

#### Question 82
Proseware wants to encrypt data while it's being processed in memory. What Azure feature provides this?
- A) Storage Service Encryption
- B) Transparent Data Encryption
- C) Confidential Computing (with secure enclaves)
- D) BitLocker

**Answer**: C - Confidential Computing uses hardware-based Trusted Execution Environments (TEEs) to encrypt data in use (during processing).

---

### Scenario 10: Licensing and Features
**Context**: Questions about which licenses provide specific features.

#### Question 83
Which license is required for Azure AD Conditional Access?
- A) Azure AD Free
- B) Office 365
- C) Azure AD Premium P1
- D) Azure AD Premium P2

**Answer**: C - Conditional Access requires Azure AD Premium P1 or P2.

#### Question 84
Which license includes all four Microsoft Defender products (Office 365 Plan 2, Endpoint, Identity, Cloud Apps)?
- A) Microsoft 365 E3
- B) Microsoft 365 E5
- C) Office 365 E3
- D) Azure subscription

**Answer**: B - Microsoft 365 E5 includes comprehensive Defender suite with advanced features.

#### Question 85
Audit (Premium) with MailItemsAccessed events requires which license?
- A) Microsoft 365 E3
- B) Microsoft 365 E5 or Compliance add-on
- C) Office 365 E1
- D) Azure AD Premium P1

**Answer**: B - Audit Premium requires E5 or Microsoft 365 Compliance add-on license.

#### Question 86
eDiscovery Premium with predictive coding requires which license?
- A) Microsoft 365 E3
- B) Microsoft 365 Business Premium
- C) Microsoft 365 E5 or Compliance add-on
- D) Office 365 E1

**Answer**: C - eDiscovery Premium features require E5 or Compliance add-on license.

#### Question 87
Which features are included in the FREE Azure AD tier? (Select all that apply)
- A) User and group management
- B) Conditional Access
- C) Self-service password change
- D) Identity Protection

**Answer**: A and C - Free tier includes basic identity management and self-service password change. Conditional Access and Identity Protection require Premium licenses.

---

### Scenario 11: Advanced Threat Protection
**Context**: Questions about detecting and responding to sophisticated attacks.

#### Question 88
An attacker uses stolen Kerberos tickets to access resources. Which attack is this and which Defender product detects it?
- A) Phishing - Defender for Office 365
- B) Pass-the-ticket - Defender for Identity
- C) Malware - Defender for Endpoint
- D) Data exfiltration - Defender for Cloud Apps

**Answer**: B - Pass-the-ticket uses stolen Kerberos tickets; Defender for Identity monitors domain controllers to detect this identity attack.

#### Question 89
Ransomware is detected on a device. Which Defender for Endpoint feature should automatically investigate and remediate?
- A) Threat & Vulnerability Management
- B) Attack Surface Reduction
- C) Automated Investigation and Response (AIR)
- D) Advanced Hunting

**Answer**: C - AIR automatically investigates alerts, examines evidence, and takes or recommends remediation actions.

#### Question 90
You want to proactively search for indicators of compromise using custom queries. Which feature should you use?
- A) Security alerts
- B) Advanced Hunting (with KQL queries)
- C) Secure Score
- D) Vulnerability assessment

**Answer**: B - Advanced Hunting allows proactive threat hunting using KQL queries across security data.

---

## Answer Key Summary

### Practice Exam 1 (Questions 1-50)
**Module 1 (Identity)**: 1-C, 2-B, 3-A, 4-B, 5-B, 6-C, 7-C, 8-B, 9-B, 10-B, 11-C, 12-C, 13-B
**Module 2 (Concepts)**: 14-B, 15-C, 16-B, 17-B
**Module 3 (Security)**: 18-C, 19-B, 20-B, 21-B, 22-B, 23-B, 24-C, 25-B, 26-B, 27-B, 28-C, 29-B, 30-C, 31-B, 32-C, 33-B, 34-B
**Module 4 (Compliance)**: 35-B, 36-B, 37-B, 38-B, 39-C, 40-C, 41-B, 42-B, 43-B, 44-C, 45-B, 46-C, 47-B, 48-B, 49-B, 50-B

### Practice Exam 2 (Questions 51-90)
51-B, 52-B, 53-B, 54-B, 55-B, 56-C, 57-B, 58-B, 59-C, 60-B, 61-C, 62-B, 63-B, 64-C, 65-B, 66-C, 67-C, 68-C, 69-B, 70-C, 71-B, 72-C, 73-C, 74-B, 75-C, 76-B, 77-B, 78-C, 79-C, 80-B, 81-C, 82-C, 83-C, 84-B, 85-B, 86-C, 87-A&C, 88-B, 89-C, 90-B

---

## Exam Day Tips

### Before the Exam
- [x] Review all 4 module summaries
- [x] Complete both practice exams
- [x] Review incorrect answers and understand why
- [x] Focus on areas with lowest scores
- [x] Get good sleep night before
- [x] Eat a proper meal before exam

### During the Exam
1. **Read carefully**: Questions can be tricky with similar-sounding options
2. **Mark for review**: Flag questions you're unsure about
3. **Eliminate wrong answers**: Narrow down choices
4. **Manage time**: 60 minutes for 40-60 questions = ~1 minute per question
5. **Don't overthink**: First instinct often correct
6. **Watch for "select all"**: Some questions have multiple correct answers

### Question Keywords to Watch
- **"BEST"**: Look for the most appropriate solution
- **"LEAST"**: Find the option that doesn't fit
- **"EXCEPT"**: All are correct except one
- **"FIRST"**: Order of operations matters
- **"REQUIRED"**: Mandatory vs. optional features
- **"MINIMAL"**: Simplest or least privileged solution

### Common Traps
❌ **Overcomplicating**: Usually the straightforward answer is correct
❌ **Licensing confusion**: Know which features require Premium licenses
❌ **Similar products**: Defender for X vs. Azure AD X vs. Purview X
❌ **Scope confusion**: Policy (location-wide) vs. Label (item-level)
❌ **Standard vs. Premium**: What's included in base vs. premium tiers

### Final Checklist
- [ ] Understand difference between authentication vs. authorization
- [ ] Know Azure AD features by license tier (Free, P1, P2)
- [ ] Recognize which Defender product protects what (Office/Endpoint/Identity/Cloud Apps)
- [ ] Differentiate sensitivity labels (protect) vs. retention labels (govern)
- [ ] Know DLP enforcement locations and capabilities
- [ ] Understand Insider Risk vs. Communication Compliance focus areas
- [ ] Recognize eDiscovery Standard vs. Premium features
- [ ] Know Audit Standard (90 days) vs. Premium (1-10 years) capabilities
- [ ] Understand SIEM (Sentinel) vs. SOAR (Playbooks) concepts
- [ ] Know encryption types: at rest, in transit, in use

---

## Additional Resources

**Microsoft Learn Paths**:
- SC-900: Security, Compliance, and Identity Fundamentals (https://learn.microsoft.com/en-us/certifications/exams/sc-900)
- Microsoft Purview Learning Path
- Microsoft Defender Learning Path
- Azure AD Learning Path

**Practice Questions**:
- Microsoft Learn practice assessments
- MeasureUp practice exams
- Whizlabs SC-900 practice tests

**Study Groups**:
- Microsoft Tech Community
- Reddit r/AzureCertification
- LinkedIn SC-900 study groups

**Videos**:
- John Savill's SC-900 YouTube playlist
- Microsoft Mechanics channel
- Azure Academy

**Good luck on your SC-900 exam! 🎓**