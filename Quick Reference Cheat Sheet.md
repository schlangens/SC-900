# SC-900 Quick Reference Cheat Sheet

> Use this as your last-minute review before the exam. Fill in as you study!

---

## Must-Know Acronyms

| Acronym | Full Name | Quick Definition |
|---------|-----------|------------------|
| **AAA** | Authentication, Authorization, Accounting | |
| **AIR** | Automated Investigation & Response | |
| **ASR** | Attack Surface Reduction | |
| **B2B** | Business-to-Business | |
| **B2C** | Business-to-Consumer | |
| **CA** | Conditional Access | |
| **CASB** | Cloud Access Security Broker | |
| **CSPM** | Cloud Security Posture Management | |
| **CWPP** | Cloud Workload Protection Platform | |
| **DDoS** | Distributed Denial of Service | |
| **DLP** | Data Loss Prevention | |
| **EDR** | Endpoint Detection & Response | |
| **FIDO** | Fast Identity Online | |
| **GDPR** | General Data Protection Regulation | |
| **GRC** | Governance, Risk, and Compliance | |
| **IAM** | Identity and Access Management | |
| **MFA** | Multi-Factor Authentication | |
| **NSG** | Network Security Group | |
| **PHS** | Password Hash Synchronization | |
| **PII** | Personally Identifiable Information | |
| **PIM** | Privileged Identity Management | |
| **PTA** | Pass-Through Authentication | |
| **SIEM** | Security Information & Event Management | |
| **SOAR** | Security Orchestration, Automation, Response | |
| **SSO** | Single Sign-On | |
| **UEBA** | User & Entity Behavior Analytics | |
| **WAF** | Web Application Firewall | |
| **XDR** | Extended Detection & Response | |

---

## Core Concepts (5-Minute Review)

### Zero Trust Principles
1. **Verify explicitly** - Always authenticate and authorize
2. **Least privilege access** - Just-enough, just-in-time access
3. **Assume breach** - Minimize blast radius, verify end-to-end

### Defense in Depth Layers (bottom to top)
1. Physical Security
2. Identity & Access
3. Perimeter
4. Network
5. Compute
6. Application
7. Data

### CIA Triad
- **Confidentiality**: Only authorized access
- **Integrity**: Data is accurate and trustworthy
- **Availability**: Data accessible when needed

### Shared Responsibility Model
- **IaaS**: Customer manages most (OS, apps, data)
- **PaaS**: Shared management
- **SaaS**: Microsoft manages most (customer manages data/access)
- **Always Customer**: Data, accounts, devices

---

## Identity & Access Management

### Azure AD vs Active Directory

| Feature | Azure AD | Active Directory |
|---------|----------|------------------|
| Environment | Cloud | On-premises |
| Protocol | HTTP/HTTPS, SAML, OAuth | Kerberos, LDAP |
| Structure | Flat (no OUs) | Hierarchical (OUs) |
| Auth | Modern (passwordless) | Traditional |

### Authentication Methods (Weakest → Strongest)
```
Password → Password + MFA → Passwordless (FIDO2, WHfB, Authenticator)
```

### Azure AD Premium Editions

| Feature | Free | P1 | P2 |
|---------|------|----|----|
| **Users** | 500K | Unlimited | Unlimited |
| **Conditional Access** | ✗ | ✓ | ✓ |
| **Identity Protection** | ✗ | ✗ | ✓ |
| **PIM** | ✗ | ✗ | ✓ |
| **Access Reviews** | ✗ | ✓ | ✓ |

### Conditional Access: IF-THEN Logic
**IF** (Signals): User, Location, Device, App, Risk
**THEN** (Controls): Block, Grant, Require MFA, Require compliant device

### PIM States
- **No Access** → **Eligible** (can activate) → **Active** (time-limited)

---

## Microsoft Security Solutions

### Microsoft Defender Products

| Product | Protects | Key Feature | Portal |
|---------|----------|-------------|--------|
| **Defender for Office 365** | Email & collaboration | Safe Links/Attachments | security.microsoft.com |
| **Defender for Endpoint** | Devices (Windows, Mac, etc.) | EDR, ASR, TVM | security.microsoft.com |
| **Defender for Identity** | On-prem AD | Detect AD attacks | security.microsoft.com |
| **Defender for Cloud Apps** | SaaS apps | CASB (shadow IT) | security.microsoft.com |
| **Defender for Cloud** | Azure/hybrid/multi-cloud | CSPM, CWPP | portal.azure.com |
| **Microsoft 365 Defender** | Unified XDR | Combines all above | security.microsoft.com |

### Azure Network Security

| Service | Purpose | OSI Layer |
|---------|---------|-----------|
| **NSG** | Basic filtering for subnet/NIC | Layer 4 |
| **Azure Firewall** | Advanced firewall with threat intel | Layer 4-7 |
| **WAF** | Protect web apps (OWASP Top 10) | Layer 7 |
| **DDoS Protection** | Mitigate DDoS attacks | Layer 3-4 |
| **Azure Bastion** | Secure RDP/SSH access | N/A (PaaS) |

### Sentinel (SIEM + SOAR)

**Workflow**:
```
Data Connectors → Analytics Rules → Incidents → Investigation → Playbooks (Automation)
```

**Key Features**:
- Workbooks (visualization)
- Hunting (KQL queries)
- UEBA (behavior analytics)
- Threat intelligence integration

---

## Microsoft Compliance Solutions

### Microsoft Purview Capabilities
1. **Know your data**: Classification, sensitive info types
2. **Protect your data**: Sensitivity labels, encryption
3. **Prevent data loss**: DLP policies
4. **Govern your data**: Retention, records management

### Label Types

| Label Type | Purpose | Key Features |
|------------|---------|--------------|
| **Sensitivity** | Protect (how) | Encryption, marking, access control |
| **Retention** | Retain/delete (how long) | Auto-delete, disposition review |

**Both can coexist on same item!**

### DLP Policy Flow
```
Content Match → Condition Evaluation → Action (Block/Notify/Alert)
```

**DLP Locations**: Exchange, SharePoint, OneDrive, Teams, Endpoints, Cloud apps

### Records vs Regulatory Records

| Feature | Record | Regulatory Record |
|---------|--------|-------------------|
| **Delete** | No | No |
| **Edit** | Some fields | No |
| **Unlock Label** | Admin can | Nobody can |
| **Use Case** | Standard retention | Legal/regulatory |

### Key Purview Tools

| Tool | Purpose | Key Feature |
|------|---------|-------------|
| **Compliance Manager** | Assess compliance posture | Compliance Score |
| **Insider Risk Management** | Detect insider threats | Pseudonymized alerts |
| **Communication Compliance** | Monitor communications | Policy violation detection |
| **Information Barriers** | Prevent conflicts | Segment users |
| **eDiscovery Standard** | Basic legal search | Search, hold, export |
| **eDiscovery Premium** | Advanced legal | Custodians, analytics, ML |
| **Audit Standard** | Log activities | 90 days retention |
| **Audit Premium** | Enhanced audit | 1 year+, high-value events |

---

## Exam Strategy Reminders

### Question Approach
1. Read question carefully (what are they REALLY asking?)
2. Eliminate obviously wrong answers
3. Look for key words: "least cost", "most secure", "minimum effort"
4. Don't overthink - first instinct often correct
5. Flag uncertain questions, return later

### Common Exam Patterns
- **Scenario-based**: Match solution to business requirement
- **Capability questions**: What can Product X do?
- **Comparison**: When to use Product A vs Product B?
- **License requirements**: What license is needed for Feature X?

### If You Don't Know
- Eliminate wrong answers
- Think about product purpose and category
- Consider license tier (premium features need premium licenses)
- Remember: Defender = Security, Purview = Compliance

---

## Quick Decision Trees

### Which Defender Product?
```
Email threats? → Defender for Office 365
Device threats? → Defender for Endpoint
On-prem AD attacks? → Defender for Identity
Cloud app risks/shadow IT? → Defender for Cloud Apps
Azure workload security? → Defender for Cloud
Want unified view? → Microsoft 365 Defender (portal)
Want SIEM/SOAR? → Sentinel
```

### Which Label?
```
Need encryption/protection? → Sensitivity Label
Need retention/deletion? → Retention Label
Need both? → Use both!
Item-level? → Retention Label
Location-wide? → Retention Policy
```

### Which Authentication?
```
Strongest security? → Passwordless (FIDO2, WHfB)
Reduce passwords? → MFA + Password Protection
Eliminate passwords? → Passwordless
On-prem integration needed? → Azure AD Connect (PHS/PTA/Federation)
```

### Which Access Control?
```
Time-based admin access? → PIM
Risk-based access? → Conditional Access + Identity Protection
Guest access management? → Entitlement Management
Review access periodically? → Access Reviews
```

---

## Common "Gotcha" Facts

### Identity
- Azure AD Connect syncs **one way**: On-prem → Cloud
- MFA is **not** the same as passwordless
- Conditional Access requires **Azure AD Premium P1** (not free)
- Identity Protection requires **Premium P2**
- PIM requires **Premium P2**

### Security
- Microsoft 365 Defender is the **portal**, not a separate product
- Sentinel is **not included** by default - separate cost
- Defender for Cloud has **free** tier (limited) and **paid** plans
- NSGs are **stateful** (return traffic allowed automatically)
- Azure Bastion eliminates need for **public IPs** on VMs

### Compliance
- Sensitivity labels can **encrypt**, retention labels cannot
- Retention labels can **delete**, sensitivity labels cannot
- DLP can **prevent**, not just detect
- Records **cannot be deleted** during retention period
- Regulatory records **cannot be edited** at all
- eDiscovery Premium needs **E5** license
- Audit Premium needs **E5** or add-on
- Compliance Score is **not** a percentage

### Licensing Quick Reference
- **E3**: Basic security and compliance
- **E5**: Advanced (Identity Protection, PIM, Defender plans, eDiscovery Premium, Audit Premium)
- **F3**: Frontline workers (limited features)
- Some features available as **standalone add-ons**

---

## Last-Minute Memory Aids

### MFA Three Factors
- **Something you KNOW**: Password, PIN
- **Something you HAVE**: Phone, token
- **Something you ARE**: Biometric

### OWASP Top 10 (WAF protects against)
- SQL Injection
- XSS (Cross-Site Scripting)
- Broken authentication
- Sensitive data exposure
- (and more...)

### GDPR Data Subject Rights
- Right to access
- Right to rectification
- Right to erasure ("right to be forgotten")
- Right to data portability

### NIST Framework Functions
1. **Identify**
2. **Protect**
3. **Detect**
4. **Respond**
5. **Recover**

---

## Confidence Check

Before the exam, rate your confidence:

- [ ] Core concepts (Zero Trust, Defense in Depth)
- [ ] Azure AD / Entra ID fundamentals
- [ ] Authentication methods
- [ ] Conditional Access
- [ ] Identity Protection & PIM
- [ ] Microsoft Defender products (all 5)
- [ ] Defender for Cloud
- [ ] Microsoft Sentinel
- [ ] Sensitivity vs Retention labels
- [ ] DLP policies
- [ ] Compliance Manager
- [ ] Insider Risk vs Communication Compliance
- [ ] eDiscovery Standard vs Premium
- [ ] Audit capabilities

**Target**: High confidence on all items above

---

## Final Exam Day Tips

### Before Exam
- [ ] Review this cheat sheet
- [ ] Get good sleep
- [ ] Eat before exam
- [ ] Use restroom
- [ ] Clear workspace (online exam)
- [ ] Close all apps except exam
- [ ] Have ID ready

### During Exam
- [ ] Read instructions carefully
- [ ] Budget time: ~1 minute per question
- [ ] Flag uncertain questions
- [ ] Don't spend too long on one question
- [ ] Review flagged questions at end
- [ ] Check all answers before submitting

### Stay Calm
- It's OK to not know every answer
- 700/1000 to pass (you can miss ~30%)
- Trust your preparation
- Take deep breaths

---

**You've got this! Good luck!**
