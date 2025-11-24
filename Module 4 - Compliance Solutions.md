# Module 4: Microsoft Compliance Solutions
**Weight**: 25-30% of exam

---

## 4.1 Microsoft Purview Overview

### What is Microsoft Purview?

**Definition**: Microsoft Purview is a comprehensive set of solutions for data governance, risk, and compliance across your entire data estate—spanning multi-cloud, SaaS, and on-premises environments.

**Unified Data Governance**: Provides a unified approach to understanding, managing, and governing your data wherever it lives—helping organizations meet compliance requirements while protecting sensitive information.

**Key Capabilities**:
1. **Know your data** - Discover and classify sensitive information across your environment
2. **Protect your data** - Apply encryption, access restrictions, and visual markings to sensitive content
3. **Prevent data loss** - Stop sensitive data from leaving your organization through monitoring and blocking
4. **Govern your data** - Manage data lifecycle with retention policies and records management

**Portal**: https://compliance.microsoft.com (Microsoft Purview compliance portal, formerly Microsoft 365 compliance center)

### Purview Compliance Portal Sections

| Section | Purpose | Key Features |
|---------|---------|--------------|
| **Compliance Manager** | Assess and improve compliance posture | Compliance score, assessments, improvement actions, regulatory standards |
| **Data Classification** | Discover and classify sensitive data | Sensitive info types, trainable classifiers, content/activity explorer |
| **Information Protection** | Protect sensitive data | Sensitivity labels, encryption, access controls, visual markings |
| **Data Loss Prevention** | Prevent data leakage | DLP policies, endpoint protection, policy tips, alerts |
| **Records Management** | Manage records lifecycle | Retention labels, file plans, disposition, regulatory records |
| **Insider Risk Management** | Detect risky user behavior | Risk policies, ML detection, investigations, pseudonymization |
| **Communication Compliance** | Monitor communications | Message monitoring, inappropriate content detection, regulatory compliance |
| **eDiscovery** | Legal holds and investigations | Case management, content search, advanced analytics, legal hold notifications |
| **Audit** | Track user and admin activities | Audit logs, compliance reporting, forensic investigations |

---

## 4.2 Service Trust Portal

### Overview

**What is the Service Trust Portal?**: A public-facing portal that provides access to security, privacy, and compliance information about Microsoft's cloud services. It's a central repository for audit reports, compliance documents, and trust resources.

**Portal URL**: https://servicetrust.microsoft.com

**Purpose**:
- **Transparency** - Microsoft shares detailed security and compliance information
- **Due diligence** - Customers can review audit reports for compliance assessments
- **Trust building** - Demonstrates Microsoft's commitment to security and compliance
- **Regulatory compliance** - Access certifications and attestations needed for audits

### Key Resources Available

**Audit Reports**:
- [x] **SOC 1, SOC 2, SOC 3** - Service Organization Control reports for security, availability, and confidentiality
- [x] **ISO/IEC certifications** - ISO 27001, 27018, 27017, 27701 audit reports
- [x] **FedRAMP packages** - Federal Risk and Authorization Management Program documentation
- [x] **PCI DSS** - Payment Card Industry Data Security Standard attestations
- [x] **HIPAA BAA** - Health Insurance Portability and Accountability Act Business Associate Agreement

**Compliance Guides**:
- **GDPR** - General Data Protection Regulation compliance documentation
- **CCPA** - California Consumer Privacy Act guidance
- **Industry-specific** - Financial services, healthcare, government compliance guides
- **Regional compliance** - EU, Asia-Pacific, Americas regional requirements
- **Data protection assessments** - Privacy impact assessments and data transfer documentation

**Trust Documents**:
- **Security white papers** - Technical documentation on Microsoft's security architecture
- **Privacy documentation** - How Microsoft handles data privacy and protection
- **Compliance blueprints** - Architecture guides for building compliant solutions
- **Penetration testing** - Information on Microsoft's security testing practices
- **Service resilience** - Business continuity and disaster recovery documentation

**Data Protection Resources**:
- **Data protection addendums** - Contractual commitments for data processing
- **Standard contractual clauses** - EU data transfer mechanisms
- **Data Processing Agreement (DPA)** - Terms for processing customer data
- **Subprocessor lists** - Third parties Microsoft uses for service delivery

### Accessing the Service Trust Portal

**Access Requirements**:
- **Free access** - No license required, available to anyone
- **Microsoft account** - Sign in with Microsoft account (work, school, or personal)
- **Enhanced access** - Some documents require accepting NDA for sensitive audit reports

**Navigation**:
- **Home** - Featured documents and recent updates
- **Compliance Manager** - Link to Compliance Manager in Microsoft Purview
- **Trust Documents** - Categorized by service and compliance framework
- **Industries & Regions** - Industry-specific and regional compliance resources
- **My Library** - Save frequently accessed documents

**Document Filtering**:
- By cloud service (Azure, Microsoft 365, Dynamics 365, Power Platform)
- By compliance standard (ISO, SOC, FedRAMP, GDPR)
- By region (Global, EU, US, Asia-Pacific)
- By document type (audit reports, white papers, guides)

### Use Cases

**Auditors and Compliance Teams**:
- Download SOC 2 Type II reports for annual audits
- Review ISO certifications for compliance verification
- Access HIPAA documentation for healthcare compliance
- Obtain FedRAMP authorization packages for government contracts

**Security Professionals**:
- Review Microsoft's security architecture and controls
- Understand shared responsibility model
- Access penetration testing guidelines
- Review incident response procedures

**Legal and Privacy Teams**:
- Download Data Processing Agreement (DPA)
- Review standard contractual clauses for GDPR
- Access privacy impact assessments
- Verify subprocessor compliance

**IT Decision Makers**:
- Evaluate Microsoft's compliance posture before adoption
- Compare certifications across cloud providers
- Understand regional data residency options
- Review service-level commitments

### Key Benefits

- **Comprehensive documentation** - Single source for all compliance materials
- **Regular updates** - New audit reports added as soon as available
- **Self-service** - Download reports without contacting Microsoft
- **Trust transparency** - Demonstrates Microsoft's accountability
- **Time savings** - Reduces due diligence effort for customers
- **Audit support** - Provides evidence for customer compliance audits

---

## 4.3 Microsoft's Six Privacy Principles

### Overview

**Purpose**: Microsoft's six privacy principles guide how the company handles customer data across all products and services. These principles demonstrate Microsoft's commitment to privacy by design and regulatory compliance.

**Foundation**: Based on global privacy regulations (GDPR, CCPA) and industry best practices, going beyond legal requirements to earn customer trust.

### The Six Privacy Principles

#### 1. Control

**Principle**: "We will put you in control of your privacy with easy-to-use tools and clear choices."

**What it means**:
- Customers decide how their data is used
- Clear, understandable privacy settings
- Granular controls over data collection and processing
- Ability to access, export, and delete personal data

**Examples in Microsoft 365**:
- **Privacy Dashboard** - Centralized view of privacy settings across Microsoft services
- **Data export** - Download your data from Microsoft services (mailbox, OneDrive files, activity history)
- **Diagnostic data controls** - Choose level of telemetry data sent to Microsoft (Required vs. Optional)
- **Privacy settings** - Configure tracking, advertising, and personalization preferences
- **Consent management** - Clear consent prompts before collecting sensitive data
- **Activity history** - View and delete activity data collected by Microsoft

**Customer Impact**: Users maintain sovereignty over their personal information, with transparent controls to manage privacy preferences.

#### 2. Transparency

**Principle**: "We will be transparent about data collection and use so you can make informed decisions."

**What it means**:
- Clear communication about what data is collected
- Explain why data is collected and how it's used
- Provide detailed privacy statements in plain language
- No hidden data collection or usage

**Examples in Microsoft 365**:
- **Privacy Statement** - Comprehensive, readable documentation at https://privacy.microsoft.com
- **Data collection notices** - In-product notifications when new data collection begins
- **Service Trust Portal** - Public access to audit reports and compliance documentation
- **Privacy reports** - Regular transparency reports on government data requests
- **Product documentation** - Clear explanation of data flows in admin centers
- **Data location transparency** - Know where data is stored geographically

**Customer Impact**: Organizations and users make informed decisions based on complete understanding of data practices.

#### 3. Security

**Principle**: "We will protect the data you entrust to us through strong security and encryption."

**What it means**:
- Industry-leading security measures to protect data
- Encryption in transit and at rest
- Multi-layered defense against threats
- Regular security updates and monitoring
- Compliance with security standards (ISO 27001, SOC 2)

**Examples in Microsoft 365**:
- **Encryption at rest** - All customer data encrypted using BitLocker (256-bit AES)
- **Encryption in transit** - TLS/SSL for all data transmission
- **Azure Rights Management** - Persistent encryption for sensitive documents
- **Multi-factor authentication** - Strong identity verification
- **Microsoft Defender** - Advanced threat protection across endpoints, email, and collaboration
- **Zero Trust architecture** - Verify explicitly, use least privilege access, assume breach
- **Security defaults** - Secure configurations enabled by default
- **Confidential computing** - Protect data while in use with hardware-based encryption

**Customer Impact**: Data remains protected against unauthorized access, breaches, and cyber threats throughout its lifecycle.

#### 4. Strong Legal Protections

**Principle**: "We will respect your local privacy laws and fight for legal protection of your privacy as a fundamental human right."

**What it means**:
- Comply with global privacy regulations (GDPR, CCPA, LGPD, etc.)
- Challenge government requests for customer data when legally questionable
- Provide legal guarantees through contracts and agreements
- Advocate for privacy rights through public policy engagement

**Examples in Microsoft 365**:
- **GDPR compliance** - Data Processing Agreements, Data Subject Rights tools
- **EU Data Boundary** - Keep EU customer data within the European Union
- **Government data requests** - Microsoft notifies customers unless legally prohibited
- **Legal challenges** - Microsoft has challenged over 2,800 government requests
- **Contractual commitments** - Data Processing Agreement (DPA) and Standard Contractual Clauses
- **Privacy as a human right** - Public advocacy for stronger privacy laws globally
- **Warrant canaries** - Transparency reports disclose government data requests (where legal)

**Customer Impact**: Legal protections that go beyond minimum compliance, with Microsoft defending customer data against overreach.

#### 5. No Content-Based Targeting

**Principle**: "We will not use your email, chat, files, or other personal content to target ads to you."

**What it means**:
- Microsoft does not scan content for advertising purposes
- Personal communications remain private
- No ad profiling based on document content or emails
- Clear separation between productivity tools and advertising

**Examples in Microsoft 365**:
- **Email privacy** - Outlook emails are NEVER scanned for ad targeting
- **Document privacy** - Word, Excel, PowerPoint files not used for advertising
- **Chat privacy** - Teams conversations remain confidential, not mined for ads
- **Search privacy** - Bing searches in enterprise context not used for targeting
- **No cross-product profiling** - Work data never combined with consumer ad profiles
- **Clear separation** - Enterprise services operate independently from consumer advertising

**Important Distinction**:
- **Consumer services** (Outlook.com free accounts, free Bing searches) may show personalized ads based on search queries and browsing (with user control)
- **Enterprise services** (Microsoft 365 business/enterprise licenses) NEVER use content for ad targeting

**Customer Impact**: Work content remains confidential and separate from advertising ecosystems, ensuring privacy in business communications.

#### 6. Benefits to You

**Principle**: "When we do collect data, we will use it to benefit you and to make your experiences better."

**What it means**:
- Data collection serves customer interests, not just Microsoft's
- Improve product functionality and user experience
- Provide personalized features when beneficial (with user control)
- Use data to enhance security and prevent threats
- No data collection without clear benefit to customer

**Examples in Microsoft 365**:
- **Diagnostic data** - Improve product reliability and fix bugs faster
  * Crash reports help identify and resolve issues
  * Performance telemetry optimizes service efficiency
  * Feature usage data guides product improvements

- **Security improvements** - Threat intelligence to protect all customers
  * Anonymous threat data shared across Microsoft Defender network
  * Phishing detection learns from attacks across tenant base
  * Vulnerability research strengthens all deployments

- **Productivity features** - AI-powered capabilities that enhance work
  * **Microsoft Editor** - Grammar and style suggestions improve writing
  * **PowerPoint Designer** - AI design recommendations for presentations
  * **Excel data types** - Intelligent data enrichment
  * **Outlook focused inbox** - ML learns your email priorities

- **Search improvements** - Better search results in SharePoint, Teams, OneDrive
  * Learn from aggregated queries to improve relevance
  * Graph API powers intelligent suggestions

- **Accessibility** - Data used to improve features for users with disabilities
  * Voice recognition accuracy improvements
  * Screen reader optimization
  * Cognitive accessibility enhancements

**Customer Control**: Users can opt out of optional diagnostic data while retaining core functionality.

**Customer Impact**: Data collection creates value for customers through better security, improved features, and personalized productivity tools.

---

## 4.4 Compliance Manager

### Overview

**What is Compliance Manager?**: A feature in the Microsoft Purview compliance portal that helps organizations understand and manage compliance requirements by providing a risk-based compliance score and improvement actions to meet various regulatory standards.

**Purpose**:
- **Assess compliance posture** - Measure current state against regulatory requirements
- **Implement controls** - Receive actionable recommendations to improve compliance
- **Track compliance activities** - Monitor progress on improvement actions
- **Generate reports** - Create compliance documentation for auditors and stakeholders

### Compliance Score

**What it measures**: A percentage-based measurement representing your progress in completing improvement actions that reduce risk around data protection and regulatory standards. Score ranges from 0-100%.

**Score Calculation**:
- **Technical actions** - Configuration changes that can be tested/automated (e.g., enable MFA, configure encryption)
- **Non-technical actions** - Processes and documentation (e.g., create policies, conduct training)
- **Microsoft managed actions** - Actions Microsoft implements on backend infrastructure

**Components**:
- **Your Score**: Points earned from completed improvement actions
- **Total Points**: Maximum possible points from all assigned assessments
- **Score Breakdown**: Points by category (Protect information, Govern information, Respond to data requests)

**Example Calculation**: If you have 500 total points available and have achieved 350 points, your compliance score is 70%.

### Key Concepts

#### Regulations and Standards
**Available Standards**:
- [x] **GDPR** (General Data Protection Regulation) - EU data protection
- [x] **ISO 27001** - Information security management
- [x] **ISO 27701** - Privacy information management
- [x] **NIST 800-53** - Security and privacy controls for federal systems
- [x] **SOC 2** - Service organization controls for security, availability, integrity
- [x] **HIPAA** (Health Insurance Portability and Accountability Act) - Healthcare data protection
- [x] **PCI DSS** (Payment Card Industry Data Security Standard) - Payment card data security
- [x] **CCPA** (California Consumer Privacy Act) - California privacy rights
- [x] **FedRAMP** - Federal Risk and Authorization Management Program
- [x] **CMMC** (Cybersecurity Maturity Model Certification) - Defense industry cybersecurity

#### Assessments
**What they are**: Groupings of controls from a specific regulation or standard that map to improvement actions in your environment. Each assessment evaluates your compliance against that specific standard.

**Creating an Assessment**:
1. Choose a template (pre-built for common standards like GDPR, ISO 27001)
2. Select which Microsoft 365 services to include
3. Assign to groups for review and implementation
4. Track progress through improvement actions
5. Generate compliance reports

**Default Assessment**: Microsoft 365 Data Protection Baseline (automatically created)

#### Improvement Actions
**Types**:
1. **Technical Actions**: Can be automated or tested
   - Enable multi-factor authentication
   - Configure audit logging
   - Implement data encryption
   - Apply retention policies
   
2. **Non-Technical Actions**: Manual processes requiring documentation
   - Create security awareness training program
   - Develop incident response plan
   - Establish data governance committee
   - Conduct risk assessments

3. **Microsoft Managed Actions**: Handled by Microsoft
   - Data center physical security
   - Infrastructure encryption
   - Platform vulnerability management
   - Microsoft 365 service hardening

**Example Actions**:
- Enable MFA for all users (10 points) - Technical
- Turn on audit logging in Microsoft 365 (8 points) - Technical
- Create and distribute privacy policy (6 points) - Non-technical
- Conduct annual security awareness training (5 points) - Non-technical

**Action States**:
- **Not assessed** - Action identified but not yet evaluated
- **Assessed** - Action reviewed but not implemented
- **Implemented** - Action completed and tested
- **Alternative implementation** - Different approach used to meet requirement
- **Planned** - Scheduled for future implementation
- **Risk accepted** - Decision made not to implement (with justification)

#### Controls
**What they are**: Requirements from regulations or standards that must be met. Multiple improvement actions may map to a single control.

**Control Categories**:
- **Preventive** - Stop issues before they occur (e.g., access controls, encryption)
- **Detective** - Identify issues when they happen (e.g., monitoring, auditing)
- **Corrective** - Fix issues after detection (e.g., incident response, remediation)

**Control Families**: Groups of related controls
- Access Control (AC)
- Awareness and Training (AT)
- Audit and Accountability (AU)
- Security Assessment and Authorization (CA)
- Configuration Management (CM)
- Contingency Planning (CP)
- Identification and Authentication (IA)
- Incident Response (IR)
- System and Information Integrity (SI)

### Benefits
- **Centralized compliance management** - Single view across multiple standards
- **Risk-based prioritization** - Focus on highest impact actions first
- **Continuous monitoring** - Real-time tracking of compliance posture
- **Automated testing** - Some technical controls automatically verified
- **Shared responsibility transparency** - Clear view of Microsoft vs. customer responsibilities
- **Audit-ready reports** - Export documentation for auditors and regulators
- **Cross-regulation efficiency** - One action may satisfy multiple standards

---

## 4.5 Data Classification

### Overview

**Why Classify Data?**:
- **Identify sensitive information** - Know what data you have and where it lives
- **Apply appropriate protection** - Different data types need different security levels
- **Meet compliance requirements** - Regulations require knowing and protecting sensitive data
- **Enable automation** - Classification drives automated protection and retention policies
- **Reduce risk** - Understand where your most sensitive data is to reduce exposure

### Sensitive Information Types

**What they are**: Patterns that identify specific types of sensitive data using pattern matching, regular expressions, keywords, checksums, and other methods.

**Built-in Types Examples** (300+ available):
- **Financial**:
  - Credit card numbers (Visa, Mastercard, Amex, Discover)
  - Bank account numbers (international formats)
  - SWIFT codes
  - ABA routing numbers

- **Personal Identification**:
  - Social Security numbers (SSN/ITIN)
  - Driver's license numbers (US states, international)
  - Passport numbers (multiple countries)
  - National ID numbers (global coverage)

- **Healthcare**:
  - Medical record numbers
  - Health insurance numbers
  - Drug Enforcement Agency (DEA) numbers

- **Security**:
  - Azure AD access tokens
  - API keys
  - Database connection strings

**Custom Sensitive Information Types**:
- **Patterns using regex** - Define custom patterns (e.g., employee ID: EMP-[0-9]{6})
- **Keywords** - Supporting evidence words that increase confidence
- **Confidence levels** - Low (60-75%), Medium (75-85%), High (85-100%)
- **Character proximity** - Keywords must be within certain distance of pattern

**Example Custom Type**: Employee ID
```
Pattern: EMP-\d{6}
Keywords: employee, contractor, staff
Confidence: High (if both pattern and keyword found)
```

### Trainable Classifiers

**What they are**: Machine learning-based models that can identify content based on what it IS (not just keywords). Learns from examples to recognize content types.

**Types**:

1. **Pre-trained Classifiers** (Microsoft-provided, ready to use):
   - **Resumes** - Identifies resume/CV documents
   - **Source code** - Detects programming code files
   - **Harassment** - Identifies harassing language
   - **Profanity** - Detects profane content
   - **Threat** - Recognizes threatening communications
   - **Offensive language** - Identifies offensive text
   - **Targeted harassment** - Detects targeted attacks

2. **Custom Trainable Classifiers** (Train with your own data):
   - **Training requirements**: 
     * Minimum 50 positive samples (examples of what you want to detect)
     * Minimum 50 negative samples (examples of what you don't want to detect)
     * Up to 500 samples recommended for best accuracy
   - **Process**:
     1. Create classifier and upload positive samples
     2. Train the model (takes 1-24 hours)
     3. Test with additional samples
     4. Publish when accuracy is acceptable (typically >70%)
   - **Examples**:
     * Legal contracts
     * Engineering specifications
     * Marketing materials
     * Financial reports specific to your org

**Use Cases**:
- **Auto-apply sensitivity labels** - Automatically label documents based on content type
- **Retention policies** - Apply different retention to different content types
- **DLP policies** - Prevent leakage of specific document types
- **Communication compliance** - Monitor for inappropriate content types

### Content Explorer & Activity Explorer

**Content Explorer**:
- **Purpose**: View items that have been classified with sensitivity or retention labels
- **Capabilities**:
  - See where sensitive data lives (SharePoint, OneDrive, Exchange)
  - View label distribution across organization
  - Drill down to specific documents
  - Export lists for reporting
- **Permissions**: Requires Content Explorer List viewer or Content Explorer Content viewer roles
- **Use case**: Understand data landscape and label adoption

**Activity Explorer**:
- **Purpose**: Track user activities related to labeled content
- **Activities monitored**:
  - Label applied (manual or automatic)
  - Label changed
  - Label removed
  - File read
  - File modified
  - File deleted
  - File copied
  - File moved
  - File uploaded to cloud
- **Retention**: 30 days of activity data
- **Filtering**: By user, location, label, activity type, date range
- **Use cases**:
  - Audit label usage
  - Detect suspicious data access
  - Monitor compliance with labeling policies
  - Investigate security incidents

---

## 4.6 Sensitivity Labels

### Overview

**What are Sensitivity Labels?**: Persistent, clear-text metadata tags applied to documents and emails that travel with the content and enforce protection settings like encryption, access restrictions, and visual markings.

**Label Actions**:
- **Visual markings** - Header, footer, watermark (e.g., "CONFIDENTIAL" banner)
- **Encryption** - Restrict who can access and what they can do (read, edit, print)
- **Access restrictions** - Control sharing and collaboration
- **Content marking** - Track and identify labeled content
- **Auto-deletion** - Delete after specified period (when used with retention)

### Label Components

#### Label Priority
**Order** (lowest to highest priority):
1. **Public** - No restrictions, anyone can access
2. **General** - Business data, some controls
3. **Confidential** - Sensitive business data, restricted access
4. **Highly Confidential** - Most sensitive, maximum protection

**Inheritance**: 
- Once a higher priority label is applied, users must provide business justification to apply lower priority label
- Prevents accidental downgrade of protection
- Admins can configure justification requirements

#### Scope
**Where can the label be applied?**
- [x] **Files and emails** - Office documents, PDFs, emails
- [x] **Groups and sites** - Microsoft 365 Groups, Teams, SharePoint sites
- [x] **Schematized data assets** - Azure Purview-managed data sources (databases, etc.)

**Scope Impact**:
- Labels with file/email scope appear in Office apps and Outlook
- Labels with group/site scope control privacy and external sharing
- One label can have multiple scopes

### Protection Settings

#### Encryption
**Options**:
1. **Assign permissions now** (admin defines):
   - Specify users, groups, or everyone in organization
   - Define permissions (Co-Author, Reviewer, Viewer, Custom)
   - Set expiration date (optional)
   - Allow offline access control

2. **Let users assign permissions** (user decides):
   - In Outlook: Recipients only, or Forward only
   - In Word/Excel/PowerPoint: User chooses who can access
   - For Do Not Forward in email: Only recipients can read, no forwarding

3. **Remove encryption** (if previously encrypted):
   - Strip encryption from content
   - Useful for public content that was previously sensitive

**Permissions**:
- **Co-Author** - Full edit rights except changing permissions
- **Reviewer** - Can view, edit, save copy (no forwarding in email)
- **Viewer** - Read-only, no copy/paste, no printing
- **Custom** - Granular control (view, edit, copy, print, forward, export, etc.)

**Encryption Technical Details**:
- Uses Azure Rights Management Service (Azure RMS)
- Encryption travels with document
- Works offline (cached licenses)
- Decryption requires authentication

#### Content Marking
**Visual indicators applied to documents**:
- **Header** - Top of each page (e.g., "Confidential - Internal Use Only")
- **Footer** - Bottom of each page (e.g., "Property of Contoso Corporation")
- **Watermark** - Diagonal text across page (e.g., "CONFIDENTIAL")

**Dynamic Variables**:
- `${User.Name}` - Person who applied label
- `${User.PrincipalName}` - Email address
- `${Item.Name}` - Document filename
- `${Item.Location}` - Document path
- `${Date}` - Current date
- `${Label.Name}` - Label name

**Example**: Footer with "Classified by: ${User.Name} on ${Date}"

#### Auto-labeling

**Client-side** (Office applications):
- **Recommends labels** - Suggests label to user with justification
- **Auto-applies labels** - Automatically applies without user interaction
- **Trigger**: When content matches sensitive information types or trainable classifiers
- **User experience**: Tooltip explaining why label is recommended/applied

**Service-side** (Microsoft 365 services):
- **Locations**: SharePoint Online, OneDrive for Business, Exchange Online
- **Automatic application** - Scans existing and new content
- **Conditions**: Based on sensitive info types, trainable classifiers, keywords
- **Simulation mode**: Test before enforcement
- **Processing time**: Can take up to 7 days for large content

**Auto-labeling Configuration**:
1. Choose conditions (e.g., content contains credit card numbers)
2. Set confidence level threshold (60-100%)
3. Define instance count (e.g., at least 10 credit cards)
4. Select locations to apply
5. Choose label to auto-apply
6. Test in simulation mode first

### Label Policies

**What they do**: Control which users can see and apply sensitivity labels, and enforce labeling requirements.

**Policy Settings**:
- [x] **Publish labels to users/groups** - Make labels available to specific users
- [x] **Default label** - Automatically applied to new documents
- [x] **Require justification** - Users must explain when removing/downgrading label
- [x] **Require label on documents** - Block saving unlabeled files
- [x] **Require label on emails** - Block sending unlabeled emails
- [x] **Provide help link** - Custom URL for labeling guidance
- [x] **Apply label to meetings** - Extend labels to Teams/Outlook meetings
- [x] **Apply label to Power BI** - Extend to Power BI datasets and reports

**Policy Deployment**:
- Takes 24 hours for changes to propagate to users
- Can create multiple policies for different user groups
- Priority order if user is in multiple policies

### Common Label Examples

| Label Name | Use Case | Protection Settings |
|------------|----------|---------------------|
| **Public** | Marketing materials, public documents | No encryption, optional watermark, no restrictions |
| **General** | Internal business documents | No encryption, visual markings, internal sharing only |
| **Confidential** | Financial reports, HR data | Encryption for employees only, visual markings, no external sharing |
| **Highly Confidential** | Executive communications, M&A docs | Encryption for specific groups, watermark, no forwarding, expire after 90 days |

**Sub-labels** (hierarchical structure):
- Confidential
  - Confidential \ HR
  - Confidential \ Finance
  - Confidential \ Legal
- Highly Confidential
  - Highly Confidential \ Executives Only
  - Highly Confidential \ Board Members

---

## 4.7 Data Loss Prevention (DLP)

### Overview

**What is DLP?**: Data Loss Prevention identifies, monitors, and automatically protects sensitive information across Microsoft 365 services, devices, and cloud apps to prevent accidental or malicious data leakage.

**Goals**:
- **Identify sensitive data** - Discover where sensitive information lives
- **Monitor data usage** - Track how sensitive data is being used and shared
- **Prevent accidental sharing** - Block or warn when users try to share inappropriately
- **Educate users** - Teach proper data handling through policy tips and notifications

### DLP Locations

**Where DLP Works**:
- [x] **Exchange Online** - Emails and attachments
- [x] **SharePoint Online** - Documents in sites and libraries
- [x] **OneDrive for Business** - Personal file storage
- [x] **Teams chat and channels** - Messages and shared files
- [x] **Windows 10/11 devices** - Endpoint DLP (local files, apps, browsers)
- [x] **macOS devices** - Endpoint DLP for Apple computers
- [x] **Cloud apps** - Third-party SaaS via Defender for Cloud Apps
- [x] **On-premises repositories** - File shares via scanner
- [x] **Power BI** - Datasets, reports, dashboards

### DLP Policies

#### Policy Components

**1. Content to Protect** (What to look for):
- **Sensitive information types** - Credit cards, SSN, passport numbers (300+ built-in)
- **Sensitivity labels** - Content already labeled as confidential
- **Retention labels** - Content marked as records
- **Trainable classifiers** - ML-identified content types
- **Exact data match** - Specific values from database (e.g., employee list)

**2. Conditions** (When to trigger):
- **Content contains** - Sensitive info types, keywords, labels
- **Content is shared** - With people outside organization, specific domains
- **Document properties** - Size, file extension, created by
- **Sender/recipient** - Specific users or groups
- **Recipient domain** - External domains, specific partners
- **Instance count** - Number of sensitive items (e.g., >= 10 credit cards)
- **Confidence level** - How certain the detection is (low/medium/high)

**3. Actions** (What to do):
- [x] **Block access** - Prevent opening encrypted email
- [x] **Block sharing** - Stop external sharing in SharePoint/OneDrive
- [x] **Restrict access** - Limit to specific people
- [x] **Encrypt email** - Apply rights management
- [x] **Quarantine email** - Hold for admin review
- [x] **Remove external recipients** - Strip external addresses from email
- [x] **Send notifications** - Alert users, managers, or security team
- [x] **Generate alerts** - Create alerts in compliance portal
- [x] **Create incidents** - Group related violations for investigation

**4. User Notifications**:
- **Policy tips** - In-app notifications explaining violation
  * "This document contains credit card numbers and cannot be shared externally"
- **Email notifications** - Sent to user after violation
  * Include violation details, affected content, remediation guidance
- **Override options** - Allow users to override block with justification
  * Business justification required
  * False positive reporting
  * Admin approval required

#### Policy Modes
- **Test with policy tips** - Show tips to users but don't enforce blocks (recommended for new policies)
- **Test without policy tips** - Simulate silently, log violations, no user notification
- **Turn on immediately** - Full enforcement, blocks and notifications active

**Best Practice**: Always test new DLP policies before full enforcement to avoid disrupting business operations and assess false positive rate.

### Endpoint DLP

**What it protects** (Windows 10/11 and macOS):
- **Local files** - Documents on device hard drive
- **Network shares** - Mapped drives, UNC paths
- **Removable media** - USB drives, external hard drives
- **Browsers** - Edge, Chrome, Firefox (upload/download monitoring)
- **Cloud storage** - Personal OneDrive, Google Drive, Dropbox uploads
- **Print activities** - Physical and virtual printers

**Actions**:
- **Audit** - Log activity only, no blocking
- **Block** - Prevent action completely
- **Block with override** - User can override with business justification
- **Warn** - Show warning, user can proceed

**Activities Monitored**:
- **Copy to clipboard** - Copying sensitive data
- **Copy to USB** - Saving to removable media
- **Copy to network share** - Saving to file shares
- **Print** - Physical or PDF printing
- **Upload to cloud** - Personal cloud storage services
- **Share via app** - Messaging apps, collaboration tools
- **Rename/move/delete** - File operations on sensitive content
- **Access by unallowed apps** - Restrict which apps can open sensitive files

**File Activity Monitoring**:
- Monitors sensitive files across all locations
- Detects sensitive content using DLP conditions
- Works even when files are offline
- Integrates with Microsoft 365 Compliance portal

**Requirements**:
- Windows 10 version 1809+ or macOS Catalina+
- Onboarded to Microsoft 365 compliance
- DLP policy with endpoint location enabled
- E5 or Compliance add-on license

### DLP Alerts & Reports

**Alerts Dashboard**:
- **Severity levels** - High, Medium, Low, Informational
- **Alert volume** - Trends over time
- **Top policies** - Which policies trigger most
- **Top users** - Who triggers violations most
- **Top locations** - Where violations occur (Exchange, SharePoint, Endpoint)

**Reports Available**:
- **DLP policy matches** - How many times policies were triggered
- **DLP incidents** - Grouped violations requiring investigation
- **False positives** - User-reported incorrect blocks
- **Override requests** - When users override policy blocks
- **Third-party DLP** - Violations in connected cloud apps

**Alert Configuration**:
- Choose which policy violations generate alerts
- Set alert thresholds (e.g., alert after 5 violations in 1 hour)
- Configure severity based on rule type
- Send email notifications to admins
- Aggregate related alerts into incidents

**Investigation Workflow**:
1. Alert triggered by policy violation
2. Review details (user, content, location, rule matched)
3. View content and activity timeline
4. Determine if true positive or false positive
5. Take action (close, escalate, update policy)
6. Document resolution

---

## 4.8 Retention & Records Management

### Retention Policies

**What they are**: Organization-wide or location-wide settings that specify how long to keep content and what to do when the retention period ends (delete or keep).

**Retention Actions**:
1. **Retain only** - Keep for specified period, don't delete (for compliance archiving)
2. **Delete only** - Delete after specified period (for data minimization)
3. **Retain then delete** - Keep for period, then automatically delete (most common)

**Retention Locations**:
- [x] **Exchange email** - User mailboxes, shared mailboxes
- [x] **SharePoint sites** - All sites or specific sites
- [x] **OneDrive accounts** - All accounts or specific users
- [x] **Microsoft 365 Groups** - Group mailboxes and sites
- [x] **Skype for Business** - Conversations
- [x] **Teams messages** - Chat and channel messages
- [x] **Teams private channels** - Private channel messages
- [x] **Yammer community messages** - Community posts
- [x] **Yammer user messages** - Private messages

#### Retention Period
**Start date options**:
- **When created** - From content creation date
- **Last modified** - From last modification date (resets timer with each edit)
- **Labeled** - From when retention label was applied
- **Event-based** - From when specific event occurs (employee departure, contract expiration, product end-of-life)

**Duration**: 
- Specific number of days, months, or years
- Forever (indefinite retention)
- Examples: 7 years, 90 days, 10 years, forever

**Example Scenarios**:
- **Email**: Retain 7 years from creation, then delete (legal requirement)
- **Contracts**: Retain 10 years after last modification
- **HR records**: Retain 7 years after employee departure (event-based)

#### Adaptive Scopes
**What they are**: Dynamic groups that automatically update membership based on attributes, replacing static location selection.

**Query-based Targeting**:
- Department = "Finance" → All Finance users
- CustomAttribute1 = "Legal" → All sites tagged Legal
- Location = "New York" → All NY-based users

**Examples**:
- All users in Finance department → Policy applies to new Finance employees automatically
- All sites with tag "Legal" → New legal sites automatically included
- All accounts where JobTitle contains "Executive" → Dynamic executive retention

**Benefits**:
- No manual policy updates when users/sites change
- Scalable for large organizations
- Consistent policy application
- Reduces administrative overhead

### Retention Labels

**What they are**: Item-level retention settings that can be manually or automatically applied to individual documents and emails, providing more granular control than policies.

**Differences from Policies**:

| Feature | Retention Policy | Retention Label |
|---------|------------------|-----------------|
| **Scope** | Location-wide (all content in Exchange, SharePoint, etc.) | Item-level (individual documents/emails) |
| **User Application** | No (applied automatically to location) | Yes (users can manually apply in Office/Outlook) |
| **Auto-apply** | Applies to all content by default | Requires conditions (keywords, sensitive info types) |
| **Portability** | No (stays with location) | Yes (moves with content when copied/moved) |
| **Priority** | Lower | Higher (label overrides policy if both apply) |
| **Visibility** | Not visible to users | Visible in Office apps and Outlook |

**Label Actions**:
- **Apply retention** - Keep for period, then delete or keep forever
- **Mark as record** - Prevent modification/deletion, allow some edits
- **Mark as regulatory record** - Prevent all modifications, maximum restrictions

**Auto-apply Conditions**:
- Content contains keywords (e.g., "trade secret", "confidential")
- Sensitive information types (credit cards, SSN)
- Trainable classifiers (contracts, source code)
- Cloud attachments (SharePoint/OneDrive links in email)
- Properties (author, subject line, file extension)

**Manual Application**:
- Users select label from ribbon in Office apps
- Right-click in SharePoint/OneDrive
- Outlook email properties
- Default label can be configured

### Records Management

**What is a Record?**: Content designated as official business record that must be preserved for regulatory, legal, or business reasons. Records have restrictions on modification and deletion.

**Record Types**:

#### Record (Standard)
**Properties**:
- **Can't be deleted** - Users cannot delete records
- **Can be edited** - Limited edits allowed (some fields lockable)
- **Metadata locked** - Classification metadata cannot be changed
- **Disposition required** - Must be reviewed before final deletion
- **Audit trail** - All actions logged

**Allowed Actions**:
- Edit content (unless version lock enabled)
- Move within same location
- Add metadata
- Unlock for editing (if versioning enabled)

**Blocked Actions**:
- Delete
- Remove label
- Modify locked metadata

#### Regulatory Record (Maximum Restrictions)
**Properties**:
- **Can't be deleted** - Not even by admins
- **Can't be edited** - No modifications allowed once declared
- **Metadata locked** - All metadata immutable
- **Label can't be removed** - Even Global Admins cannot remove label
- **Must meet disposition** - Mandatory review before deletion

**Use Cases**:
- **Legal hold** - Litigation-related documents
- **Regulatory requirements** - SEC, FINRA, HIPAA mandated retention
- **Intellectual property** - Patents, trade secrets
- **Government contracts** - Records required for compliance
- **Financial statements** - Audited financial records

**Comparison**:
| Feature | Regular Content | Record | Regulatory Record |
|---------|----------------|--------|-------------------|
| **Delete** | Yes | No | No |
| **Edit** | Yes | Limited | No |
| **Remove Label** | Yes | No | No (even admin) |
| **Admin Override** | N/A | Yes | No |

### File Plan

**What it is**: Metadata framework for organizing and managing records based on business functions, providing structure similar to traditional file cabinets.

**Descriptors** (Custom metadata fields):
- **Function** - Business function (HR, Finance, Legal, IT)
- **Category** - Sub-category within function (Payroll, Accounts Receivable)
- **Sub-category** - Further classification (W-2 Forms, Invoices)
- **Authority type** - Legal basis (Regulatory, Legal, Business)
- **Provision/Citation** - Specific regulation (SOX Section 404, GDPR Article 17)

**File Plan Structure Example**:
```
Function: Human Resources
  Category: Employee Records
    Sub-category: Hiring Documents
      Records: Resumes, Offer Letters, I-9 Forms
      Retention: 7 years after termination
      Authority: DOL regulations
```

**Use Case**: 
- Organize records systematically
- Document retention decisions
- Provide clear audit trail
- Support compliance reporting
- Enable consistent classification

**Export/Import**: File plan can be exported to Excel for review and imported for bulk updates.

### Disposition

**What it is**: The process that occurs at the end of a retention period, determining what happens to content.

**Disposition Options**:
1. **Automatic deletion** - Content deleted without review
2. **Disposition review** - Manual review required before deletion
3. **Event-based disposition** - Triggered by specific events

**Disposition Review Process**:
1. Content reaches end of retention period
2. Notification sent to disposition reviewers
3. Reviewer examines content
4. Decision made:
   - **Approve deletion** - Permanently delete
   - **Extend retention** - Keep longer with same or different label
   - **Relabel** - Apply new retention label
5. Action taken and logged

**Disposition Proof**:
- **Audit trail** - Complete record of disposition actions
- **What was deleted** - File names, locations, metadata
- **When** - Date and time of deletion
- **By whom** - User who approved deletion
- **Reason** - Why content was deleted
- **Certification** - Proof for compliance auditors

**Disposition Report**: Export evidence of compliance with retention requirements, showing all disposed content.

---

## 4.9 Insider Risk Management

### Overview

**What is Insider Risk?**: Potential harm to an organization caused by people with authorized access—either malicious actions or unintentional mistakes that expose the organization to threats.

**Risk Types**:
- **Data theft** - Stealing intellectual property before leaving company
- **Data leaks** - Accidental or intentional sharing of sensitive information
- **Security violations** - Bypassing security controls, installing unauthorized software
- **Compliance violations** - Violating regulatory requirements or company policies
- **Sabotage** - Intentional harm to systems or data
- **IP theft** - Stealing trade secrets, source code, customer lists

**Privacy by Design**: 
- **Pseudonymization** - User identities hidden by default, shown as User1, User2
- **Role-based access** - Only authorized investigators see actual identities
- **Audit trail** - All access to user identities logged
- **RBAC permissions** - Granular control over who can investigate

### Policy Templates

| Template | Detects | Example Scenario |
|----------|---------|---------|
| **Data theft by departing users** | Exfiltration before termination | Employee downloads all customer lists 2 days before resignation |
| **General data leaks** | Unusual data movement | User uploads sensitive files to personal Dropbox |
| **Data leaks by priority users** | Executives/high-risk users | CFO emails financial data to personal account |
| **Data leaks by disgruntled users** | Users with negative indicators | Employee with poor performance review copies source code |
| **Security policy violations** | Breaking security rules | User disables antivirus, installs unauthorized software |
| **Patient data misuse** (Healthcare) | HIPAA violations | Nurse accesses records of family members without legitimate need |
| **Data leaks by risky users** | High-risk behavior patterns | User with prior violations downloads sensitive data |
| **Offensive language** | Inappropriate communications | Employee sends harassing messages in Teams |

**Policy Configuration**:
- Choose template
- Select indicators to monitor
- Define thresholds (how many violations trigger alert)
- Set priority users (executives, admins, developers)
- Configure HR integration for context
- Set alert volumes (reduce noise)

### Risk Indicators

**Activity Examples** (Signals tracked):

**File Activities**:
- Downloading large volumes of files
- Copying files to USB or external drive
- Uploading to personal cloud storage (Dropbox, Google Drive)
- Printing unusual amounts of documents
- Accessing files outside normal work hours
- Accessing files unrelated to job function

**Email Activities**:
- Forwarding to personal email
- Sending to competitors
- Emailing large attachments externally
- Using encrypted email services

**Browser Activities**:
- Accessing job search sites frequently
- Visiting competitor websites
- Researching data wiping tools
- Accessing dark web sites

**Device Activities**:
- Connecting new USB devices
- Using screen capture tools excessively
- Disabling security software
- Attempting to bypass DLP policies

**Communication Activities**:
- Negative sentiment in communications
- Discussing company secrets in personal chat
- Planning sabotage activities

**HR Indicators** (Context from HR data):
- Resignation submitted
- Termination pending
- Poor performance review
- Demotion
- Passed over for promotion
- Compensation disputes

### Workflow

**1. Policy Creation**:
- Admin creates policy from template
- Configures indicators and thresholds
- Assigns users to monitor (all, groups, or specific users)
- Sets sensitivity level

**2. User Triggering Events**:
- **HR triggers**: Termination date, resignation notice (imported from HR system)
- **Activity triggers**: Threshold exceeded (e.g., 100+ file downloads in 24 hours)
- **Sequence triggers**: Multiple risky activities in pattern (download → USB copy → personal email)

**3. Risk Scoring** (Machine Learning):
- **ML algorithms** analyze user behavior against baseline
- **Historical patterns** - Compare to user's normal activity
- **Peer comparison** - Compare to similar users (role, department)
- **Anomaly detection** - Identify unusual deviations
- **Risk score** - 0-100 scale (low, medium, high)
- **Dynamic scoring** - Updates as new activities occur

**4. Alerts**:
- Generated when risk score crosses threshold
- Severity level assigned (low/medium/high)
- Provides summary of risky activities
- Pseudonymized user identifier

**5. Investigation**:
- **Activity timeline** - Chronological view of user actions
- **File access history** - What files accessed, when, from where
- **Device activity** - USB connections, screen captures, downloads
- **Email analysis** - Recipients, content scanning results
- **Communication review** - Teams/email sentiment analysis
- **User profile** - Job role, department, manager, tenure
- **Notes** - Investigators can add annotations

**6. Case Management**:
- **Escalate to case** - Formal investigation with case number
- **Notify manager** - Alert user's supervisor (configurable)
- **Collect evidence** - Gather logs, files, communications
- **User notification** - Optional alert to user being investigated
- **Remediation actions**:
  * Coaching/training
  * Policy enforcement
  * Account restrictions
  * Legal action
- **Case resolution** - Document outcome and close case

### Integration

**HR Connectors**:
- Import termination dates
- Performance review data
- Organizational hierarchy
- Job role changes
- Compensation information

**Physical Badging Systems**:
- After-hours access
- Access to sensitive areas
- Badge usage patterns

**VPN Logs**:
- Remote access patterns
- Geographic anomalies

**DLP Policies**:
- DLP violations trigger risk scoring
- Coordinated response to data leaks

**Microsoft Defender for Endpoint**:
- Device security posture
- Malware detections
- Security violations

---

## 4.10 Communication Compliance

### Overview

**What is Communication Compliance?**: Monitoring and reviewing communications (email, Teams, Yammer) to detect regulatory violations, inappropriate content, and policy breaches.

**Regulatory Drivers**:
- **SEC** (Securities and Exchange Commission) - Financial services communications
- **FINRA** (Financial Industry Regulatory Authority) - Broker-dealer communications
- **MiFID II** (Markets in Financial Instruments Directive) - EU financial markets
- **GDPR** - Privacy violations in communications
- **Internal policies** - Code of conduct, acceptable use policies

**Key Principle**: Proactive detection of problematic communications before they cause harm.

### Policy Types

**Built-in Templates**:
- [x] **Detect inappropriate text** - Profanity, threats, harassment, discrimination
- [x] **Detect inappropriate images** - Adult content, violent imagery, offensive memes
- [x] **Detect sensitive information** - PII, financial data, health information shared inappropriately
- [x] **Monitor compliance keywords** - Regulatory terms, banned phrases (stock tips, inside information)
- [x] **Detect conflicts of interest** - Unauthorized external communications, competitor contacts
- [x] **Customer interactions** - Quality assurance for customer-facing communications
- [x] **Regulatory compliance** - SEC/FINRA required supervision of communications

**Custom Policies**:
- Define custom conditions
- Combine multiple detectors
- Set specific thresholds
- Target specific user groups

### Detection Methods

#### Text Classification (Machine Learning)
**Detects**:
- **Threats** - Violence, physical harm, terrorism
- **Harassment** - Bullying, intimidation, hostile work environment
- **Profanity** - Explicit language, cursing
- **Adult content** - Sexual content, inappropriate discussions
- **Discrimination** - Racial, gender, religious, age discrimination
- **Targeted harassment** - Personalized attacks against individuals
- **Negative sentiment** - Hostile tone, aggression

**How it works**:
- Pre-trained ML models analyze text
- Contextual understanding (not just keyword matching)
- Multi-language support
- Continuous model updates from Microsoft

#### Image Classification (Computer Vision)
**Detects**:
- **Adult images** - Sexually explicit content
- **Racy images** - Suggestive but not explicit content
- **Gory images** - Violence, blood, injury
- **Weapons** - Guns, knives, weapons
- **Offensive symbols** - Hate symbols, inappropriate imagery

**Technology**:
- Azure Cognitive Services
- OCR (Optical Character Recognition) - Reads text in images
- Meme detection - Identifies offensive memes
- Confidence scoring - Low/Medium/High confidence

#### Sensitive Information Types
**Detects**:
- **PII** - SSN, passport numbers, driver's licenses shared in communications
- **Financial data** - Credit cards, bank accounts discussed inappropriately
- **Health information** - PHI/ePHI in non-secure channels
- **Custom types** - Organization-specific sensitive patterns

**Use case**: Prevent accidental disclosure of sensitive data in casual communications.

#### Custom Conditions
- **Keywords** - Specific terms to monitor
- **Regex patterns** - Custom patterns (e.g., internal project codenames)
- **Trainable classifiers** - ML models trained on your content
- **Sender/recipient** - Monitor specific users or external contacts
- **Direction** - Inbound, outbound, internal

### Monitored Channels

**Microsoft Services**:
- [x] **Microsoft Teams** - Chat messages, channel posts, private channels
- [x] **Exchange Online** - Email messages and attachments
- [x] **Yammer** - Community posts and private messages
- [x] **Skype for Business** - IM conversations (legacy)

**Third-party Sources** (via connectors):
- [x] **Bloomberg** - Financial messaging
- [x] **Thomson Reuters** - Trading communications
- [x] **LinkedIn** - Business messages
- [x] **Custom connectors** - Any messaging platform with API

**Coverage**:
- Real-time monitoring of new messages
- Historical review of past communications
- Attachments analyzed (documents, images, files)
- Meeting invites and responses

### Review Workflow

**1. Policy Match**:
- Message scanned when sent/received
- Conditions evaluated (text, images, sensitive data)
- Policy rules applied
- Match confidence scored

**2. Alert Generation**:
- Alert created for policy violations
- Severity assigned based on violation type
- Message queued for review
- Metadata collected (sender, recipients, timestamp, channel)

**3. Reviewer Investigation**:
- **View message** - Full context of communication
- **View thread** - Conversation history (email chain, Teams conversation)
- **User history** - Past violations by this user
- **Pattern analysis** - Frequency and types of violations
- **Related activities** - Other flagged communications
- **OCR results** - Text extracted from images
- **Translation** - Non-English content translated

**4. Remediation Actions**:
- **Resolve as compliant** - False positive, no violation
- **Resolve as non-compliant** - Confirmed violation, documented
- **Notify sender** - Educate user about policy
- **Notify manager** - Escalate to supervisor
- **Escalate for investigation** - Create formal case
- **Remove message** - Delete from Teams/Yammer (if enabled)
- **Tag for training** - Use for future policy improvements

**5. Audit Trail**:
- All review decisions logged
- Reviewer actions tracked
- Time spent on each review recorded
- Compliance reporting generated

### Key Features

**Optical Character Recognition (OCR)**:
- Extracts text from images
- Detects inappropriate text in memes, screenshots
- Scans embedded images in documents
- Supports 20+ languages

**Conversation Threading**:
- Groups related messages together
- Shows full conversation context
- Email chains properly linked
- Teams conversations threaded

**Translation Support**:
- Auto-translate non-English content
- 50+ languages supported
- Helps global organizations maintain consistent policies

**Pattern Matching**:
- Detect repeated violations
- Identify coordinated misconduct
- Track escalation patterns
- Behavioral trend analysis

**Privacy Controls**:
- Reviewer access logs
- Pseudonymization options
- RBAC for sensitive reviews
- Compliance with privacy regulations

**Reporting**:
- Policy effectiveness metrics
- Top violators and violation types
- Response time analytics
- Trend analysis over time
- Regulatory compliance reports

---

## 4.11 Information Barriers

### Overview

**What are Information Barriers?**: Policies that restrict or allow communication and collaboration between specific groups of users to prevent conflicts of interest and protect confidential information, commonly required in regulated industries.

**Purpose**: Prevent conflicts of interest and unauthorized information sharing between groups that should be isolated (e.g., competing deal teams, conflicting client representations).

**Use Cases**:
- **Prevent insider trading** - Separate investment banking from trading desks
- **Separate competing deal teams** - M&A teams working on competing acquisitions
- **Protect confidential information** - Legal teams with conflicting client matters
- **Regulatory compliance** - Meet SEC, FINRA, MiFID II requirements
- **Chinese Wall** - Traditional financial services information barriers

**Industries**: Financial services, legal firms, consulting, healthcare, government

### How They Work

**Segments**: Groups of users defined by attributes
- **Finance team** - Department = Finance
- **M&A Team A** - CustomAttribute1 = DealA
- **M&A Team B** - CustomAttribute1 = DealB
- **Trading desk** - JobTitle contains "Trader"
- **Investment banking** - Department = Investment Banking

**Segment Creation**:
- Based on Azure AD attributes (Department, Title, Office, CustomAttribute1-15)
- PowerShell or admin center
- Dynamic membership (updates automatically)
- Can combine multiple attributes

**Policies**:
1. **Block policies** - Prevent communication between segments
   - Example: Block M&A Team A from communicating with M&A Team B
   
2. **Allow policies** - Permit communication (in strict mode)
   - Example: Allow Finance team to communicate with Audit team
   - Only needed when using strict mode

**Policy Logic**:
- If Segment A is blocked from Segment B, users cannot:
  * Add to Teams chats/channels
  * Search for users in people picker
  * @mention in messages
  * Add to meetings
  * Share files in OneDrive
  * Access SharePoint sites

### Enforcement Points

**Microsoft Teams**:
- **Chats** - Cannot start 1:1 or group chats with blocked segments
- **Channel messages** - Cannot @mention or add blocked users to channels
- **Meetings** - Cannot invite blocked users to meetings
- **Private channels** - Blocked users cannot be added

**OneDrive for Business**:
- **User lookup** - Blocked users don't appear in sharing picker
- **File sharing** - Cannot share files with blocked segments
- **Folder collaboration** - Cannot add to shared folders

**SharePoint**:
- **Site access** - Blocked users cannot be added to sites
- **Sharing** - Cannot share content with blocked segments
- **Search** - Blocked users don't appear in people search

**Outlook/Exchange**:
- Not directly enforced (design limitation)
- Organizations use mail flow rules for email barriers
- Consider using separate mail-enabled security groups

**Viva Engage (Yammer)**:
- Community membership restrictions
- Private message limitations

### Implementation Steps

**1. Define Segments**:
```powershell
New-OrganizationSegment -Name "M&A Team A" -UserGroupFilter "CustomAttribute1 -eq 'DealA'"
New-OrganizationSegment -Name "M&A Team B" -UserGroupFilter "CustomAttribute1 -eq 'DealB'"
```

**2. Create Policies**:
```powershell
New-InformationBarrierPolicy -Name "Block DealA from DealB" -AssignedSegment "M&A Team A" -SegmentsBlocked "M&A Team B" -State Active
```

**3. Apply Policies**:
```powershell
Start-InformationBarrierPoliciesApplication
```
- Takes 24-48 hours to fully apply
- Processes in batches
- Status tracking available

**4. Monitor Compliance**:
- Review policy application status
- Check for conflicts (policy incompatibilities)
- Monitor user issues
- Audit logs track enforcement

### Modes

**Open Mode** (Default):
- Allow unless explicitly blocked
- Users can communicate freely except where barriers exist
- Suitable for organizations with limited barrier needs

**Strict Mode**:
- Block unless explicitly allowed
- Requires allow policies for any cross-segment communication
- More restrictive and controlled
- Suitable for highly regulated environments

**Example Strict Mode**:
```
Segment A: Can only communicate with Segment B (allowed)
Segment B: Can only communicate with Segment A (allowed)
Segment C: Cannot communicate with A or B (default block)
```

### Considerations

**Planning**:
- Map organizational structure before implementing
- Identify which groups need isolation
- Consider business workflows that cross segments
- Plan exception handling

**User Experience**:
- Users see "You can't add this person" messages
- Education needed about why barriers exist
- Clear communication to affected users

**Limitations**:
- Doesn't enforce email barriers directly
- Guest users not supported
- External users not affected
- Takes time to propagate changes

**Troubleshooting**:
- Policy conflicts can prevent application
- Check segment membership accuracy
- Verify Azure AD attributes are correct
- Use Get-InformationBarrierPoliciesApplicationStatus

---

## 4.12 eDiscovery

### Overview

**What is eDiscovery?**: Electronic Discovery—the process of identifying, collecting, reviewing, and producing electronic information in response to legal requests, investigations, or litigation.

**Typical eDiscovery Process** (EDRM Model):
1. **Identification** - Determine what data is relevant
2. **Preservation** - Place legal holds to prevent deletion
3. **Collection** - Gather relevant data
4. **Review** - Examine content for responsiveness and privilege
5. **Analysis** - Find patterns, key documents, themes
6. **Production** - Export data in required format for attorneys/regulators

**Microsoft 365 eDiscovery Solutions**:
- Content Search - Simple searches without case management
- eDiscovery (Standard) - Basic case management and legal holds
- eDiscovery (Premium) - Advanced analytics and custodian management

### eDiscovery (Standard)

**Capabilities**:
- **Create cases** - Organize investigations by case number/name
- **Case members** - Control who can access each case
- **Place holds** - Preserve content in place (legal holds)
- **Search for content** - KQL-based searches across locations
- **Preview results** - Review items before exporting
- **Export search results** - Download for review in external tools
- **Reports** - Summary statistics and export reports

**Search Locations**:
- **Exchange mailboxes** - User and shared mailboxes, inactive mailboxes
- **SharePoint sites** - All sites or specific site collections
- **OneDrive accounts** - Individual user OneDrive storage
- **Microsoft Teams** - Chat messages, channel messages, files
- **Microsoft 365 Groups** - Group mailbox and SharePoint site
- **Skype for Business** - Conversations
- **Yammer** - Messages and files

**Hold Types**:
- **Query-based hold** - Hold content matching specific criteria
- **All content hold** - Hold everything in selected locations
- **Hold duration** - Indefinite until manually released

**Use Cases**:
- Basic legal holds for litigation
- Simple internal investigations
- Small-scale document collections
- Regulatory inquiries
- HR investigations

**Licensing**: Included with E3, E5, Business Premium licenses

### eDiscovery (Premium)

**Additional Capabilities**:

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Custodian Management** | Track individuals and their data sources | Centralized management of people under investigation |
| **Legal Hold Notifications** | Automated hold notice workflow | Send, track, and manage hold notifications with reminders |
| **Advanced Indexing** | Re-index partially indexed items | Ensure all content is searchable, including attachments |
| **Review Sets** | Dedicated workspace for review | Load search results into review set for detailed analysis |
| **Analytics** | Near-duplicate, email threading, themes | Reduce review time by identifying similar documents |
| **Predictive Coding** | ML-based relevance ranking | Train model to identify relevant documents automatically |
| **Conversation Threading** | Group related messages | See complete conversation context |
| **Case Management** | Advanced workflow tools | Manage large, complex cases with multiple reviewers |
| **Tagging** | Apply tags during review | Mark documents as responsive, privileged, or irrelevant |
| **Redaction** | Mask sensitive information | Protect privacy before production |
| **Export Options** | Multiple formats | Native files, text, PDFs, load files for review platforms |

**Advanced Analytics Features**:

**Near-Duplicate Detection**:
- Identifies documents with similar content
- Groups nearly identical files together
- Reduces redundant review
- Example: Multiple versions of same contract

**Email Threading**:
- Groups email conversations
- Shows conversation hierarchy
- Identifies unique messages vs. repeated content
- Review entire thread efficiently

**Themes**:
- ML identifies topics/themes across documents
- Groups documents by subject matter
- Find documents about specific topics
- Example: All documents mentioning "acquisition terms"

**Relevance Analysis** (Predictive Coding):
- Train ML model with sample documents
- Model predicts relevance of remaining documents
- Prioritize most relevant documents for review
- Significantly reduces review time and costs

**Advanced Indexing**:
- Re-processes partially indexed items
- Handles complex file types
- Extracts text from images (OCR)
- Processes encrypted content when possible

### Content Search

**What it is**: Standalone search tool (not part of a case) for quick searches across Microsoft 365 services.

**When to Use**:
- Quick ad-hoc searches
- No need for case management
- Simple export requirements
- Preliminary investigation
- Compliance checks

**Search Query Language**: KQL (Keyword Query Language)

**Example KQL Searches**:
```
subject:"confidential" AND from:user@domain.com
- Finds emails with "confidential" in subject from specific user

from:competitor.com AND received>=2024-01-01
- Emails from competitor domain since Jan 1, 2024

filetype:pdf AND author:"John Smith"
- PDF files authored by John Smith

size>10MB AND (kind:meetings OR kind:contacts)
- Large calendar items or contacts

documentdate>=2023-01-01 AND documentdate<=2023-12-31
- Documents created in 2023
```

**Conditions (GUI-based)**:
- Date range
- Sender/Author
- Size
- Subject/Title
- File type
- Compliance tag (retention/sensitivity labels)
- Message kind (email, meeting, task, etc.)

**Search Permissions Filtering**: 
- Limit what specific investigators can search
- Filter by user (can only search certain mailboxes)
- Filter by site (can only search certain sites)
- Compliance boundary enforcement

**Export Options**:
- Exchange content (PST or individual messages)
- SharePoint/OneDrive (native files or folder structure)
- Metadata and load file for review platforms
- De-duplication options
- Download or Azure export

**Limitations**:
- No legal hold capability (use eDiscovery cases for holds)
- Limited analytics (no near-duplicate or threading)
- Results limited to 1000 items for preview
- Export size limits apply

---

## 4.13 Audit Solutions

### Overview

**Why Audit?**:
- **Track user activities** - Monitor what users do with data
- **Investigate incidents** - Forensic analysis of security events
- **Meet compliance requirements** - Many regulations require audit logs
- **Detect threats** - Unusual activities may indicate compromise
- **Forensic analysis** - Reconstruct events after incidents

**Microsoft 365 Audit Solutions**:
- Audit (Standard) - Basic auditing, 90-day retention
- Audit (Premium) - Advanced auditing, longer retention, high-value events

### Audit (Standard)

**What it logs**:
- **User activities** - File access, document downloads, sharing
- **Admin activities** - Configuration changes, user management
- **File operations** - Created, modified, deleted, renamed, moved
- **Email events** - Send, receive, delete, folder operations
- **SharePoint activities** - Site access, permission changes, file downloads
- **Teams activities** - Team creation, member changes, message posted
- **Azure AD events** - Sign-ins, password changes, role assignments
- **Exchange admin** - Mailbox changes, permission grants

**Retention**: 90 days (default, non-configurable in Standard)

**Search Capabilities**:
- **Date range** - Specify start and end dates (up to 90 days)
- **User** - Search activities by specific user or all users
- **Activity** - Select from 200+ activity types
- **Location (IP)** - Filter by IP address or range
- **Workload** - Exchange, SharePoint, Azure AD, Teams, etc.

**Common Activities**:
- **FileAccessed** - File opened or accessed
- **FileDownloaded** - File downloaded to local device
- **FileSyncDownloadedFull** - File synced with OneDrive client
- **SendAs** - Email sent as another user
- **New-InboxRule** - New email rule created (potential exfiltration)
- **Set-Mailbox** - Mailbox configuration changed
- **MemberAdded** - User added to group or team
- **SiteCollectionAdminAdded** - Site admin permissions granted
- **UserLoggedIn** - Successful sign-in to Azure AD

**Export**:
- CSV format (opens in Excel)
- Up to 50,000 results per export
- PowerShell for larger exports (Search-UnifiedAuditLog)
- Results can be filtered and analyzed

**Availability**:
- Enabled by default for all organizations
- No additional license required
- Included with E3, E5, Business Premium

### Audit (Premium)

**Additional Features**:

| Feature | Standard | Premium |
|---------|----------|---------|
| **Retention** | 90 days | 1 year (default), 10 years available |
| **High-value Events** | No | Yes (MailItemsAccessed, Send, SearchQueryInitiated) |
| **Bandwidth** | Standard API limits | Higher API limits for export |
| **Retention Policies** | No | Custom retention (1-10 years) |
| **Intelligent Insights** | No | Anomaly detection, unusual access patterns |
| **Priority Account Logging** | No | Enhanced logging for VIP accounts |

**High-Value Events** (Premium-only):

**MailItemsAccessed**:
- Tracks every time email is accessed
- Critical for breach investigations
- Determine what attacker read
- Protocol: MAPI, POP3, IMAP, OWA
- Helps answer: "What emails did the attacker access?"

**Send**:
- Tracks when email is sent
- More detailed than standard SendAs events
- Includes message details
- Critical for data exfiltration investigations

**SearchQueryInitiatedExchange**:
- Tracks mailbox searches
- What search terms were used
- How many results returned
- Detect attackers searching for sensitive data

**SearchQueryInitiatedSharePoint**:
- Tracks SharePoint/OneDrive searches
- Search terms and results count
- Identify data discovery attempts

**Intelligent Insights**:
- ML-based anomaly detection
- Unusual access patterns (time, location, volume)
- Behavioral baselines per user
- Automated alerts for suspicious activity

**Long-term Retention**:
- Default: 1 year for all users
- Optional: 10 years (requires add-on license)
- Create audit retention policies for specific record types
- Compliance with regulations requiring long retention

**Priority Account Logging**:
- Enhanced logging for VIP users (executives, admins)
- More detailed activities captured
- Faster visibility into high-risk account activities
- Configure in Audit settings

**Licensing**: Requires E5 or Compliance add-on license

### Audit Log Search

**Search Criteria**:
- **Activities** - Choose from 200+ activity types or "All activities"
- **Date range** - Start and end date/time (precision to minute)
- **Users** - Specific users, all users, or user list
- **File/folder/site** - Specific item or location
- **IP address** - Filter by IP or range

**Search Interface**:
- Web-based search in compliance portal
- PowerShell (Search-UnifiedAuditLog) for advanced queries
- Microsoft Graph API for integration

**Results Display**:
- Date/time of activity
- User who performed action
- Activity type
- Item affected (file, mailbox, site)
- Additional details (IP, client, UserAgent)

**Export Options**:
- **CSV** - Up to 50,000 results per export
- **JSON** - For programmatic processing
- **PowerShell** - Unlimited results (iterate through batches)
- **SIEM integration** - Stream to Sentinel, Splunk, etc.

**Advanced PowerShell Examples**:
```powershell
# Search last 7 days for specific user
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds user@contoso.com

# Export large result set
$results = @()
Do {
    $logs = Search-UnifiedAuditLog -StartDate $start -EndDate $end -SessionCommand ReturnLargeSet -ResultSize 5000
    $results += $logs
} While ($logs.Count -ne 0)
$results | Export-Csv "audit-export.csv"

# Search for file downloads
Search-UnifiedAuditLog -Operations FileDownloaded -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
```

**Common Investigation Scenarios**:

**Data Exfiltration**:
```
Activities: FileDownloaded, FileSyncDownloadedFull
Look for: Unusual volume, external sharing, personal cloud uploads
```

**Compromised Account**:
```
Activities: UserLoggedIn, MailItemsAccessed, SendAs
Look for: Sign-ins from unusual locations, bulk email reading, suspicious forwarding
```

**Privilege Escalation**:
```
Activities: Add member to role, Set-Mailbox, SiteCollectionAdminAdded
Look for: Unauthorized permission grants
```

**Insider Threat**:
```
Activities: All file operations, email activities
Look for: Departing employees accessing unusual data
```

---

## Comparison Tables

### Retention vs Sensitivity Labels

| Feature | Sensitivity Label | Retention Label |
|---------|-------------------|-----------------|
| **Purpose** | Protect data (encryption, markings) | Govern data lifecycle (retention, deletion) |
| **User Visible** | Yes (visible in Office apps) | Yes (visible in Office apps) |
| **Encryption** | Yes (can apply encryption) | No |
| **Deletion Control** | No | Yes (prevent deletion, auto-delete) |
| **Portability** | Yes (travels with content) | Yes (travels with content) |
| **Visual Markings** | Yes (headers, footers, watermarks) | No |
| **Access Control** | Yes (restricts who can access) | No (doesn't control access) |
| **Use Case** | Protect sensitive data, control sharing | Meet retention requirements, lifecycle management |

### eDiscovery Standard vs Premium

| Feature | Standard | Premium |
|---------|----------|---------|
| **Cases** | ✓ Basic case management | ✓ Advanced case management |
| **Holds** | ✓ Legal holds | ✓ Advanced holds with notifications |
| **Searches** | ✓ KQL searches | ✓ Advanced queries |
| **Preview** | ✓ Preview results | ✓ Enhanced preview |
| **Export** | ✓ Basic export | ✓ Multiple export formats |
| **Custodians** | ✗ No custodian management | ✓ Full custodian tracking |
| **Legal Hold Notices** | ✗ Manual process | ✓ Automated workflow |
| **Analytics** | ✗ No analytics | ✓ Near-duplicate, threading, themes |
| **Predictive Coding** | ✗ No ML assistance | ✓ Relevance ranking |
| **Review Sets** | ✗ No review workspace | ✓ Dedicated review environment |
| **Tagging** | ✗ No tagging | ✓ Document tagging and coding |
| **Licensing** | E3, E5, Business Premium | E5 or Compliance add-on |

### Insider Risk vs Communication Compliance

| Feature | Insider Risk Management | Communication Compliance |
|---------|------------------------|-------------------------|
| **Focus** | User behavior and data activities | Communication content |
| **Content** | Files, emails, device activities | Messages, emails, chat conversations |
| **Detection** | ML-based risk scoring, anomaly detection | Text/image classification, keywords, sensitive info types |
| **Privacy** | Pseudonymization (User1, User2) | Message content visible to reviewers |
| **Triggers** | HR events (termination), activity thresholds | Policy violations, inappropriate content |
| **Use Case** | Detect data theft, security violations | Monitor for regulatory compliance, inappropriate content |
| **Indicators** | File downloads, USB usage, after-hours access | Threats, harassment, profanity, sensitive data sharing |
| **Workflow** | Risk scoring → alerts → investigation → case | Policy match → alert → review → remediation |
| **Remediation** | Investigation, case management, evidence collection | Remove message, notify user, escalate, training |

### Audit Standard vs Premium

| Feature | Standard | Premium |
|---------|----------|---------|
| **Retention** | 90 days | 1 year (default), up to 10 years |
| **High-value Events** | No | Yes (MailItemsAccessed, Send, SearchQueryInitiated) |
| **API Bandwidth** | Standard limits | Higher limits |
| **Custom Retention** | No | Yes (create retention policies) |
| **Intelligent Insights** | No | Yes (anomaly detection) |
| **Priority Accounts** | No | Yes (enhanced logging for VIPs) |
| **Cost** | Included | Requires E5 or add-on |
| **Use Case** | Basic compliance, 90-day investigations | Advanced forensics, long-term compliance, breach investigations |

---

## Practice Questions

### Compliance Manager

#### Question 1: Compliance Score Calculation
**Q**: Your organization has 800 total compliance points available across all assessments. You have completed improvement actions worth 560 points. What is your compliance score percentage?

**Answer**: 70%
**Explanation**: Compliance Score = (Points achieved / Total points) × 100 = (560/800) × 100 = 70%

#### Question 2: Improvement Action Types
**Q**: Which type of improvement action in Compliance Manager requires documentation and manual processes rather than technical configuration?
A) Technical actions
B) Non-technical actions
C) Microsoft managed actions
D) Automated actions

**Answer**: B) Non-technical actions
**Explanation**: Non-technical actions require manual processes like creating policies, conducting training, or establishing governance committees. Technical actions involve configurations that can be automated or tested. Microsoft managed actions are handled by Microsoft's infrastructure.

#### Question 3: Assessments
**Q**: What is the purpose of assessments in Microsoft Compliance Manager?

**Answer**: Assessments group controls from a specific regulation or standard (like GDPR, ISO 27001) and map them to improvement actions, allowing organizations to track compliance progress against specific regulatory requirements.
**Explanation**: Each assessment evaluates your environment against a specific compliance standard, providing a structured way to manage compliance with multiple regulations simultaneously.

### Data Classification

#### Question 4: Sensitive Information Types
**Q**: Your organization needs to detect a custom employee ID format (EMP-######). What should you create?

**Answer**: Custom Sensitive Information Type
**Explanation**: Custom sensitive information types allow you to define patterns using regex, keywords, and confidence levels to detect organization-specific data formats. In this case, you would create a pattern using regex: `EMP-\d{6}`

#### Question 5: Trainable Classifiers
**Q**: What is the minimum number of sample documents required to train a custom trainable classifier?
A) 10 positive samples
B) 50 positive and 50 negative samples
C) 100 total samples
D) 500 samples

**Answer**: B) 50 positive and 50 negative samples
**Explanation**: Custom trainable classifiers require at least 50 positive samples (examples of what you want to detect) and 50 negative samples (examples of what you don't want to detect) for training.

#### Question 6: Content Explorer vs Activity Explorer
**Q**: Which tool would you use to see a chronological view of all label changes made by users in the last 30 days?

**Answer**: Activity Explorer
**Explanation**: Activity Explorer tracks user activities related to labeled content, including label applied, changed, or removed. Content Explorer shows where labeled content exists but doesn't track activities over time.

### Sensitivity Labels

#### Question 7: Label Priority
**Q**: A user applies a "Confidential" label to a document. Later they try to change it to "General" (lower priority). What happens if justification is required?

**Answer**: The user must provide a business justification before the label can be downgraded to "General"
**Explanation**: Label priority prevents accidental downgrade of protection. When justification is enabled, users must explain why they're applying a lower priority label.

#### Question 8: Encryption Options
**Q**: Your organization wants users to decide who can access their confidential documents when they apply a sensitivity label. Which encryption option should you configure?

**Answer**: "Let users assign permissions"
**Explanation**: This option allows users to specify permissions when they apply the label. The alternative "Assign permissions now" requires admins to pre-define who can access labeled content.

#### Question 9: Auto-labeling
**Q**: What is the difference between client-side and service-side auto-labeling?
**Answer**: 
- **Client-side**: Recommends or applies labels in Office applications in real-time when content is created/edited
- **Service-side**: Automatically scans and labels existing content in SharePoint, OneDrive, and Exchange (can take up to 7 days)
**Explanation**: Client-side provides immediate feedback to users. Service-side handles existing content at scale but with processing delay.

#### Question 10: Scope
**Q**: You want to apply consistent privacy settings to all Microsoft Teams created by the finance department. What label scope should you use?

**Answer**: Groups and sites scope
**Explanation**: Labels with "Groups and sites" scope can be applied to Microsoft 365 Groups, Teams, and SharePoint sites to control privacy settings and external sharing.

### Data Loss Prevention

#### Question 11: DLP Policy Components
**Q**: In a DLP policy, you want to block sharing of documents containing 10 or more credit card numbers with external users. What components do you need?
A) Condition only
B) Content to protect and action only
C) Content to protect, condition, and action
D) Action only

**Answer**: C) Content to protect, condition, and action
**Explanation**: 
- Content: Credit card numbers (sensitive info type)
- Condition: Count >= 10 AND shared with external users
- Action: Block sharing

#### Question 12: Policy Modes
**Q**: You're deploying a new DLP policy for the first time. What policy mode should you use initially?

**Answer**: Test with policy tips
**Explanation**: Testing with policy tips allows you to see how the policy would work, gather data on false positives, and educate users without disrupting business. After testing, you can enable full enforcement.

#### Question 13: Endpoint DLP
**Q**: Which of the following requires Endpoint DLP to monitor? (Select all that apply)
A) Email sent through Outlook
B) Files copied to USB drive
C) Documents uploaded to SharePoint
D) Files copied to personal OneDrive

**Answer**: B and D (Files copied to USB drive, Files copied to personal OneDrive)
**Explanation**: Endpoint DLP monitors local device activities like USB copying and browser uploads to personal cloud storage. Email and SharePoint are monitored through service-side DLP (Exchange and SharePoint locations).

#### Question 14: User Notifications
**Q**: What is the purpose of policy tips in DLP?

**Answer**: Policy tips are in-app notifications that appear when users violate DLP policies, explaining the violation and suggesting correct behavior, helping educate users while they work.
**Explanation**: Policy tips are educational, appearing at the moment of violation to guide users toward compliant behavior without blocking them (depending on policy configuration).

#### Question 15: DLP Alerts
**Q**: Your DLP policy detects 100 violations in one hour. You want to receive a single alert rather than 100 separate alerts. What should you configure?

**Answer**: Alert aggregation or alert thresholds
**Explanation**: Alert aggregation groups related violations into a single alert based on time windows and thresholds, reducing alert fatigue and making investigation more efficient.

### Retention & Records Management

#### Question 16: Retention Policy vs Label
**Q**: What is the key difference between a retention policy and a retention label?
A) Policies apply to locations, labels apply to items
B) Policies are permanent, labels are temporary
C) Policies encrypt data, labels don't
D) There is no difference

**Answer**: A) Policies apply to locations (location-wide), labels apply to items (item-level)
**Explanation**: Retention policies automatically apply to all content in selected locations (Exchange, SharePoint). Retention labels can be manually or automatically applied to specific documents and emails.

#### Question 17: Retention Actions
**Q**: Your organization must keep financial records for 7 years then automatically delete them. What retention action should you configure?

**Answer**: Retain then delete (Keep for 7 years, then auto-delete)
**Explanation**: "Retain then delete" keeps content for the specified period (7 years) then automatically removes it, meeting both retention and data minimization requirements.

#### Question 18: Event-Based Retention
**Q**: HR records must be retained for 7 years after an employee leaves the company. What type of retention should you use?

**Answer**: Event-based retention
**Explanation**: Event-based retention starts the retention period when a specific event occurs (employee termination). This is more accurate than creation or modification date for employee records.

#### Question 19: Records vs Regulatory Records
**Q**: What can be done with a standard record that cannot be done with a regulatory record?
A) Delete the record
B) Edit the content
C) Remove the label
D) All of the above

**Answer**: B) Edit the content (with limitations)
**Explanation**: Standard records allow limited editing while regulatory records prevent all modifications. Neither type can be deleted or have labels removed, but regulatory records are completely immutable.

#### Question 20: Disposition
**Q**: At the end of a retention period, you want a legal team member to review documents before they are permanently deleted. What should you configure?

**Answer**: Disposition review
**Explanation**: Disposition review requires manual approval before content is deleted. Reviewers can approve deletion, extend retention, or apply new labels. All disposition actions are logged for compliance.

### Insider Risk Management

#### Question 21: Privacy by Design
**Q**: How does Insider Risk Management protect user privacy by default?

**Answer**: Pseudonymization - user identities are hidden (shown as User1, User2) until authorized investigators reveal them
**Explanation**: Only users with specific permissions can view actual identities. All access to identities is logged for audit purposes.

#### Question 22: Policy Templates
**Q**: Which Insider Risk Management template would you use to detect an employee downloading large amounts of data before their resignation?

**Answer**: Data theft by departing users
**Explanation**: This template specifically monitors users with departure indicators (resignation notice, termination date) for data exfiltration activities like unusual downloads, copying to USB, or uploading to personal cloud.

#### Question 23: Risk Indicators
**Q**: What type of information from HR systems can trigger Insider Risk Management policies?
A) Performance reviews
B) Termination dates
C) Salary information
D) All of the above

**Answer**: D) All of the above
**Explanation**: HR connectors can import various data points: termination dates, resignation notices, performance reviews, demotions, and salary changes—all providing context for risk scoring.

#### Question 24: Investigation Workflow
**Q**: An alert is generated for a user with high risk score. What is the correct investigation sequence?
1. Escalate to case
2. Review activity timeline
3. Alert generated
4. Take remediation action

**Answer**: 3 → 2 → 1 → 4 (Alert generated → Review activity timeline → Escalate to case → Take remediation action)
**Explanation**: Alerts trigger investigations where analysts review activities, then escalate serious cases for formal investigation and remediation.

#### Question 25: Risk Scoring
**Q**: How does Insider Risk Management calculate risk scores for users?

**Answer**: Machine learning analyzes user activities against behavioral baselines, peer comparisons, and historical patterns to generate dynamic risk scores (0-100)
**Explanation**: The ML engine learns normal behavior for each user and detects anomalies, updating risk scores in real-time as new activities occur.

### Communication Compliance

#### Question 26: Regulatory Drivers
**Q**: Which regulation requires broker-dealers to supervise communications for compliance?
A) GDPR
B) FINRA
C) HIPAA
D) PCI DSS

**Answer**: B) FINRA
**Explanation**: FINRA (Financial Industry Regulatory Authority) requires broker-dealers to supervise employee communications. SEC and MiFID II have similar requirements for financial services.

#### Question 27: Detection Methods
**Q**: Your policy needs to detect inappropriate images shared in Teams messages. What detection method should you enable?

**Answer**: Image classification (Computer Vision)
**Explanation**: Image classification uses Azure Cognitive Services to detect adult content, violent imagery, and offensive symbols in images. OCR extracts text from images for additional scanning.

#### Question 28: Monitored Channels
**Q**: Which Microsoft 365 service is NOT natively monitored by Communication Compliance?
A) Microsoft Teams
B) Exchange Online
C) OneDrive file names
D) Yammer

**Answer**: C) OneDrive file names
**Explanation**: Communication Compliance monitors communications (messages, emails) but not file storage services like OneDrive or SharePoint directly. Files shared in communications are scanned.

#### Question 29: Review Workflow
**Q**: A reviewer determines a flagged message is a false positive. What should they do?

**Answer**: Resolve as compliant (no violation)
**Explanation**: Marking as compliant documents that the alert was incorrect, helping improve policy accuracy over time and reducing false positives.

#### Question 30: OCR
**Q**: What is the purpose of OCR (Optical Character Recognition) in Communication Compliance?

**Answer**: Extract text from images to detect policy violations in memes, screenshots, and embedded images
**Explanation**: OCR reads text in images, allowing detection of inappropriate text in visual content that would otherwise evade text-based detection.

### Information Barriers

#### Question 31: Purpose
**Q**: Why would an organization implement Information Barriers?

**Answer**: To prevent conflicts of interest by restricting communication between groups that should be isolated (e.g., competing deal teams, conflicting client representations)
**Explanation**: Information Barriers create "Chinese Walls" required in regulated industries like financial services, legal firms, and consulting.

#### Question 32: Segments
**Q**: How are segments typically defined in Information Barriers?

**Answer**: Based on Azure AD attributes like Department, JobTitle, Office, or CustomAttributes
**Explanation**: Segments use Azure AD user properties to dynamically group users. When attributes change, segment membership updates automatically.

#### Question 33: Enforcement
**Q**: Where are Information Barriers enforced? (Select all that apply)
A) Teams chats
B) Exchange email
C) SharePoint sites
D) OneDrive sharing

**Answer**: A, C, D (Teams chats, SharePoint sites, OneDrive sharing)
**Explanation**: Information Barriers are enforced in Teams (chats, channels, meetings), SharePoint (site access), and OneDrive (user lookup, sharing). Exchange/Outlook is NOT directly enforced—mail flow rules needed for email barriers.

#### Question 34: Modes
**Q**: In strict mode, what happens by default between segments without explicit policies?

**Answer**: Communication is blocked by default; allow policies required for any cross-segment communication
**Explanation**: Strict mode (also called "explicit allow") blocks all communication unless explicitly allowed. Open mode (default) allows communication unless explicitly blocked.

#### Question 35: Implementation
**Q**: After creating Information Barrier policies, approximately how long does it take for them to fully apply?

**Answer**: 24-48 hours
**Explanation**: Policy application is a background process that runs in batches. Status can be monitored with Get-InformationBarrierPoliciesApplicationStatus cmdlet.

### eDiscovery

#### Question 36: Standard vs Premium
**Q**: Which eDiscovery feature requires Premium licensing?
A) Legal holds
B) Content search
C) Predictive coding
D) Export results

**Answer**: C) Predictive coding
**Explanation**: Predictive coding (relevance analysis) is a Premium-only feature. Standard includes holds, searches, and exports. Premium adds analytics, custodian management, and ML-based review assistance.

#### Question 37: Hold Types
**Q**: You need to preserve all email for 5 specific users involved in litigation. What should you create?

**Answer**: eDiscovery case with custodian-based hold
**Explanation**: Create an eDiscovery (Standard or Premium) case, add the 5 users as custodians, and place a hold on their mailboxes. Content is preserved in place without user awareness.

#### Question 38: KQL Search
**Q**: Which KQL query finds emails with attachments larger than 10MB sent to external domains in the last 90 days?

**Answer**: `size>10MB AND recipients:*@* NOT recipients:*@yourdomain.com AND received>=2024-01-01`
**Explanation**: KQL combines conditions: size>10MB filters large items, recipients with NOT excludes internal emails, received>= sets date range.

#### Question 39: Review Sets
**Q**: What is the purpose of a Review Set in eDiscovery Premium?

**Answer**: A dedicated workspace where search results are loaded for detailed review, tagging, analytics, and redaction before production
**Explanation**: Review Sets provide a stable collection of documents with advanced tools: near-duplicate detection, threading, themes, tagging, and redaction capabilities.

#### Question 40: Content Search
**Q**: When should you use Content Search instead of creating an eDiscovery case?

**Answer**: For quick ad-hoc searches when you don't need legal holds or case management
**Explanation**: Content Search is simpler and faster for preliminary investigations or compliance checks. Use eDiscovery cases when you need holds, case management, or formal investigations.

### Audit

#### Question 41: Standard vs Premium
**Q**: What is the default audit log retention period for Audit (Standard)?
A) 30 days
B) 90 days
C) 1 year
D) 10 years

**Answer**: B) 90 days
**Explanation**: Audit (Standard) retains logs for 90 days (non-configurable). Audit (Premium) provides 1 year default with option for up to 10 years with add-on license.

#### Question 42: High-Value Events
**Q**: Which audit event is only available in Audit (Premium) and tracks every time a mailbox item is accessed?
A) FileAccessed
B) MailItemsAccessed
C) UserLoggedIn
D) SendAs

**Answer**: B) MailItemsAccessed
**Explanation**: MailItemsAccessed is a Premium-only high-value event critical for breach investigations, showing exactly which emails an attacker (or compromised account) accessed.

#### Question 43: Search Export
**Q**: You need to export 100,000 audit log entries. What is the recommended method?

**Answer**: PowerShell (Search-UnifiedAuditLog) with pagination
**Explanation**: The web interface limits exports to 50,000 results. PowerShell allows unlimited export by iterating through result batches using -SessionCommand ReturnLargeSet.

#### Question 44: Investigation Scenario
**Q**: A user account was compromised. Which audit activities should you search to determine what the attacker accessed? (Select all that apply)
A) UserLoggedIn
B) MailItemsAccessed
C) FileDownloaded
D) New-InboxRule

**Answer**: All of the above (A, B, C, D)
**Explanation**: 
- UserLoggedIn shows sign-in locations/times
- MailItemsAccessed shows emails read (Premium)
- FileDownloaded shows files stolen
- New-InboxRule shows forwarding rules created for persistence

#### Question 45: Priority Accounts
**Q**: What is the benefit of configuring Priority Accounts in Audit (Premium)?

**Answer**: Enhanced logging and faster visibility for VIP users (executives, administrators)
**Explanation**: Priority accounts receive more detailed activity logging and appear in dedicated dashboards, enabling quicker detection of threats targeting high-value users.

### Cross-Product Scenarios

#### Question 46: Label Combination
**Q**: Can you apply both a sensitivity label and a retention label to the same document?
A) No, only one label type allowed
B) Yes, they serve different purposes
C) Only if they're from the same policy
D) Only in SharePoint

**Answer**: B) Yes, they serve different purposes
**Explanation**: Sensitivity labels protect data (encryption, marking), retention labels govern lifecycle (retention, deletion). Both can be applied to provide comprehensive protection and governance.

#### Question 47: DLP + Sensitivity Labels
**Q**: How can sensitivity labels enhance DLP policies?

**Answer**: DLP policies can detect content with specific sensitivity labels and apply additional protections (e.g., block external sharing of "Confidential" labeled documents)
**Explanation**: Using labels as DLP conditions creates layered protection: users classify (label), DLP enforces based on classification.

#### Question 48: Insider Risk + DLP
**Q**: An Insider Risk Management policy detects unusual file downloads. DLP detects the same user copying sensitive data to USB. What happens?

**Answer**: Both systems generate alerts; DLP can block the USB copy while Insider Risk increases the user's risk score for investigation
**Explanation**: The systems complement each other: DLP provides immediate protection, Insider Risk provides behavioral context for investigation.

#### Question 49: Communication Compliance + Sensitivity Labels
**Q**: Can Communication Compliance policies detect messages containing documents with specific sensitivity labels?

**Answer**: Yes, policies can be configured to detect messages with labeled attachments
**Explanation**: Combining communication monitoring with sensitivity label detection ensures labeled sensitive documents aren't shared inappropriately via messaging channels.

#### Question 50: Audit + eDiscovery
**Q**: During an eDiscovery investigation, how can audit logs help?

**Answer**: Audit logs show who accessed, modified, or deleted relevant content, providing timeline and context for the investigation
**Explanation**: Audit data helps reconstruct events, identify custodians, determine content locations, and prove chain of custody for legal proceedings.

---

## Key Terms Glossary

| Term | Definition |
|------|------------|
| **Compliance Manager** | Tool for managing compliance with regulations through assessments, improvement actions, and scoring |
| **Compliance Score** | Percentage-based measurement of compliance posture (0-100%) |
| **Sensitivity Label** | Persistent tag that protects data with encryption, access controls, and visual markings |
| **Retention Label** | Tag that specifies how long to keep content and what to do at end of retention period |
| **DLP** | Data Loss Prevention - identifies, monitors, and protects sensitive information from leakage |
| **Record** | Official business content with restrictions on modification and deletion |
| **Regulatory Record** | Maximum restriction record that cannot be edited or deleted, even by admins |
| **Insider Risk** | Potential harm caused by authorized users through malicious or negligent actions |
| **Communication Compliance** | Monitoring communications for regulatory violations and inappropriate content |
| **Information Barriers** | Policies restricting communication between groups to prevent conflicts of interest |
| **eDiscovery** | Process of identifying, preserving, collecting, and producing electronic information for legal purposes |
| **Custodian** | Individual and their associated data sources under investigation in eDiscovery |
| **Legal Hold** | Preservation requirement preventing content deletion during litigation or investigation |
| **Audit Log** | Record of user and admin activities for compliance, forensics, and investigations |
| **Disposition** | Process occurring at end of retention period determining content fate (delete, review, extend) |
| **Trainable Classifier** | Machine learning model trained to recognize content types based on examples |
| **Sensitive Information Type** | Pattern-based detection of specific data types (SSN, credit cards, etc.) |
| **Pseudonymization** | Replacing user identities with pseudonyms (User1, User2) for privacy |
| **KQL** | Kusto Query Language - query language for searching audit logs and content |
| **Segment** | Group of users defined by Azure AD attributes for Information Barriers |

---

## Visual Summary

### Information Protection Lifecycle
```
Discover → Classify → Protect → Monitor → Govern
    ↓          ↓          ↓          ↓        ↓
Content   Sensitivity  Encryption   DLP    Retention
Explorer     Labels      & Marking  Alerts  Policies
```

### Label Types
```
Sensitivity Labels     → HOW to protect (encryption, marking, access control)
Retention Labels       → HOW LONG to keep (retention period, deletion)
Records Labels         → IMMUTABILITY (prevent modification/deletion)
```

### DLP vs Insider Risk vs Communication Compliance
```
DLP                    → Prevent data loss (outbound protection)
                        - Detects: Sensitive info sharing
                        - Action: Block, notify, audit

Insider Risk           → Detect risky user behavior
                        - Detects: Unusual activities, exfiltration
                        - Action: Investigate, create case

Comm Compliance        → Monitor communications for violations
                        - Detects: Inappropriate content, policy violations
                        - Action: Review, remove, escalate
```

### Compliance Architecture
```
┌──────────────────────────────────────────────────┐
│         Microsoft Purview Compliance Portal       │
├──────────────────────────────────────────────────┤
│                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐│
│  │ Information │  │   Data      │  │  Insider ││
│  │ Protection  │  │   Lifecycle │  │   Risk   ││
│  │             │  │             │  │          ││
│  │ • Labels    │  │ • Retention │  │ • Policy ││
│  │ • DLP       │  │ • Records   │  │ • Alerts ││
│  │ • Encryption│  │ • Disposition│  │ • Cases  ││
│  └─────────────┘  └─────────────┘  └──────────┘│
│                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐│
│  │Communication│  │  eDiscovery │  │  Audit   ││
│  │ Compliance  │  │             │  │          ││
│  │             │  │ • Cases     │  │ • Logs   ││
│  │ • Monitoring│  │ • Holds     │  │ • Search ││
│  │ • Detection │  │ • Analytics │  │ • Reports││
│  │ • Review    │  │ • Export    │  │ • Alerts ││
│  └─────────────┘  └─────────────┘  └──────────┘│
│                                                   │
└──────────────────────────────────────────────────┘
```

### eDiscovery Workflow
```
Identification → Preservation → Collection → Review → Analysis → Production
      ↓              ↓              ↓           ↓         ↓           ↓
  Custodians    Legal Hold      Search      Review   Analytics   Export
   Content      Notifications   Query       Sets     Themes      Native
   Locations                                         Duplicates   Files
```

---

## Summary & Review

### Most Important Concepts for Exam

**Information Protection** (High importance):
- Sensitivity labels protect (encryption, marking, access control)
- Retention labels govern (how long to keep, when to delete)
- DLP prevents data loss (monitors, blocks, notifies)
- Both label types can be applied together

**Compliance Management** (Medium-High importance):
- Compliance Manager assesses posture with score (0-100%)
- Improvement actions: technical, non-technical, Microsoft-managed
- Assessments map to specific regulations (GDPR, ISO 27001, etc.)

**Insider Risk & Communication Compliance** (Medium importance):
- Insider Risk detects behavioral anomalies (data theft, security violations)
- Communication Compliance monitors message content (inappropriate, violations)
- Both use ML for detection, different focus areas

**Records & Retention** (Medium importance):
- Retention policies: location-wide, automatic
- Retention labels: item-level, manual or auto-applied
- Records: restrict modification/deletion
- Regulatory records: maximum restrictions, admin cannot override

**eDiscovery** (Medium importance):
- Standard: Basic holds, searches, export
- Premium: Custodians, analytics, predictive coding
- Legal holds preserve content in place
- Review sets for detailed analysis

**Audit** (Medium importance):
- Standard: 90 days, basic events
- Premium: 1-10 years, high-value events (MailItemsAccessed)
- Critical for investigations and compliance

### Label Decision Tree
```
Need to PROTECT data?
├─ Yes → Sensitivity Label
│  ├─ Encryption needed? → Assign permissions
│  ├─ Visual marking? → Header/Footer/Watermark
│  └─ Access control? → Define permissions

Need to GOVERN lifecycle?
├─ Yes → Retention Label
│  ├─ Keep for period? → Retain then delete
│  ├─ Delete after period? → Delete only
│  └─ Keep forever? → Retain only

Need BOTH? → Apply BOTH labels!
```

### Study Tips for SC-900

1. **Understand label purposes**:
   - Sensitivity = protect
   - Retention = govern
   - They work together, not exclusively

2. **Know the differences**:
   - Policy vs. Label (location-wide vs. item-level)
   - Standard vs. Premium (features and licensing)
   - Record vs. Regulatory Record (restrictions)

3. **Focus on use cases**:
   - When to use each solution
   - How solutions integrate
   - Which solution for which problem

4. **Portal locations**:
   - compliance.microsoft.com for most Purview features
   - Know where to find each tool

5. **Licensing requirements**:
   - E3 vs. E5 features
   - What requires add-ons
   - Included vs. premium capabilities

---

**Next Steps**: Practice with the SC-900 Practice Exam file I'll create next!
