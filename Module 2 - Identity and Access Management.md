# Module 2: Identity and Access Management Solutions
**Weight**: 25-30% of exam (HIGHEST WEIGHT)

---

## 2.1 Identity Fundamentals

### What is Identity?

**Definition**:
A set of characteristics that define a person or entity in a digital system (username, email, roles, permissions)

**Identity is Not Just a "Person"**:
Identity applies to multiple types of entities:
- **Employees**: Internal workforce users
- **Partners and Customers**: External users (B2B, B2C)
- **Cloud Apps**: SaaS applications (Microsoft 365, Salesforce)
- **On-prem Apps**: Traditional applications in data centers
- **Devices**: Workstations, mobile devices, IoT devices

**Modern Identity**:
- Identity as the security perimeter
- Moved from network-based to identity-based security
- Enables access from anywhere (cloud, mobile, remote work)

### Authentication vs Authorization

**Critical Distinction**: Authentication happens FIRST, then authorization determines access rights.

| Aspect | Authentication (AuthN) | Authorization (AuthZ) |
|--------|----------------|---------------|
| **Definition** | Verifying the identity of a user | Determining what resources a user can access |
| **Question Asked** | Who are you? | What can you do? |
| **Process** | Proves you are who you claim to be | Checks what permissions you have |
| **Examples** | Password, MFA, Biometrics | Role assignments, permissions, access policies |
| **Technologies** | Azure AD, MFA, Windows Hello | RBAC, Conditional Access, PIM |
| **Failure Result** | Cannot sign in | Sign in successful, but access denied |
| **When It Occurs** | At login/sign-in | After authentication, when accessing resources |

#### Authentication (AuthN) Deep Dive

**What is Authentication?**
The process of proving you are who you claim to be by providing credentials that verify your identity.

**Authentication Flow**:
1. User provides identity claim (username/email)
2. User provides proof of identity (password, biometric, security key)
3. System validates credentials against identity provider
4. System issues authentication token if successful
5. Token is used for subsequent resource access

**Types of Authentication**:
- **Single-Factor**: Password only (weakest)
- **Multi-Factor**: Password + second factor (strong)
- **Passwordless**: Biometric or security key (strongest)

#### Authorization (AuthZ) Deep Dive

**What is Authorization?**
The process of determining what an authenticated user is allowed to do - which resources they can access and what actions they can perform on those resources.

**Key Principle**: Authorization ALWAYS happens AFTER authentication. You must prove who you are before the system decides what you can do.

**Authorization Flow**:
1. User successfully authenticates (proven identity)
2. User attempts to access a resource (file, application, API)
3. System checks user's permissions/roles for that resource
4. System evaluates policies (Conditional Access, RBAC)
5. Access is granted or denied based on authorization decision
6. Actions are logged for auditing

**Authorization Components**:

**1. Permissions**:
- Specific actions allowed on a resource
- Examples: Read, Write, Delete, Execute
- Granular: "Read emails" vs "Send emails as another user"

**2. Roles**:
- Collections of permissions grouped by job function
- Examples: Global Admin, User Admin, Security Reader
- Assigned to users or groups
- **Role-Based Access Control (RBAC)**: Authorization model using roles

**3. Policies**:
- Rules that determine access based on conditions
- Examples: Conditional Access policies
- Can require additional verification even after authentication
- Dynamic: "Allow access to SharePoint only from corporate network"

**4. Scopes**:
- Limits what permissions apply to
- Examples: Subscription-level, Resource Group-level, Resource-level
- Principle of Least Privilege: Grant narrowest scope needed

**Types of Authorization Models**:

| Model | Description | Example | Microsoft Technology |
|-------|-------------|---------|---------------------|
| **RBAC** | Role-Based Access Control | User assigned "Helpdesk Admin" role | Azure AD Roles, Azure RBAC |
| **ABAC** | Attribute-Based Access Control | Access based on user attributes (department, location) | Conditional Access |
| **ACL** | Access Control Lists | Specific users/groups listed per resource | SharePoint permissions, NTFS |
| **PBAC** | Policy-Based Access Control | Rules evaluated for each access attempt | Conditional Access Policies |

**Real-World Example**:

```
Scenario: Employee tries to access HR payroll system

Authentication (Who are you?):
✓ User enters username: john@contoso.com
✓ User provides password + MFA
✓ Azure AD confirms identity
✓ User receives authentication token

Authorization (What can you do?):
? User attempts to access Payroll App
? System checks: Is user in "HR-Payroll" group? → NO
? System checks: Does user have "Payroll.Read" permission? → NO
✗ Access DENIED

Alternative scenario - HR Manager:
? HR Manager attempts to access Payroll App
? System checks: Is user in "HR-Managers" group? → YES
? System checks: Does user have "Payroll.Read" permission? → YES
? Conditional Access: Is device compliant? → YES
? Conditional Access: Is location trusted? → YES
✓ Access GRANTED (Read-only)
```

**Azure AD Authorization Technologies**:

**1. Azure AD Roles** (for Azure AD resources):
- Global Administrator
- User Administrator
- Security Administrator
- Permissions to manage users, groups, licenses, etc.

**2. Azure RBAC** (for Azure resources):
- Owner
- Contributor
- Reader
- Permissions to manage subscriptions, VMs, storage, etc.

**3. Conditional Access** (policy-based authorization):
- Requires compliant device
- Requires specific location
- Requires MFA for certain apps
- Dynamic decisions based on risk level

**4. Application Permissions**:
- Delegated Permissions: Act on behalf of signed-in user
- Application Permissions: Act as the app itself (no user context)
- Consent required before apps can access resources

**Common Authorization Scenarios**:

| Scenario | Authorization Mechanism |
|----------|------------------------|
| Accessing Azure portal | Azure RBAC + Azure AD roles |
| Reading someone's email | Delegated permissions (requires consent) |
| Accessing SharePoint site | SharePoint permission groups + ACLs |
| Running Azure automation | Application permissions + Managed Identity |
| Viewing security reports | Security Reader role |
| Elevated admin tasks | PIM (Just-in-Time authorization) |

**Authorization Best Practices**:
- **Least Privilege**: Grant minimum permissions needed
- **Just-In-Time (JIT)**: Temporary elevation only when needed
- **Just-Enough-Access (JEA)**: Narrow scope of permissions
- **Regular Reviews**: Audit who has access to what
- **Separation of Duties**: No single person controls entire process
- **Zero Standing Privileges**: No permanent admin rights

**Key Difference - Authentication vs Authorization**:
```
Authentication: "I have my driver's license - I am John Smith"
Authorization: "My license allows me to drive a car, but NOT a commercial truck"

Authentication: One-time proof of identity
Authorization: Continuous checking of permissions for each action
```

#### Identity Providers (IdP)

**What is an Identity Provider?**
A trusted service that creates, maintains, and manages identity information while providing authentication services to applications.

**How Identity Providers Work**:
1. User attempts to access an application
2. Application redirects user to the Identity Provider (e.g., Azure AD)
3. User authenticates with the Identity Provider
4. Identity Provider issues a token confirming authentication
5. User presents token to application
6. Application trusts the Identity Provider and grants access

**Examples of Identity Providers**:
- **Microsoft Entra ID (Azure AD)**: Microsoft's cloud identity provider
- **Active Directory Federation Services (AD FS)**: On-premises identity provider
- **Google Identity**: Google's identity provider
- **Okta**: Third-party identity provider
- **Social Providers**: Facebook, Twitter, GitHub (for consumer apps)

**Benefits of Using an Identity Provider**:
- **Centralized Identity Management**: Single source of truth for user identities
- **Single Sign-On (SSO)**: One login for multiple applications
- **Security**: Specialized systems dedicated to identity security
- **Compliance**: Centralized auditing and monitoring
- **Reduced Development**: Applications don't need to build auth systems

**The Old Way: Application-Managed Authentication**

**Traditional Approach (Before Identity Providers)**:
- Each application maintained its own user database
- Users created separate accounts for every application
- Passwords stored in application databases (often poorly secured)
- No centralized control or visibility
- Each app responsible for implementing authentication logic

**Problems with the Old Way**:
- **Password Proliferation**: Users had dozens of different passwords
- **Security Risks**: Weak password storage, no MFA support
- **No SSO**: Users logged in separately to each application
- **Management Nightmare**: No central place to disable a user
- **Inconsistent Security**: Each app had different security standards
- **Poor Audit Trail**: No unified view of user access
- **Development Burden**: Every app team built authentication from scratch

**Evolution of Authentication**:

```
Old Way (Pre-2000s)
↓
Application stores usernames/passwords in database
↓
User logs into EACH application separately
↓
No central control, passwords everywhere
↓
═══════════════════════════════════════════
↓
Directory Services Era (2000s)
↓
LDAP/Active Directory for centralized user store
↓
Still mostly on-premises, VPN required
↓
Basic SSO within corporate network
↓
═══════════════════════════════════════════
↓
Modern Identity Provider Era (2010s+)
↓
Cloud-based Identity Providers (Azure AD, Okta)
↓
Token-based authentication (OAuth, SAML)
↓
SSO across cloud and on-premises apps
↓
MFA, Conditional Access, Zero Trust
```

#### Modern Authentication

**What is Modern Authentication?**
Microsoft's implementation of industry-standard protocols (OAuth 2.0, OpenID Connect) for secure authentication and authorization using a centralized Identity Provider (Azure AD).

**High-Level Overview**:
Modern Authentication replaces the old model of sending passwords to every application with a token-based system. Instead of giving your password to each app, you authenticate once with a trusted Identity Provider (Azure AD), which gives you tokens that prove you're authenticated. These tokens are then presented to applications to gain access - the apps never see your password.

**Think of it like this**:
- **Old Way**: Showing your driver's license (password) to every store clerk
- **Modern Way**: Getting a wristband (token) at the entrance, then showing the wristband to enter different areas

**Key Characteristics**:
- **Token-Based**: Uses security tokens instead of sending passwords repeatedly
- **MFA Support**: Natively supports multi-factor authentication
- **Conditional Access**: Enables policy-based access control
- **Single Sign-On (SSO)**: One authentication for multiple applications
- **App-Based Authentication**: Works with modern apps and mobile devices

**How Modern Authentication Works** (Simplified Flow):
1. User tries to access an application (e.g., SharePoint Online)
2. App redirects user to Azure AD (Identity Provider)
3. User authenticates with Azure AD (password + MFA)
4. Azure AD issues tokens to the user
5. User presents tokens to the application
6. Application validates tokens and grants access
7. User continues using tokens for subsequent requests (no re-authentication needed)

**Modern Auth vs Legacy Authentication**:

| Feature | Modern Authentication | Legacy Authentication |
|---------|----------------------|----------------------|
| **Protocol** | OAuth 2.0, OpenID Connect, SAML | Basic Auth, NTLM, Form-based |
| **MFA Support** | Native support | Not supported or limited |
| **Conditional Access** | Fully supported | Not supported |
| **Token-Based** | Yes (refresh tokens, access tokens) | No (sends credentials each time) |
| **Security** | High (tokens, encryption, expiration) | Low (sends passwords in clear/hash) |
| **User Experience** | SSO across apps | Repeated login prompts |
| **Examples** | Microsoft 365, Azure AD apps | Legacy Exchange, POP3/IMAP, older apps |

**Modern Authentication Components**:
- **OAuth 2.0**: Authorization framework for delegated access
- **OpenID Connect**: Identity layer on top of OAuth 2.0 for authentication
- **SAML 2.0**: XML-based standard for SSO across domains
- **Tokens**: Digital proof of authentication and authorization (see detailed explanation below)

### Understanding Tokens in Modern Authentication

**What are Tokens?**
Tokens are digitally signed data packages that contain information about the user's identity, authentication status, and permissions. They act as temporary credentials that prove you've been authenticated.

**Why Tokens Matter**:
- **Security**: Passwords never leave the Identity Provider
- **Efficiency**: No need to re-authenticate for every request
- **Scalability**: Applications don't need to store user credentials
- **Stateless**: Applications can validate tokens without contacting Azure AD every time

**Types of Tokens**:

#### 1. Access Tokens
**Purpose**: Grant access to specific resources (APIs, applications)

**Characteristics**:
- **Short-lived**: Typically 1 hour (security best practice)
- **Resource-specific**: Valid for specific APIs or applications
- **Contains claims**: User identity, permissions, expiration time
- **Cannot be revoked**: Must wait for expiration (hence short lifetime)

**Example Use**:
- User accesses Microsoft Graph API
- Access token proves they're authorized to read emails
- Token expires after 1 hour, requiring refresh

#### 2. Refresh Tokens
**Purpose**: Obtain new access tokens without re-authenticating

**Characteristics**:
- **Long-lived**: Days, weeks, or months (configurable)
- **Can be revoked**: Admin can invalidate refresh tokens
- **More sensitive**: Stored securely, never sent to resource servers
- **Conditional Access aware**: New tokens respect current CA policies

**Example Use**:
- Access token expires after 1 hour
- Application uses refresh token to request new access token
- User doesn't have to sign in again
- If device/location/risk changed, Conditional Access may require re-authentication

#### 3. ID Tokens
**Purpose**: Prove user's identity (used with OpenID Connect)

**Characteristics**:
- **Identity information**: User's name, email, unique ID
- **Not for authorization**: Shouldn't be used to access APIs
- **JWT format**: JSON Web Token (readable, digitally signed)
- **For the application**: Tells the app who the user is

**Example Use**:
- User signs into a web application
- ID token tells the app: "This is John Smith (john@contoso.com)"
- App personalizes the experience based on user identity

**Token Lifecycle**:

```
User Authenticates with Azure AD
         ↓
Azure AD issues tokens:
 - Access Token (1 hour)
 - Refresh Token (90 days)
 - ID Token
         ↓
User accesses Application
         ↓
App uses Access Token (valid for 1 hour)
         ↓
After 1 hour, Access Token expires
         ↓
App uses Refresh Token to get new Access Token
         ↓
Azure AD checks:
 - Is Refresh Token still valid?
 - Do Conditional Access policies allow?
 - Has user been disabled?
         ↓
If OK: Issue new Access Token
If NOT: Require re-authentication
```

**Token Security Features**:
- **Digital Signatures**: Prevents tampering (tokens are signed by Azure AD)
- **Expiration Times**: Limits damage if token is stolen
- **Audience Validation**: Tokens only work for intended applications
- **Scope Limitations**: Tokens only grant specific permissions
- **Encryption**: Sensitive tokens encrypted in transit (HTTPS)

**Token Format (JWT - JSON Web Token)**:
Modern auth tokens are typically JWTs with three parts:
1. **Header**: Token type and signing algorithm
2. **Payload**: Claims (user info, expiration, permissions)
3. **Signature**: Cryptographic signature to prevent tampering

**Real-World Analogy**:
- **Access Token** = Movie ticket (gets you into one specific movie, expires quickly)
- **Refresh Token** = Season pass (lets you get new tickets without buying again)
- **ID Token** = Your ID badge (proves who you are)

**Why Modern Authentication Matters**:
- Blocks legacy authentication attacks (password spray, credential stuffing)
- Enables Zero Trust security model
- Required for advanced security features (Conditional Access, Identity Protection)
- Better audit trails and logging
- Industry standard compliance

### Ways to Verify Identity (Authentication Methods)

**Beyond Simple User ID/Password**:

#### Single Sign-On (SSO)
- **What**: Authenticate once, access multiple applications
- **How**: Using Azure AD (Entra ID) everywhere
- **Benefits**:
  - Improved user experience (one set of credentials)
  - Reduced password fatigue
  - Centralized identity management
  - Lower help desk costs
- **Example**: Sign in once to access Microsoft 365, Azure, Salesforce, etc.

#### Multi-Factor Authentication (MFA)
- **What**: Requires two or more verification methods
- **Why**: Passwords alone are easily compromised
- **Methods**: Something you know + something you have + something you are
- **Protection**: Blocks 99.9% of account compromise attacks
- **Example**: Password + phone notification + fingerprint

#### Just-In-Time (JIT) Access
- **What**: Temporary, time-limited access to privileged roles
- **How**: Request access when needed, auto-expires after set time
- **Use Case**: Admin privileges granted only when performing admin tasks
- **Technology**: Privileged Identity Management (PIM)
- **Benefits**: Reduces standing privileges, minimizes attack surface

### Identity as Primary Security Perimeter

**Traditional Security Perimeter** (Network-Based):
- Company owned network
- Company owned device
- Services are provided only inside company data center
- Trust model: "Inside the network = trusted"

**Modern Security Perimeter** (Identity-Based):
- The person is who they say they are (verified identity)
- Access from anywhere: cloud, remote, mobile
- Any device: BYOD, personal, unmanaged
- Services across multiple clouds and on-premises

**Why Identity Matters**:
- Traditional network perimeters are dissolving (cloud, BYOD, remote work)
- 80%+ of security breaches involve compromised credentials
- Identity controls access to all resources regardless of location
- Zero Trust model: "Verify explicitly, assume breach, least privilege access"

### Granular Security & Intelligent Monitoring

**Modern Identity-Based Security Capabilities**:

#### Intelligent Monitoring & Detection
- **Behavioral Analytics**: Detects strange or anomalous user behavior
- **AI-Powered Risk Detection**: Identifies suspicious sign-ins (unusual locations, impossible travel)
- **Real-Time Threat Intelligence**: Alerts on known malicious IP addresses and attack patterns
- **Technology**: Azure AD Identity Protection, Microsoft Defender for Identity

#### Granular Access Controls
- **Document-Level Security**: Restrict access to specific files and data
- **Application-Level Controls**: Control which apps users can access
- **Conditional Access Policies**: Dynamic access decisions based on context
- **Data Classification**: Apply protection based on sensitivity labels
- **Technology**: Microsoft Purview Information Protection, Conditional Access

#### Restrict Lateral Movement
- **Network Segmentation**: Limit movement between systems and resources
- **Least Privilege Access**: Users get only the minimum access required
- **Default Deny**: Block all access unless explicitly granted
- **Just-Enough-Access (JEA)**: Time-bound, task-specific permissions
- **Zero Standing Privileges**: No permanent admin rights
- **Technology**: PIM, Conditional Access, Azure AD roles

#### Comprehensive Logging & Auditing
- **Sign-in Logs**: Track all authentication attempts (successful and failed)
- **Audit Logs**: Record all configuration changes and administrative actions
- **Risk Detection Logs**: Document detected threats and anomalies
- **Access Reviews**: Regular certification of who has access to what
- **Retention**: Long-term storage for compliance and forensics

---

## 2.2 Microsoft Entra ID (Azure AD)

### Overview

**What is Entra ID?**:
Microsoft Entra ID (formerly Azure Active Directory) is Microsoft's cloud-based identity and access management service. It provides authentication and authorization services for cloud applications, Microsoft 365, Azure, and thousands of SaaS applications.

**Core Purpose**: Central identity provider for managing users, devices, and applications in the cloud and hybrid environments.

### What is a Directory Service?

**Definition**:
A directory service is a centralized database system that stores, organizes, and provides access to information about network resources and user identities. Think of it as a "phone book" for your organization that keeps track of who is in your organization, what resources exist, and who can access what.

**Core Purpose**:
Directory services provide a single source of truth for identity and resource information across an organization's IT infrastructure.

**What Information Does a Directory Service Store?**

A directory service maintains information about:
- **Users**: Names, email addresses, phone numbers, department, manager, job title
- **Groups**: Collections of users organized by team, department, or function
- **Computers/Devices**: Workstations, servers, mobile devices, printers
- **Applications**: Software and services available to users
- **Resources**: File shares, printers, network resources
- **Permissions**: Who can access which resources and what they can do

**How Directory Services Work**:

```
User wants to access a resource (file share, application, printer)
         ↓
System queries the Directory Service
         ↓
Directory Service checks:
 - Does this user exist?
 - Is the password correct?
 - What groups is this user in?
 - What permissions does this user have?
         ↓
Directory Service responds: Allow or Deny
         ↓
Resource grants or denies access based on directory response
```

**Key Directory Service Protocols**:
- **LDAP (Lightweight Directory Access Protocol)**: Standard protocol for querying and modifying directory services
- **Kerberos**: Network authentication protocol providing secure ticket-based authentication
- **SAML (Security Assertion Markup Language)**: XML-based protocol for exchanging authentication and authorization data
- **OAuth/OpenID Connect**: Modern web-based protocols for authentication and authorization

**Examples of Directory Services**:
- **Active Directory (AD)**: Microsoft's on-premises directory service
- **Azure Active Directory (Entra ID)**: Microsoft's cloud directory service
- **LDAP directories**: OpenLDAP, Apache Directory Server
- **Cloud directory services**: Okta, Google Workspace Directory, AWS Directory Service

**Benefits of Directory Services**:
- **Single source of truth**: One place to manage all identity information
- **Centralized authentication**: Users authenticate once against the directory
- **Centralized authorization**: Permissions managed in one location
- **Reduced administration**: Change user info once, updates everywhere
- **Better security**: Consistent security policies across all resources
- **Scalability**: Handle thousands to millions of users and resources
- **Audit and compliance**: Track who accessed what and when

### What is Active Directory?

**Definition**:
Active Directory (AD) is Microsoft's on-premises directory service that has been the foundation of Windows-based enterprise networks since 2000. It provides authentication and authorization services for Windows domain-joined computers and manages resources across an organization's network.

**Think of it as**: The traditional on-premises "master database" for Windows networks that knows about every user, computer, and resource in your organization.

**Active Directory Domain Services (AD DS)**:
The full name is Active Directory Domain Services, which is the core directory service component that stores directory information and handles authentication/authorization.

**Key Active Directory Concepts**:

#### Domain
- A security boundary containing users, computers, and resources
- Has its own security policies and trust relationships
- Example: contoso.com domain with 5,000 users and 2,000 computers

#### Organizational Units (OUs)
- Containers within a domain for organizing objects (users, groups, computers)
- Used to delegate administration and apply Group Policies
- Example: "Sales" OU containing all sales department users and computers

#### Forest
- Collection of one or more domains sharing a common schema and global catalog
- Represents the highest level of security boundary
- Example: Contoso forest with contoso.com, europe.contoso.com, asia.contoso.com domains

#### Domain Controller (DC)
- Windows Server running Active Directory Domain Services
- Stores copy of directory database and handles authentication requests
- Multiple DCs for redundancy and load balancing
- Changes replicate between all domain controllers

#### Group Policy Objects (GPOs)
- Configuration settings applied to users and computers in the domain
- Centrally manage security settings, software deployment, desktop configurations
- Example: GPO enforcing password complexity, screen lock after 10 minutes, desktop wallpaper

**How Active Directory Works**:

```
User logs into domain-joined Windows PC
         ↓
Computer contacts Domain Controller
         ↓
DC validates credentials against AD database
         ↓
DC issues Kerberos ticket to user
         ↓
User uses ticket to access network resources (file shares, applications)
         ↓
Resources trust the Kerberos ticket from the DC
         ↓
Access granted without re-entering password (seamless SSO within domain)
```

**Active Directory Authentication Protocols**:
- **Kerberos**: Primary authentication protocol for AD (ticket-based)
- **NTLM**: Legacy authentication protocol (challenge-response, less secure)
- **LDAP**: Protocol for querying and modifying AD data
- **LDAPS**: LDAP over SSL for encrypted communication

**What Active Directory is Good For**:
- Managing Windows domain-joined computers
- Authenticating users to on-premises resources
- Applying Group Policies to configure Windows devices
- Controlling access to file shares, printers, applications
- Managing on-premises Exchange servers
- Traditional corporate networks with on-premises infrastructure

**What Active Directory is NOT Good For**:
- Cloud applications (doesn't speak modern protocols like OAuth/SAML natively)
- Mobile device management (designed for domain-joined Windows PCs)
- Internet-scale applications (not designed for millions of users)
- Modern authentication methods (MFA, passwordless, Conditional Access)
- Cross-organization collaboration (B2B scenarios)

**Key Differences: Azure AD vs Active Directory**

| Feature | Azure AD (Entra ID) | Active Directory (AD) |
|---------|---------------------|----------------------|
| **Type** | Cloud-based identity service | On-premises directory service |
| **Protocol** | OAuth 2.0, SAML, OpenID Connect, REST APIs | LDAP, Kerberos, NTLM |
| **Authentication** | Modern authentication, MFA, passwordless | Traditional password-based, NTLM, Kerberos |
| **Structure** | Flat structure (tenants, no OUs) | Hierarchical (domains, OUs, forests) |
| **Primary Use** | Cloud apps, SaaS, Microsoft 365, Azure | On-prem apps, file shares, GPOs, domain-joined devices |
| **Management** | Web-based Azure portal, PowerShell, Graph API | Active Directory Users and Computers, Group Policy Management |
| **Scalability** | Millions of users, global scale | Typically thousands to tens of thousands per domain |
| **Infrastructure** | Microsoft-managed cloud service | Self-managed servers (Domain Controllers) |
| **Group Policy** | Not supported (use Intune for device management) | Full GPO support for Windows configuration |
| **Query Protocol** | Microsoft Graph API (REST/HTTP) | LDAP (Lightweight Directory Access Protocol) |

### What is Federation and Federated Services?

**Definition**:
Federation (also called Federated Identity or Identity Federation) is a system of trust that allows users to use the same identity credentials to access multiple independent systems across different organizations or domains. Instead of creating separate accounts in each system, users authenticate with their home organization's identity provider, and that authentication is trusted by partner organizations.

**Think of it as**: Your passport - you authenticate your identity with your home country (identity provider), and other countries trust that passport without requiring you to become a citizen or get separate IDs.

**Core Concept**:
Federation establishes trust relationships between different identity providers so that authentication performed in one system can be accepted by another system without the user needing to re-authenticate or have separate credentials.

#### How Federation Works

```
User (employee of Company A) wants to access Application hosted by Company B
         ↓
User goes to Company B's Application
         ↓
Application recognizes user is from Company A (federated partner)
         ↓
Application redirects user to Company A's Identity Provider (Azure AD or AD FS)
         ↓
User authenticates with Company A's credentials (their home/familiar login)
         ↓
Company A's Identity Provider issues a security token (SAML token or JWT)
         ↓
Token is sent to Company B's Application
         ↓
Company B's Application trusts Company A's Identity Provider (federation trust)
         ↓
Application validates the token and grants access
         ↓
User accesses the application without creating a separate account at Company B
```

#### Key Federation Concepts

**Identity Provider (IdP)**:
- The organization that authenticates users and issues security tokens
- Stores and manages user credentials
- Example: Company A's Azure AD is the identity provider for its employees

**Service Provider (SP) / Relying Party**:
- The application or service that accepts authentication tokens from the Identity Provider
- Trusts the Identity Provider to authenticate users
- Example: Company B's application is the service provider/relying party

**Federation Trust**:
- Established relationship between Identity Provider and Service Provider
- Trust is based on shared certificates or metadata
- Defines what information (claims) is shared about the user

**Security Tokens**:
- Digital packages containing authentication and authorization information
- Signed by the Identity Provider to prevent tampering
- Contains claims about the user (name, email, group memberships, permissions)

**Claims**:
- Statements about the user contained in the security token
- Examples: Name, email address, employee ID, department, role
- Consuming application decides what to do based on these claims

#### Federation Protocols

**SAML 2.0 (Security Assertion Markup Language)**:
- XML-based standard for exchanging authentication and authorization data
- Most common federation protocol for enterprise applications
- How it works:
  1. User tries to access application (Service Provider)
  2. Application redirects to Identity Provider
  3. User authenticates at Identity Provider
  4. Identity Provider issues SAML assertion (XML document)
  5. User's browser posts SAML assertion to application
  6. Application validates assertion and grants access
- **Use cases**: Enterprise SSO, SaaS applications (Salesforce, Workday, ServiceNow)
- **Example**: Employees using Azure AD credentials to access Salesforce

**WS-Federation (Web Services Federation)**:
- Microsoft's federation protocol (predecessor to modern OAuth/SAML)
- XML-based like SAML
- Commonly used with Active Directory Federation Services (AD FS)
- **Use cases**: Legacy Microsoft applications, SharePoint, older .NET applications
- **Example**: On-premises SharePoint trusting Azure AD for authentication

**OAuth 2.0 / OpenID Connect**:
- Modern web-friendly protocols for authentication and authorization
- JSON-based (simpler than XML)
- OAuth 2.0 = Authorization framework
- OpenID Connect = Identity layer on top of OAuth 2.0
- **Use cases**: Modern cloud apps, mobile apps, APIs, social login
- **Example**: "Sign in with Microsoft", "Sign in with Google"

#### Types of Federation Scenarios

**1. Cross-Organization Federation (B2B)**:
Partner organizations establish trust so their employees can access each other's resources.

**Example Scenario**:
- Contoso employees need access to Fabrikam's project management application
- Fabrikam establishes federation trust with Contoso's Azure AD
- Contoso employees sign in with their @contoso.com credentials
- Fabrikam's application accepts Contoso's authentication tokens
- No need to create separate @fabrikam.com accounts for Contoso employees

**Benefits**:
- Partners use their own credentials (no password sharing)
- Centralized management (each org manages their own users)
- Automatic access removal (when employee leaves Contoso, access to Fabrikam automatically revoked)
- Better security (no external accounts to manage)

**2. Cloud-to-On-Premises Federation**:
Bridge between cloud identity services (Azure AD) and on-premises systems (Active Directory).

**Example Scenario**:
- Organization uses on-premises Active Directory for corporate network
- Moving to Microsoft 365 and cloud applications
- Deploy Active Directory Federation Services (AD FS)
- Establish trust between Azure AD and on-premises AD FS
- Users authenticate against on-prem AD, tokens issued to access cloud apps
- Single identity across on-prem and cloud

**Technologies**: Active Directory Federation Services (AD FS), Azure AD Connect with federation

**3. SaaS Application Federation**:
Enterprise identity provider (Azure AD) federates with SaaS applications so employees use corporate credentials.

**Example Scenario**:
- Company subscribes to Salesforce, Workday, DocuSign
- Configure SAML federation between Azure AD and each SaaS app
- Employees access all SaaS apps with their corporate credentials
- Single Sign-On across all applications
- IT controls access centrally in Azure AD

**Benefits**:
- No separate passwords for each SaaS app (reduces password fatigue)
- Centralized access control (grant/revoke from Azure AD)
- MFA and Conditional Access policies apply to all federated apps
- Consistent audit logs across all applications

**4. Social Identity Federation (Consumer Scenarios)**:
Consumer applications allow users to sign in with social identity providers.

**Example Scenario**:
- E-commerce website allows customers to sign in
- Website federates with Google, Facebook, Microsoft, Apple
- Customers choose "Sign in with Google" or "Sign in with Facebook"
- Social provider authenticates user and issues token
- Website accepts the token and creates account/session
- No need to create yet another username/password

**Technology**: Azure AD B2C (Business-to-Consumer), OAuth 2.0 / OpenID Connect

#### Active Directory Federation Services (AD FS)

**What is AD FS?**:
Microsoft's on-premises federation service that enables federated identity and Single Sign-On between on-premises Active Directory and external applications (cloud or partner organizations).

**How AD FS Works**:
```
User tries to access cloud application (like Microsoft 365)
         ↓
Cloud app redirects to AD FS (on-premises federation server)
         ↓
AD FS prompts user to authenticate
         ↓
User provides Active Directory credentials
         ↓
AD FS validates credentials against on-premises Active Directory
         ↓
AD FS issues security token (SAML, JWT, or WS-Fed)
         ↓
Token sent back to cloud application
         ↓
Cloud application validates token and grants access
         ↓
User authenticated to cloud app using on-premises credentials
```

**AD FS Components**:
- **Federation Server**: Issues and validates security tokens
- **Web Application Proxy**: Publishes AD FS to the internet securely
- **Token Signing Certificate**: Cryptographically signs tokens to prevent tampering
- **Claims Rules**: Define what information about the user is sent in tokens

**When to Use AD FS**:
- Organization requires all authentication to happen on-premises (strict compliance)
- Need smartcard or certificate-based authentication
- Custom authentication requirements not supported by Azure AD
- Multi-factor authentication using third-party MFA solutions

**Why Microsoft Recommends Moving Away from AD FS**:
- **High complexity**: Requires multiple servers, load balancers, certificates, proxies
- **Maintenance burden**: Regular patching, certificate renewal, infrastructure management
- **Single point of failure**: If AD FS is down, cloud access is unavailable
- **Limited modern features**: Doesn't support many Azure AD security features
- **Better alternatives**: Password Hash Sync provides same SSO experience with less complexity

**Migration Path**: AD FS → Azure AD with Password Hash Synchronization or Pass-Through Authentication

#### Federation in Azure AD

**Modern Federation in Azure AD**:
Azure AD acts as a federated identity provider for thousands of pre-integrated SaaS applications and supports custom SAML-based federation.

**How Azure AD Federation Works**:
1. **Gallery Applications**: Pre-configured federation for popular SaaS apps (Salesforce, Workday, ServiceNow, etc.)
2. **Custom SAML Applications**: Configure SAML federation for any app supporting SAML 2.0
3. **Trust Establishment**: Exchange metadata or certificates to establish trust
4. **Claim Mapping**: Configure what user attributes are sent to the application
5. **Access Control**: Use Conditional Access to control federated app access

**Azure AD as Identity Provider**:
- Users authenticate to Azure AD
- Azure AD issues SAML token or OAuth token
- Application accepts token and grants access
- Azure AD provides SSO across all federated applications

**Azure AD B2B Federation**:
- Invite external users from partner organizations
- Partners authenticate with their home organization's Azure AD
- Your Azure AD trusts partner Azure AD authentication
- External users access your resources with their own credentials

**Azure AD B2C Federation**:
- Consumer identity solution for customer-facing applications
- Federates with social providers (Google, Facebook, Microsoft, Apple, Amazon, Twitter)
- Customers use existing social accounts or create local accounts
- Customizable sign-in pages with company branding

#### Benefits of Federation

**For Users**:
- **Single set of credentials**: Use familiar home organization credentials everywhere
- **Single Sign-On**: Authenticate once, access multiple applications
- **No password proliferation**: Don't need to create/remember passwords for every service
- **Familiar authentication experience**: Always authenticate at their home organization's sign-in page

**For IT Administrators**:
- **Centralized management**: Manage users in one place (home directory)
- **Automatic provisioning/deprovisioning**: When user leaves organization, access automatically revoked everywhere
- **Consistent security policies**: MFA, Conditional Access, and other policies apply across all federated apps
- **Better audit trail**: Centralized logging of authentication events
- **Reduced helpdesk calls**: Fewer passwords mean fewer password reset requests

**For Organizations**:
- **Improved security**: No passwords stored in external systems
- **Better compliance**: Clear audit trail, centralized access control
- **Easier partner collaboration**: External partners use their own credentials
- **Lower administrative costs**: Reduced user management overhead
- **Faster onboarding**: New users immediately have access to all federated applications

**For Application Providers**:
- **No password storage**: Don't need to store/protect user passwords
- **Simplified authentication**: Delegate authentication to trusted identity providers
- **Enterprise readiness**: Support enterprise customers with SAML/SSO requirements
- **Reduced liability**: Authentication and credential management handled by IdP

#### Federation Security Considerations

**Trust is Critical**:
- Federation relies on cryptographic trust (certificates, signatures)
- Compromised Identity Provider = compromised access to all federated applications
- Protect Identity Provider with strongest security measures (MFA, Conditional Access, PIM)

**Token Security**:
- Tokens must be signed to prevent tampering
- Tokens should be short-lived to limit damage if intercepted
- Use HTTPS/TLS to encrypt tokens in transit

**Metadata Management**:
- Keep federation metadata up to date
- Rotate signing certificates before expiration
- Monitor for federation trust changes

**Claims Validation**:
- Service Providers should validate all claims in tokens
- Don't blindly trust all claims - validate against expected values
- Implement authorization logic beyond just authentication

#### Federation vs Other Authentication Models

| Model | Description | Example | Best For |
|-------|-------------|---------|----------|
| **Local Authentication** | Each app has its own user database | WordPress blog with local accounts | Single-app scenarios, no integration needs |
| **Directory Authentication** | Apps authenticate against central directory | Apps querying on-prem Active Directory via LDAP | On-premises corporate applications |
| **Federation** | Apps trust external identity provider's tokens | Enterprise using Azure AD to access Salesforce | Cross-organization access, SaaS apps, B2B |
| **Social Login** | Apps accept social provider authentication | "Sign in with Google" | Consumer applications, B2C scenarios |

#### Real-World Federation Examples

**Example 1: University Student Access**:
- Student enrolled at University A
- Wants to access online library resources provided by Publisher
- Publisher federates with hundreds of universities
- Student goes to Publisher's website, chooses University A
- Redirected to University A's authentication system
- Authenticates with university credentials
- University issues SAML token to Publisher
- Publisher grants access to library resources
- No need to create separate Publisher account

**Example 2: Corporate SaaS Applications**:
- Company uses Azure AD for employee identity
- Subscribes to Salesforce, Workday, ServiceNow, DocuSign
- Configures SAML federation for all four applications
- Employees sign in once to Azure AD in the morning
- Access all four SaaS apps without additional sign-ins (SSO)
- IT adds/removes application access centrally in Azure AD
- When employee leaves, all access automatically revoked

**Example 3: Partner Collaboration**:
- Contoso working on project with Fabrikam partner company
- Fabrikam employees need access to Contoso's SharePoint and Teams
- Contoso enables Azure AD B2B and invites Fabrikam users
- Fabrikam users sign in with their @fabrikam.com credentials
- Fabrikam's Azure AD authenticates them
- Contoso's Azure AD trusts Fabrikam's authentication
- Fabrikam users access Contoso resources as guest users
- When project ends, Contoso revokes guest access

#### Key Takeaways - Federation

- **Federation = Trust between identity systems** allowing authentication to be performed once and accepted everywhere
- **Identity Provider (IdP)** authenticates users, **Service Provider (SP)** accepts authentication tokens
- **SAML 2.0** is most common protocol for enterprise federation
- **OAuth 2.0/OpenID Connect** used for modern web/mobile applications
- **AD FS** is Microsoft's on-premises federation service (migrating to Azure AD recommended)
- **Azure AD** acts as both Identity Provider (for your users) and Service Provider (accepting external identities)
- **Benefits**: Single Sign-On, centralized management, better security, easier partner collaboration
- **Security**: Protect Identity Provider strongly - it's the key to all federated systems

### Identity Types

#### Cloud Identities
**Definition**:
User accounts created and managed entirely in Azure AD (Entra ID) with no on-premises Active Directory presence.

**Use Cases**:
- Cloud-only organizations (no on-premises infrastructure)
- External contractors or temporary workers
- New organizations starting in the cloud
- SaaS application access

**Examples**: user@contoso.onmicrosoft.com, clouduser@company.com (managed in Entra ID only)

### Cloud Identity Types for Applications and Services

Beyond traditional user identities, Azure AD provides specialized identity types for applications, services, and automated workloads. These identities enable secure, passwordless access to Azure resources without human interaction.

#### Service Principals

**What is a Service Principal?**
A Service Principal is an identity created for use with applications, services, and automation tools that need to access Azure resources. It's the local representation of an application object in a specific Azure AD tenant.

**Think of it as**: An identity for an application (like a user account, but for apps and scripts instead of people)

**Key Concepts**:

**Application Object**:
- The global definition of an application
- Lives in the "home" Azure AD tenant where the app was registered
- Defines the application's capabilities and required permissions
- Only ONE application object exists per application

**Service Principal**:
- The local representation in each tenant where the app is used
- Created when an app is registered or consented to in a tenant
- Used to secure access to resources in that specific tenant
- Multiple service principals can exist (one per tenant where app is used)

**Relationship**: Application Object (blueprint) → Service Principal (local instance in each tenant)

**Types of Service Principals**:

**1. Application Service Principal**:
- Represents a multi-tenant or single-tenant application
- Created when you register an app in Azure AD
- Most common type
- **Example**: Service principal for your custom application accessing Microsoft Graph API

**2. Managed Identity Service Principal**:
- Automatically managed by Azure (no credentials to manage)
- Special type of service principal with automatic credential rotation
- Detailed in Managed Identities section below
- **Example**: Azure VM's system-assigned managed identity

**3. Legacy Service Principal**:
- Represents legacy applications or services
- Used for backward compatibility
- Less common in modern deployments

**How Service Principals Work**:

```
Application needs to access Azure resources
         ↓
Application authenticates using Service Principal credentials
         ↓
Azure AD validates credentials and issues access token
         ↓
Application uses token to access resources (Storage, Key Vault, APIs)
         ↓
Resource checks token claims and grants access based on assigned roles
```

**Authentication Methods for Service Principals**:

**1. Client Secret (Password)**:
- Simple password-like credential
- Must be stored securely (Key Vault recommended)
- Expires and must be manually rotated
- **Security Risk**: Can be stolen if exposed in code or logs
- **Use when**: Simplicity is priority, running in secure environment

**2. Certificate**:
- X.509 certificate for authentication
- More secure than client secrets
- Supports longer expiration periods
- Certificate must be securely stored and rotated
- **Use when**: Higher security required, compliance mandates

**3. Federated Credentials (Workload Identity Federation)**:
- Modern passwordless approach
- No secrets stored - uses trust relationship with external identity provider
- GitHub Actions, Azure Pipelines, Kubernetes can use their own tokens
- **Most secure option** - no credential storage or rotation needed
- **Use when**: Deploying from CI/CD pipelines, running in Kubernetes

**Creating a Service Principal**:

Azure Portal method:
1. Navigate to Azure AD → App Registrations
2. Click "New registration"
3. Provide name and account type (single/multi-tenant)
4. Service principal automatically created
5. Add credentials (secret or certificate)
6. Assign Azure RBAC roles or application permissions

**Permissions for Service Principals**:

**Delegated Permissions**:
- Service principal acts on behalf of a signed-in user
- Limited to what the user can do
- Requires user consent
- **Example**: App reads user's emails (requires user sign-in)

**Application Permissions**:
- Service principal acts as itself (no user context)
- Can perform actions beyond individual user permissions
- Requires admin consent
- **Example**: App reads all users' emails in organization

**Common Use Cases**:

| Scenario | Description | Example |
|----------|-------------|---------|
| **Automation Scripts** | PowerShell or Azure CLI scripts accessing Azure | Backup script accessing storage accounts |
| **CI/CD Pipelines** | GitHub Actions or Azure DevOps deploying resources | Pipeline deploying infrastructure via ARM templates |
| **Custom Applications** | Apps calling Microsoft Graph or Azure APIs | Web app reading user profiles from Graph API |
| **Third-Party Tools** | External services accessing your Azure resources | Monitoring tool querying Azure resources |
| **Microservices** | Service-to-service authentication | API calling another API securely |

**Security Best Practices**:

- [x] **Least Privilege**: Grant only the minimum permissions needed
- [x] **Credential Storage**: Store secrets in Azure Key Vault, never in code
- [x] **Credential Rotation**: Rotate secrets and certificates regularly
- [x] **Prefer Managed Identities**: Use Managed Identities instead when possible (no credential management)
- [x] **Use Federated Credentials**: Implement workload identity federation for CI/CD
- [x] **Monitor Usage**: Track service principal sign-ins and API calls
- [x] **Limit Lifetime**: Set short expiration for credentials
- [x] **Separate Service Principals**: Use different service principals for different apps/environments

**Service Principal vs User Account**:

| Aspect | Service Principal | User Account |
|--------|------------------|--------------|
| **Purpose** | Applications and services | Human users |
| **Authentication** | Client secret, certificate, or federated credential | Password, MFA, passwordless |
| **Interactive Sign-in** | No | Yes |
| **MFA Support** | No (use certificate or managed identity for security) | Yes |
| **Conditional Access** | Limited support | Full support |
| **License Required** | No (uses app licenses) | Yes (Azure AD Premium for advanced features) |
| **Lifecycle** | Managed by app owners | Managed by HR processes |

**Example Scenario**:

A company has a custom web application that needs to:
- Read user profiles from Microsoft Graph
- Store files in Azure Blob Storage
- Read secrets from Azure Key Vault

**Solution using Service Principal**:
1. Register app in Azure AD (creates application object and service principal)
2. Configure Microsoft Graph API permissions (User.Read.All - application permission)
3. Admin grants consent for the Graph permission
4. Assign Azure RBAC roles:
   - "Storage Blob Data Contributor" on storage account
   - "Key Vault Secrets User" on key vault
5. Create client secret or certificate for authentication
6. Store credentials in Azure Key Vault (accessed by app at runtime)
7. Application authenticates as service principal and accesses all three resources

#### Managed Identities

**What is a Managed Identity?**
A Managed Identity is a special type of service principal that is automatically managed by Azure. Microsoft handles all credential management (creation, rotation, deletion), eliminating the need to store or manage credentials.

**Think of it as**: Service principal with automatic credential management - "passwordless authentication for Azure resources"

**The Problem Managed Identities Solve**:

**Traditional Challenge**:
- Applications need credentials to access Azure resources
- Credentials must be stored somewhere (code, config files, Key Vault)
- Credentials must be rotated periodically
- Credentials can be leaked, stolen, or accidentally exposed
- Managing credentials across hundreds of resources is complex

**Managed Identity Solution**:
- Azure automatically creates and manages credentials
- Credentials never exposed to developers or code
- Automatic credential rotation (no expiration to worry about)
- No secrets stored anywhere
- Free to use (no additional cost)

**Types of Managed Identities**:

#### 1. System-Assigned Managed Identity

**Characteristics**:
- Created and tied directly to a single Azure resource
- Lifecycle bound to the resource (deleted when resource is deleted)
- Cannot be shared across multiple resources
- Automatically created and managed
- 1:1 relationship (one identity per resource)

**How it works**:
```
Create Azure VM with system-assigned managed identity enabled
         ↓
Azure automatically creates a service principal in Azure AD
         ↓
Service principal name: Same as resource name
         ↓
Azure manages all credentials automatically
         ↓
VM can request tokens from Azure Instance Metadata Service (IMDS)
         ↓
VM uses tokens to access Azure resources (Storage, Key Vault, etc.)
```

**When to use**:
- Simple scenarios with single resource accessing other resources
- When identity lifecycle should match resource lifecycle
- No need to share identity across multiple resources
- **Example**: Single VM accessing its own storage account

**Enabling System-Assigned Managed Identity**:

Azure Portal:
1. Navigate to Azure resource (VM, App Service, Function App, etc.)
2. Go to "Identity" section
3. Toggle "System assigned" status to "On"
4. Azure creates service principal automatically
5. Assign Azure RBAC roles to grant permissions

**Supported Azure Resources**:
- Virtual Machines and Virtual Machine Scale Sets
- Azure App Service and Azure Functions
- Azure Container Instances
- Azure Kubernetes Service (AKS)
- Azure Logic Apps
- Azure Data Factory
- Azure API Management
- Many other Azure services

#### 2. User-Assigned Managed Identity

**Characteristics**:
- Created as a standalone Azure resource
- Independent lifecycle (exists separately from resources using it)
- Can be shared across multiple resources
- Explicitly assigned to resources that need it
- 1:Many relationship (one identity used by multiple resources)

**How it works**:
```
Create user-assigned managed identity as Azure resource
         ↓
Azure creates service principal in Azure AD
         ↓
Assign RBAC permissions to the managed identity
         ↓
Assign the managed identity to one or more Azure resources (VMs, Apps, etc.)
         ↓
Each resource can authenticate using the shared managed identity
         ↓
Resources use tokens to access Azure resources
```

**When to use**:
- Multiple resources need the same set of permissions
- Identity should persist even if resources are deleted/recreated
- Pre-provision identities with permissions before creating resources
- Centralized identity management across multiple resources
- **Example**: 10 VMs all accessing the same Key Vault with identical permissions

**Creating User-Assigned Managed Identity**:

Azure Portal:
1. Navigate to "Managed Identities" in Azure Portal
2. Click "Create"
3. Provide name and resource group
4. Identity created as standalone Azure resource
5. Assign RBAC roles to grant permissions
6. Assign this identity to resources that need it (VMs, App Services, etc.)

**System-Assigned vs User-Assigned Comparison**:

| Aspect | System-Assigned | User-Assigned |
|--------|-----------------|---------------|
| **Creation** | Enabled on existing resource | Created as standalone resource |
| **Lifecycle** | Tied to resource (deleted with resource) | Independent (survives resource deletion) |
| **Sharing** | Cannot be shared (1:1) | Can be shared across resources (1:Many) |
| **Use Case** | Simple single-resource scenarios | Multiple resources needing same permissions |
| **Management** | Automatic with resource | Separate management as Azure resource |
| **Identity Count** | One per resource | One identity for many resources |
| **Permission Model** | Individual per resource | Centralized for all resources |

**How Applications Use Managed Identities**:

**Code Example Workflow**:
```
Application code needs to access Azure Key Vault
         ↓
Application calls Azure Instance Metadata Service (IMDS) endpoint
         ↓
IMDS endpoint: http://169.254.169.254/metadata/identity/oauth2/token
         ↓
IMDS validates the request is coming from the Azure resource
         ↓
IMDS returns access token for the managed identity
         ↓
Application uses token to authenticate to Key Vault
         ↓
Key Vault validates token and grants access based on RBAC
         ↓
Application retrieves secrets without any stored credentials
```

**Azure SDKs and Libraries**:
Modern Azure SDKs (Azure SDK for .NET, Python, Java, JavaScript) include DefaultAzureCredential, which automatically detects and uses managed identities without code changes:

- Application code: "Give me access to Key Vault"
- DefaultAzureCredential: Automatically tries managed identity first
- No credential management code needed
- Same code works locally (dev) and in Azure (production) with different credentials

**Managed Identity Authentication Flow**:

**Step 1: Token Request**
- Application requests token from Azure Instance Metadata Service (IMDS)
- Request includes target resource (e.g., Key Vault, Storage, Microsoft Graph)

**Step 2: IMDS Validation**
- IMDS verifies request comes from Azure resource with managed identity
- IMDS contacts Azure AD on behalf of the resource

**Step 3: Token Issuance**
- Azure AD validates managed identity and issues access token
- Token contains identity information and target resource scope

**Step 4: Resource Access**
- Application presents token to target resource
- Resource validates token and checks RBAC permissions
- Access granted if permissions are sufficient

**Managed Identity Use Cases**:

| Scenario | Description | Example |
|----------|-------------|---------|
| **Secret Retrieval** | Applications accessing secrets without storing credentials | Web app reading database connection string from Key Vault |
| **Storage Access** | Services accessing storage accounts | Function app writing logs to Blob Storage |
| **Database Authentication** | Connecting to Azure SQL without password | App Service connecting to Azure SQL Database |
| **Service-to-Service** | Microservices authenticating to each other | One API calling another API via API Management |
| **Resource Management** | Automation accessing Azure Resource Manager | Logic App creating/managing Azure resources |
| **Monitoring and Logging** | Services sending telemetry | Application sending metrics to Azure Monitor |

**Permissions and RBAC**:

Managed identities use Azure Role-Based Access Control (RBAC) for authorization:

**Common Azure RBAC Roles for Managed Identities**:
- [x] **Key Vault Secrets User**: Read secrets from Key Vault
- [x] **Storage Blob Data Contributor**: Read/write blobs in storage account
- [x] **Storage Queue Data Contributor**: Read/write queue messages
- [x] **Reader**: Read-only access to Azure resources
- [x] **Contributor**: Manage resources (cannot assign roles)
- [x] **Monitoring Metrics Publisher**: Send metrics to Azure Monitor

**Assigning Permissions**:
1. Navigate to target resource (Key Vault, Storage, etc.)
2. Go to "Access Control (IAM)"
3. Click "Add role assignment"
4. Select role (e.g., "Key Vault Secrets User")
5. Assign to managed identity (system-assigned or user-assigned)

**Microsoft Graph Permissions**:
Managed identities can also access Microsoft Graph API:
- Use PowerShell or Microsoft Graph API to assign application permissions
- Grant permissions like "User.Read.All", "Mail.Send", etc.
- Admin consent required for Graph permissions

**Benefits of Managed Identities**:

**1. Security**:
- No credentials stored in code, config files, or environment variables
- No risk of credential leakage in Git repositories or logs
- Automatic credential rotation (no expiration to manage)
- Eliminates password-based attacks (phishing, credential theft)

**2. Simplified Management**:
- No credential lifecycle management (creation, storage, rotation, deletion)
- No secrets to track or expire
- Reduces operational overhead
- Fewer security incidents from expired credentials

**3. Developer Experience**:
- Developers never handle credentials
- Same code works in development and production (different identity sources)
- Azure SDKs handle authentication automatically
- Reduces onboarding complexity

**4. Cost**:
- Free to use (no additional licensing cost)
- Reduces Key Vault costs (fewer secrets to store)
- Reduces operational costs (less credential management)

**5. Compliance**:
- Credentials managed by Microsoft (audited and certified)
- Reduces attack surface for compliance audits
- Meets security best practices and frameworks
- Audit logs for all identity usage

**Limitations and Considerations**:

**What Managed Identities CAN do**:
- Authenticate to any Azure service that supports Azure AD authentication
- Access Azure resources (Key Vault, Storage, SQL Database, etc.)
- Call Microsoft Graph API
- Access other Azure AD protected APIs
- Work across Azure subscriptions (with proper RBAC)

**What Managed Identities CANNOT do**:
- Work outside Azure (on-premises servers, external clouds) - use Service Principal instead
- Interactive sign-in (no user context)
- Multi-factor authentication (designed for service-to-service)
- Access non-Azure AD protected resources
- Share secrets with external parties

**When to use Service Principal vs Managed Identity**:

| Scenario | Recommendation |
|----------|----------------|
| **Running in Azure** | Use Managed Identity (system or user-assigned) |
| **Running outside Azure** | Use Service Principal with federated credentials or certificate |
| **CI/CD Pipeline (GitHub, Azure DevOps)** | Use Workload Identity Federation (federated service principal) or Managed Identity if pipeline runs in Azure |
| **Multiple resources, same permissions** | Use User-Assigned Managed Identity |
| **Single resource** | Use System-Assigned Managed Identity |
| **Need to share identity externally** | Use Service Principal |
| **Third-party service** | Use Service Principal |

**Real-World Example**:

**Scenario**: Company deploys web application on Azure App Service that needs to:
- Read secrets from Azure Key Vault (database connection strings)
- Store uploaded files in Azure Blob Storage
- Query data from Azure SQL Database
- Send emails via Microsoft Graph API

**Traditional Approach (insecure)**:
- Store Key Vault secret in application config
- Store storage account key in environment variables
- Store SQL password in connection string
- Store Graph API client secret in code
- **Problem**: 4 secrets to manage, rotate, and protect from leaking

**Managed Identity Approach (secure)**:
1. Enable system-assigned managed identity on App Service
2. Grant managed identity RBAC permissions:
   - "Key Vault Secrets User" on Key Vault
   - "Storage Blob Data Contributor" on Storage Account
   - Assign Graph API permissions (Mail.Send)
   - Configure Azure SQL Database to accept managed identity authentication
3. Application code uses DefaultAzureCredential (Azure SDK)
4. Azure automatically handles all authentication
5. **Result**: ZERO credentials stored, managed, or exposed

**Code Example (Conceptual)**:
```csharp
// No credentials in code - DefaultAzureCredential automatically uses managed identity
var credential = new DefaultAzureCredential();

// Access Key Vault
var keyVaultClient = new SecretClient(keyVaultUri, credential);
var secret = await keyVaultClient.GetSecretAsync("DatabaseConnectionString");

// Access Blob Storage
var blobClient = new BlobServiceClient(storageUri, credential);
await blobClient.UploadBlobAsync("container", "file.txt", fileStream);

// Access Microsoft Graph
var graphClient = new GraphServiceClient(credential);
await graphClient.Users["user@contoso.com"].SendMail(message).Request().PostAsync();

// Zero credentials managed by developer!
```

**Migration Path**:

Organizations moving from service principals to managed identities:

**Phase 1: Assessment**
- Identify all service principals used by applications
- Determine which apps run in Azure (candidates for managed identity)
- Document current permissions and RBAC assignments

**Phase 2: Pilot**
- Select low-risk application for pilot
- Enable managed identity on Azure resource
- Replicate RBAC permissions from service principal to managed identity
- Update application code to use DefaultAzureCredential
- Test thoroughly in non-production environment

**Phase 3: Rollout**
- Gradually migrate applications to managed identities
- Decommission service principals after successful migration
- Update documentation and runbooks

**Phase 4: Governance**
- Establish policy: "Use managed identities for all Azure resources"
- Exception process for non-Azure scenarios (require service principal with federated credentials)
- Regular audits to ensure compliance

**Monitoring and Auditing**:

**Azure AD Sign-in Logs**:
- Track managed identity authentication attempts
- View which resources accessed what APIs
- Detect anomalous behavior

**Azure Activity Logs**:
- Track role assignments to managed identities
- Monitor permission changes
- Compliance and audit trails

**Azure Monitor**:
- Set alerts for managed identity failures
- Dashboard for identity usage across resources
- Troubleshooting authentication issues

**Best Practices**:

- [x] **Prefer Managed Identities**: Use managed identities whenever running in Azure
- [x] **System-Assigned for Simple Cases**: Use system-assigned for single-resource scenarios
- [x] **User-Assigned for Sharing**: Use user-assigned when multiple resources need same permissions
- [x] **Least Privilege**: Grant only minimum RBAC permissions needed
- [x] **Separate Identities**: Use different managed identities for dev/test/production environments
- [x] **Monitor Usage**: Track sign-ins and API calls for anomaly detection
- [x] **Document Permissions**: Maintain inventory of managed identities and their permissions
- [x] **Test Failover**: Ensure managed identity works across Azure regions if using geo-redundancy

**Key Takeaways - Service Principals and Managed Identities**:

1. **Service Principals** = Identities for applications and services to access Azure resources
2. **Managed Identities** = Special service principals with automatic credential management by Azure
3. **System-Assigned** = Tied to single resource, deleted with resource (1:1)
4. **User-Assigned** = Standalone identity shared across resources (1:Many)
5. **Always prefer managed identities** when running in Azure (no credential management)
6. **Use service principals** for non-Azure scenarios, CI/CD pipelines, or external services
7. **Security benefits**: Zero credentials exposed, automatic rotation, reduced attack surface
8. **Cost**: Free to use, reduces operational overhead
9. **Azure RBAC** controls what managed identities can access
10. **Azure SDKs** make managed identities seamless with DefaultAzureCredential

#### Hybrid Identities
**Definition**:
User accounts that exist in both on-premises Active Directory and Azure AD, synchronized between the two environments.

**How It Works**:
- User created in on-premises Active Directory
- Azure AD Connect synchronizes user to Azure AD
- Single identity across cloud and on-premises
- User can access both on-prem resources and cloud apps with same credentials

**Tools**: Azure AD Connect (synchronization engine)

**Benefits**:
- Single sign-on across on-prem and cloud
- Unified identity management
- Supports gradual cloud migration

#### External Identities (B2B/B2C)

**B2B (Business-to-Business)**:
- Invite external partners, vendors, suppliers to collaborate
- Guests use their own credentials (work or personal account)
- Access your organization's applications and resources
- Example: Partner at supplier.com accesses your SharePoint site

**Use Cases**:
- Collaboration with external business partners
- Vendor access to specific resources
- Cross-organization project teams

**B2C (Business-to-Consumer)**:
- Customer-facing applications for millions of consumers
- Customers sign in with social accounts (Google, Facebook) or create local accounts
- Customizable sign-in experience with branding
- Example: E-commerce site where customers create accounts

**Use Cases**:
- Consumer mobile apps
- E-commerce websites
- Customer portals
- Public-facing web applications

### Entra ID Editions

| Feature | Free | Premium P1 | Premium P2 |
|---------|------|------------|------------|
| **Users** | Up to 500,000 objects | Unlimited | Unlimited |
| **SSO** | Unlimited cloud apps | ✓ Unlimited | ✓ Unlimited |
| **MFA** | Security defaults (basic) | ✓ Full MFA | ✓ Full MFA |
| **Conditional Access** | ✗ Not included | ✓ Included | ✓ Included |
| **Identity Protection** | ✗ Not included | ✗ Not included | ✓ Included (risk-based policies) |
| **PIM** | ✗ Not included | ✗ Not included | ✓ Included (JIT access) |
| **Price** | Free (included with Microsoft 365) | $6/user/month | $9/user/month |

**Additional Features by Edition**:

**Free**:
- User and group management
- Self-service password change (cloud users)
- Basic reports
- SSO to Azure, Microsoft 365, and popular SaaS apps

**Premium P1** (adds):
- Conditional Access policies
- Self-service password reset with writeback
- Dynamic groups
- Advanced group features
- Microsoft Identity Manager (MIM) licensing
- Cloud App Discovery

**Premium P2** (adds):
- Identity Protection (risk-based policies)
- Privileged Identity Management (PIM)
- Access reviews
- Entitlement management

### Key Takeaways
- Azure AD (Entra ID) is Microsoft's cloud identity service
- Supports cloud-only, hybrid, and external identities (B2B/B2C)
- Premium editions required for advanced security features (Conditional Access, PIM, Identity Protection)

---

## 2.3 Authentication Methods

### Password-Based Authentication

**Traditional Passwords**:
Most common authentication method where users provide a username and password to verify identity.

**Weaknesses**:
- Easily compromised (phishing, brute force, password spray attacks)
- Users create weak or reused passwords across multiple sites
- Password fatigue leads to poor security practices (sticky notes, simple patterns)
- No protection if credentials are leaked in data breaches
- Single point of failure for account security

### Multi-Factor Authentication (MFA)

**Definition**:
Security process requiring two or more verification methods to prove identity. Blocks 99.9% of account compromise attacks.

**Three Factors**:
1. **Something you know**: Password, PIN, security questions
2. **Something you have**: Phone, hardware token, smart card, authenticator app
3. **Something you are**: Biometrics (fingerprint, face recognition, retina scan)

**Microsoft MFA Methods**:
- [x] Microsoft Authenticator app (push notification - RECOMMENDED)
- [x] Voice call (automated call with PIN)
- [x] OATH hardware tokens (physical device generating codes)
- [x] OATH software tokens (app-based time-based codes)
- [ ] ~~SMS text message~~ (DEPRECATED - No longer supported by Microsoft due to security vulnerabilities)

**When to Use**:
- ALL administrator accounts (required best practice)
- High-value or sensitive resource access
- Sign-ins from unfamiliar locations or devices
- Remote access scenarios
- Privileged operations

### Passwordless Authentication

**Why Passwordless?**:
- Eliminates password-related attacks (phishing, credential theft, password spray)
- Improved user experience (faster, more convenient sign-in)
- More secure than passwords (uses cryptographic keys instead of shared secrets)
- Reduces IT helpdesk costs (no password resets)
- Aligns with Zero Trust security principles

**Microsoft Passwordless Methods**:

#### Windows Hello for Business
**What**:
Biometric or PIN-based authentication tied to a specific device

**How it works**:
- Uses facial recognition, fingerprint, or PIN
- Creates cryptographic key pair bound to the device's TPM (Trusted Platform Module)
- Private key never leaves the device
- Works offline (PIN) and online

**Use case**:
- Corporate Windows devices
- Primary authentication for employees on managed PCs
- Best for: Office workers with dedicated workstations

#### FIDO2 Security Keys
**What**:
Physical hardware security keys that provide strong passwordless authentication

**How it works**:
- USB, NFC, or Bluetooth security key (e.g., YubiKey)
- User inserts/taps key and may provide PIN or biometric
- Uses public key cryptography (FIDO2/WebAuthn standard)
- Resistant to phishing (domain-bound credentials)

**Use case**:
- Shared workstations or kiosks
- High-security environments
- Users who work across multiple devices
- Best for: Admins, developers, security-sensitive roles

#### Microsoft Authenticator App
**What**:
Smartphone-based passwordless authentication using push notifications

**How it works**:
- User enters username (no password)
- Push notification sent to registered phone
- User approves with biometric (fingerprint/face) or PIN
- Number matching prevents MFA fatigue attacks

**Use case**:
- Mobile workforce
- Users with smartphones
- Remote workers
- Best for: General workforce with mobile devices

### Password Protection

**Azure AD Password Protection**:
For organizations still using passwords, Azure AD provides enhanced protection:
- **Global Banned Password List**: Microsoft-maintained list of known weak passwords (e.g., "Password1", "Summer2024")
- **Smart Lockout**: Detects and blocks brute-force and password spray attacks
- **Password Hash Synchronization**: Validates passwords against known breaches
- **Contextual Blocking**: Considers organization name and variations

**Custom Banned Password Lists**:
- Organizations can add custom terms (company name, product names, industry terms)
- Up to 1000 custom banned passwords
- Case-insensitive and variation-aware (e.g., "P@ssw0rd" blocked if "password" is banned)
- Applies to password creation and reset scenarios

**On-Premises Integration**:
- Azure AD Password Protection can extend to on-premises Active Directory
- Requires Azure AD Premium P1 or P2
- Protects hybrid environments with consistent policy enforcement
- Agents installed on domain controllers enforce cloud-based policies

---

## 2.4 Conditional Access

### Overview

**What is Conditional Access?**:
Azure AD's policy-based engine that evaluates signals about authentication attempts and enforces organizational policies before granting access to resources. It's the Zero Trust "policy enforcement point" that decides who gets access to what, under which conditions.

**Think of it as**: Intelligent security guard that evaluates multiple factors before allowing entry.

**Requires**: Azure AD Premium P1 or P2

**How it Works** (IF-THEN):
- **IF**: User signals (who, what, where, how)
- **THEN**: Access controls (grant, block, require)

**Example**: IF user is an admin AND signing in from untrusted location, THEN require MFA and compliant device.

### Conditional Access Signals

Signals are the "IF" part - conditions evaluated when someone tries to access resources.

#### User/Group
- Specific users or groups
- All users, guest users, or directory roles
- Exclude emergency access accounts
- Example: Apply policy to "All Admins" group

#### Location
- Named locations (IP address ranges)
- Trusted vs untrusted locations
- Countries/regions
- Example: Block access from specific countries, allow from corporate network

#### Device
- Device platform (Windows, macOS, iOS, Android)
- Device state (compliant, hybrid Azure AD joined)
- Managed vs unmanaged devices
- Example: Require compliant devices for accessing company data

#### Application
- Specific cloud apps (Microsoft 365, Salesforce, custom apps)
- All cloud apps
- User actions (register security info, join devices)
- Example: Require MFA for accessing Azure portal

#### Risk Level
- Sign-in risk (low, medium, high) - detected by Identity Protection
- User risk (compromised credentials detected)
- Example: If high sign-in risk detected, require MFA and password change

#### Real-time Session Behavior
- Sign-in frequency (how often to re-authenticate)
- Persistent browser sessions
- Example: Require re-authentication every 4 hours for sensitive apps

### Conditional Access Controls

Controls are the "THEN" part - actions taken when conditions are met.

#### Grant Controls
Determine whether to block or grant access, and under what requirements:

- [x] **Block access**: Deny access completely (strongest control)
- [x] **Grant access**: Allow access (but may require additional controls below)
- [x] **Require MFA**: User must provide second authentication factor
- [x] **Require device to be marked as compliant**: Device must meet Intune compliance policies
- [x] **Require hybrid Azure AD joined device**: Device must be domain-joined and registered
- [x] **Require approved client app**: Use approved apps like Outlook Mobile, not browser
- [x] **Require app protection policy**: App must have Intune app protection applied

**Multiple controls**: Can require ALL controls or ANY ONE control

#### Session Controls
Apply limited experiences within cloud applications:

- [x] **Use app enforced restrictions**: Limited functionality (e.g., view-only access in SharePoint)
- [x] **Use Conditional Access App Control**: Real-time monitoring and control via Microsoft Defender for Cloud Apps
- [x] **Sign-in frequency**: Force re-authentication after specified time
- [x] **Persistent browser session**: Keep users signed in or require re-auth

### Common Conditional Access Policies

| Policy Name | Purpose | Example Configuration |
|-------------|---------|----------------------|
| **Require MFA for admins** | Protect privileged accounts | IF: Admin role, THEN: Require MFA |
| **Block legacy authentication** | Prevent attacks on older protocols | IF: Legacy auth protocol, THEN: Block access |
| **Require managed devices** | Ensure corporate data on compliant devices | IF: Accessing SharePoint, THEN: Require compliant device |
| **Risk-based access** | Respond to suspicious sign-ins | IF: High sign-in risk, THEN: Require MFA + password change |
| **Location-based access** | Restrict access by geography | IF: Sign-in from blocked country, THEN: Block access |

**Real-World Example**:
```
Policy: "Secure Admin Access"
IF:
  - User is member of "Global Administrators" group
  - AND signing in to Azure Portal
  - AND location is NOT corporate network
THEN:
  - Require MFA
  - AND Require compliant device
  - AND Sign-in frequency: 4 hours
```

### Best Practices
- **Always have emergency access** ("break glass") accounts excluded from all policies
- **Use report-only mode** to test policies before enforcement
- **Start with admins first**, then roll out to general users
- **Block legacy authentication** as priority #1 security quick win
- **Require MFA for all users**, especially admins and external access
- **Use named locations** to define trusted networks
- **Monitor Conditional Access insights** to understand policy impact

### Key Takeaways
- Conditional Access is the Zero Trust policy enforcement engine
- Requires Azure AD Premium P1 (or P2 for risk-based policies)
- Evaluates signals (user, location, device, app, risk) and enforces controls (block, grant, require)
- Essential for modern security posture and regulatory compliance

---

## 2.5 Azure AD Identity Protection

### Overview

**What is Identity Protection?**:
Azure AD Identity Protection uses machine learning and heuristics to detect suspicious activities and identity-based risks. It automatically detects, investigates, and can remediate risks related to user identities and sign-in attempts.

**Requires**: Azure AD Premium P2

**Key Capabilities**:
- Automated risk detection using AI and Microsoft threat intelligence
- Risk investigation with detailed reports and workbooks
- Risk-based Conditional Access policies for automated remediation
- Export risk data to SIEM tools for further analysis

### Risk Types

#### Sign-in Risk
**Definition**: Risk that a specific sign-in attempt is not performed by the legitimate user (account takeover attempt)

**Risk Detections**:
- [x] **Atypical travel**: Impossible travel between geographic locations
- [x] **Anonymous IP address**: Sign-in from anonymous IP (Tor, VPN)
- [x] **Malware linked IP address**: IP address known to be infected
- [x] **Unfamiliar sign-in properties**: Unusual for this user (device, location, ASN)
- [x] **Password spray**: Multiple usernames attacked with common passwords
- [x] **Azure AD threat intelligence**: Microsoft's threat intelligence detects malicious activity

**Detected in Real-Time**: Some detections are real-time, others are offline (take 2-48 hours)

**Response**: Prompt for MFA, require password change, or block access via Conditional Access

#### User Risk
**Definition**: Risk that the user's identity has been compromised (account is in danger or already breached)

**Risk Detections**:
- [x] **Leaked credentials**: User's credentials found in dark web, paste sites, or breach databases
- [x] **Azure AD threat intelligence**: Unusual activity patterns based on Microsoft's global threat data
- [x] **Unusual behavior**: Anomalous user activity not matching normal patterns

**Detected Offline**: User risk is typically calculated offline and may take time to appear

**Response**: Require password change, force MFA registration, or block access until admin investigates

### Risk Levels

Risks are assigned severity levels based on confidence and impact:

- **High**: Strong indicators of compromise - immediate action required (e.g., leaked credentials confirmed)
- **Medium**: Moderate indicators - increased monitoring and possible MFA required (e.g., unfamiliar sign-in properties)
- **Low**: Weak signals - log for investigation (e.g., minor deviations from normal behavior)

**Administrators set policy thresholds** - decide what risk level triggers which response.

### Risk-Based Policies

Use Conditional Access to automate responses based on detected risk levels.

#### Sign-in Risk Policy
**Configuration**:
- Set risk level threshold (Low, Medium, High)
- Choose response: Allow with MFA, Require password change, or Block

**Example**:
```
IF: Sign-in risk is Medium or High
THEN: Require MFA
RESULT: User must complete MFA to continue, risk auto-remediated if successful
```

#### User Risk Policy
**Configuration**:
- Set risk level threshold (Low, Medium, High)
- Typically requires password change for remediation

**Example**:
```
IF: User risk is High
THEN: Require password change
RESULT: User must create new password before accessing resources
```

**Automatic Risk Remediation**: When user successfully completes MFA or password change, risk is automatically closed.

### Investigation

**Risk Events Dashboard**:
Azure AD provides several reports and views:
- **Risky users**: Users flagged with user risk
- **Risky sign-ins**: Sign-in attempts flagged with sign-in risk
- **Risk detections**: Detailed list of all detections with risk types and times
- **Workbooks**: Visual analytics for risk trends and patterns

**Remediation Actions**:
Administrators can take manual actions on risky users:

1. **Confirm safe**: Mark detection as false positive (user was legitimate)
2. **Confirm compromised**: Confirm the account is breached (forces password reset, revokes tokens)
3. **Dismiss**: Acknowledge but take no action on this specific risk
4. **Require password reset**: Force user to change password on next sign-in

**Integration**: Export risk events to Azure Sentinel, Microsoft Defender XDR, or third-party SIEM tools for broader security operations.

---

## 2.6 Identity Governance

### What is Identity Governance?

**Definition**:
Identity Governance ensures that the right people have the right access to the right resources at the right time. It helps organizations manage the identity lifecycle, control access to critical resources, and meet compliance requirements.

**Core Goal**: Answer "Who has access to what?" and ensure that access is appropriate, reviewed, and auditable.

**Four Key Questions**:
1. Which users should have access to which resources?
2. What are those users doing with that access?
3. Are there effective organizational controls for managing access?
4. Can auditors verify that the controls are working?

### Entitlement Management

**What it is**:
Azure AD feature that automates access request workflows, access assignments, reviews, and expiration for groups, applications, and SharePoint sites.

**Think of it as**: Self-service access catalog where users request access packages instead of asking IT for every permission.

**Key Features**:
- **Access packages**: Bundles of resources users can request
- **Approval workflows**: Multi-stage approvals with delegates
- **Access reviews**: Periodic certification of who has access
- **Automatic expiration**: Time-limited access that auto-revokes

**Access Package Components**:

| Component | Description | Example |
|-----------|-------------|---------|
| **Resources** | Groups, apps, SharePoint sites included in package | "Marketing Team" group + "Adobe Creative Cloud" app + "Marketing SharePoint" |
| **Policies** | Who can request, approval required, expiration time | Require manager approval, 90-day expiration |
| **Catalog** | Collection of related access packages | "Marketing Resources Catalog" |

**Use Cases**:
- Onboarding new employees with standard access bundles
- Project-based access that auto-expires when project ends
- Partner/vendor temporary access with approval workflows

**Example**: "Marketing Contractor Access" package includes Marketing group membership, Creative Cloud license, and SharePoint access - expires in 6 months, requires manager approval.

### Access Reviews

**What are Access Reviews?**:
Periodic certification process where designated reviewers verify that users still need their assigned access. Helps prevent "access creep" and ensures compliance.

**Types of Reviews**:
- [x] **Group membership reviews**: Review who belongs to security and Microsoft 365 groups
- [x] **Application access reviews**: Review who has access to specific applications
- [x] **Azure AD role reviews**: Review privileged role assignments (admin roles)
- [x] **Azure resource role reviews**: Review Azure RBAC role assignments (subscriptions, resource groups)

**Review Process**:
1. **Create review**: Define scope (what to review), reviewers, frequency
2. **Notify reviewers**: Automatic emails sent to reviewers with review link
3. **Reviewers decide**: Approve (keep access) or Deny (remove access)
4. **Auto-apply results**: System automatically removes access for denied users (or manual approval)

**Benefits**:
- Ensures least privilege by removing unnecessary access
- Meets compliance requirements (SOX, HIPAA, GDPR)
- Provides audit trail of access decisions
- Reduces security risks from abandoned accounts

**Best Practice**: Schedule quarterly reviews for privileged roles, annual reviews for standard access.

### Identity Lifecycle Management

**Definition**:
Identity lifecycle management is the process of managing user identities from creation through changes to eventual deletion. It ensures users have appropriate access throughout their entire journey with an organization while maintaining security and compliance.

**The Identity Lifecycle Stages**:

```
   CREATE → JOIN → MOVE → LEAVE → DELETE
      ↓       ↓      ↓       ↓        ↓
   Pre-hire → Onboard → Role Change → Offboard → Cleanup
```

#### Stage 1: CREATE (Pre-hire/Provisioning)
**When**: Before employee starts work
**Goal**: Prepare identity and initial resources

**Activities**:
- Create user account in Azure AD
- Generate temporary credentials or Temporary Access Pass (TAP)
- Pre-assign baseline access (default employee group, location-based access)
- Prepare mailbox and OneDrive
- Assign initial licenses (Microsoft 365 E3, Teams, etc.)
- Create Welcome email templates

**Automation Options**:
- HR system integration (Workday, SuccessFactors) automatically triggers account creation
- Template-based provisioning based on department/role
- Pre-hire workflows execute 7 days before start date

**Example**: HR adds new marketing manager to Workday → Azure AD automatically creates account → Marketing group membership assigned → Microsoft 365 license allocated → Welcome email drafted for Day 1

---

#### Stage 2: JOIN (Onboarding)
**When**: Employee's first day/week
**Goal**: Grant access needed to be productive immediately

**Activities**:
- Activate account (if disabled during pre-hire)
- Assign role-specific access packages
- Add to department groups and Teams channels
- Grant application access (Salesforce, Adobe, Jira, etc.)
- Enroll in MFA and device management
- Send onboarding communications and training links
- Assign physical access (if integrated)

**Onboarding Tasks**:
- [x] Generate Temporary Access Pass for first passwordless sign-in
- [x] Add user to security groups automatically based on department
- [x] Assign Microsoft 365 and application licenses
- [x] Add to Microsoft Teams channels (e.g., Marketing Team, All Employees)
- [x] Send welcome email with getting started resources
- [x] Trigger training module assignments (compliance, security awareness)
- [x] Register device for Intune management on first sign-in

**Example Workflow**:
```
Day 1 Trigger (start date = today)
  ↓
Enable account + Generate TAP
  ↓
Assign access package: "Marketing Manager Bundle"
  (includes: Marketing group, Adobe license, Salesforce access, Marketing SharePoint)
  ↓
Send welcome email with TAP and setup instructions
  ↓
User signs in with TAP → Prompted to set up MFA and passwordless
  ↓
User completes security training (automatically assigned)
```

**Key Benefit**: New employee can log in and access everything needed on Day 1 without IT tickets.

---

#### Stage 3: MOVE (Role Changes/Internal Transfers)
**When**: Employee changes role, department, or location
**Goal**: Update access to match new responsibilities while removing old access

**Common Scenarios**:
- Department transfer (Sales → Marketing)
- Promotion (Developer → Senior Developer)
- Location change (New York → London office)
- Temporary assignment (Project team for 3 months)

**Activities**:
- Remove old department/role access
- Add new department/role access
- Update group memberships
- Reassign licenses if needed (different apps for different roles)
- Update manager relationships
- Modify mailbox permissions
- Change Teams memberships

**Challenges Without Automation**:
- **Access creep**: User keeps old Sales access while getting new Marketing access
- **Productivity gaps**: Delay in getting new access slows down employee
- **Manual errors**: IT forgets to remove sensitive old access

**Automated Mover Process**:
```
Trigger: HR updates department in Workday (Sales → Marketing)
  ↓
Azure AD Connect syncs attribute change
  ↓
Lifecycle workflow detects department change
  ↓
Removes Sales group memberships
  ↓
Adds Marketing group memberships
  ↓
Removes Salesforce license
  ↓
Adds Adobe Creative Cloud license
  ↓
Updates manager to new department head
  ↓
Sends notification to old and new managers
```

**Best Practice**: Use dynamic groups based on HR attributes (department, jobTitle) so group membership automatically updates when attributes change.

---

#### Stage 4: LEAVE (Offboarding/Termination)
**When**: Employee resignation, termination, or end of contract
**Goal**: Immediately remove access while preserving data and audit trail

**Critical Actions** (must happen immediately):
- [x] Disable user account (block sign-in)
- [x] Revoke all active sessions and tokens
- [x] Remove from all groups (except audit groups)
- [x] Block access to email and OneDrive
- [x] Revoke application access
- [x] Remove from Teams and SharePoint
- [x] Disable MFA enrollments
- [x] Wipe corporate data from mobile devices

**Data Preservation Actions**:
- Convert mailbox to shared mailbox (preserve emails)
- Grant manager access to OneDrive for 30 days
- Archive Teams messages and files
- Transfer ownership of owned resources

**Phased Offboarding Approach**:

**Phase 1: Immediate (Termination day)**
```
Trigger: Last working day attribute set in HR system
  ↓
IMMEDIATELY disable account
  ↓
Revoke all refresh tokens (force sign-out)
  ↓
Remove from all security groups
  ↓
Remove application assignments
  ↓
Notify manager and security team
```

**Phase 2: Short-term (Days 1-30)**
```
Convert mailbox to shared mailbox
  ↓
Grant manager temporary access to email/OneDrive
  ↓
Remove licenses (keep mailbox as shared)
  ↓
Archive critical data
  ↓
Transfer document ownership
```

**Phase 3: Long-term (Day 30+)**
```
Delete shared mailbox (or archive to compliance retention)
  ↓
Delete OneDrive (after manager access expires)
  ↓
Hard delete user account from Azure AD
  ↓
Remove from all audit logs (after retention period)
```

**Security Considerations**:
- **Immediate action required**: Terminated employees pose insider threat risk
- **Audit trail**: Keep logs of what access was removed and when
- **Break-glass accounts**: Ensure offboarding doesn't remove emergency access
- **Vendor/contractor offboarding**: Critical for external users who may have had broad access

---

#### Stage 5: DELETE (Cleanup/Deprovisioning)
**When**: 30-90 days after termination
**Goal**: Permanently remove identity while maintaining compliance

**Activities**:
- Hard delete user from Azure AD (after 30-day soft delete period)
- Remove from external directories
- Delete archived mailboxes (per retention policy)
- Remove from compliance holds (if appropriate)
- Delete associated service accounts
- Clean up orphaned resources (OneDrive, Teams sites)

**Soft Delete vs Hard Delete**:
- **Soft delete**: User moved to "Deleted users" for 30 days, can be restored
- **Hard delete**: Permanent removal, cannot be restored

**Compliance Retention**:
- Audit logs may need to be kept 7 years (regulatory requirements)
- Email may need litigation hold (legal requirements)
- Access reviews must show historical access decisions

---

### Lifecycle Workflows (Microsoft Entra)

**What they are**:
Microsoft Entra Lifecycle Workflows automate identity lifecycle tasks using pre-built or custom templates. Part of Microsoft Entra ID Governance (requires Premium P2).

**How They Work**:
```
Trigger Condition → Workflow Executes → Tasks Run → Results Logged
```

**Trigger Types**:
1. **Attribute-based**: When user attribute changes (department, jobTitle, employeeType)
2. **Date-based**: X days before/after a date (start date, end date)
3. **Manual**: Admin or manager initiates workflow
4. **Event-based**: HR system event (hire, termination)

**Built-in Workflow Templates**:

| Template | Trigger | Example Tasks |
|----------|---------|---------------|
| **Onboard pre-hire employee** | 7 days before startDate | Create account, assign groups, prepare mailbox |
| **Onboard new hire employee** | On startDate (Day 1) | Generate TAP, assign licenses, send welcome email |
| **Post-Onboarding** | 7 days after startDate | Check MFA enrollment, verify app access, send survey |
| **Real-time employee change** | Department/manager attribute change | Update groups, reassign access packages |
| **Offboard employee** | Last working day | Disable account, revoke tokens, remove groups |
| **Post-Offboarding** | 30 days after last day | Delete account, remove licenses, clean up resources |

**Task Library** (Available automated tasks):

**Provisioning Tasks**:
- Generate Temporary Access Pass (TAP)
- Enable user account
- Add user to groups
- Assign licenses
- Create Teams team and add user

**Communication Tasks**:
- Send welcome email to new hire
- Send email to manager
- Send custom email with variables
- Request user input/feedback

**Deprovisioning Tasks**:
- Disable user account
- Remove user from all groups
- Remove all licenses
- Remove user from all Teams
- Delete user account
- Cancel all pending access requests

**Integration Tasks**:
- Run Logic App (integrate with custom systems)
- Call custom API (integrate with HR/third-party systems)

**Workflow Execution Example**:

**Scenario**: Automate contractor offboarding

**Configuration**:
```yaml
Workflow Name: Contractor Offboarding
Trigger: employeeType = "Contractor" AND lastWorkingDay = today
Execution Conditions: User in "Contractors" group
Tasks:
  1. Disable account (immediate)
  2. Revoke all sessions (immediate)
  3. Remove from all groups except "Former Contractors" (immediate)
  4. Send email to manager with data access instructions (immediate)
  5. Convert mailbox to shared (Day 1)
  6. Remove all licenses (Day 7)
  7. Delete account (Day 30)
Notifications: Email security team and manager
```

**Monitoring & Reporting**:
- Real-time workflow execution status
- Task success/failure logs
- User-level workflow history
- Audit trail of all automated actions
- Failed task alerts to admins

**Benefits**:
- [x] **Consistency**: Every employee gets same treatment, no missed steps
- [x] **Speed**: Onboarding in minutes instead of days
- [x] **Security**: Immediate offboarding reduces risk window
- [x] **Compliance**: Audit trail proves governance controls work
- [x] **Efficiency**: IT focuses on exceptions, not routine tasks
- [x] **Employee experience**: New hires productive on Day 1
- [x] **Cost reduction**: Automated license reclamation saves money

**Real-World Impact**:
- **Before automation**: IT spends 2 hours per onboarding, 1 hour per offboarding
- **After automation**: IT spends 10 minutes on exceptions only
- **For 100 employees/year**: Saves 290 hours of IT time annually

### Privileged Identity Management (PIM)

**What is PIM?**:
Azure AD Premium P2 feature that provides time-based and approval-based role activation to mitigate risks of excessive, unnecessary, or misused access permissions on critical resources.

**Core Principle**: **Zero Standing Privileges** - Nobody has permanent admin rights; all privileged access is temporary and must be activated when needed.

**Requires**: Azure AD Premium P2

**Key Concepts**:

#### Just-in-Time (JIT) Access
- Users request privileged role activation only when needed
- Access granted for limited time (1-24 hours, configurable)
- No permanent "always-on" admin rights
- Example: IT admin activates Global Admin role for 4 hours to perform maintenance

#### Just-Enough Access (JEA)
- Grant the minimum role necessary for the task
- Use scoped roles instead of broad permissions
- Time-limited to specific duration
- Example: Grant "User Administrator" instead of "Global Administrator" if user only needs to manage accounts

#### Approval Requirements
- Require approval from designated approvers before role activation
- Multi-stage approvals for highly sensitive roles
- Justification required (business reason for activation)
- Example: Global Admin activation requires approval from two security team members

**PIM for Azure AD Roles**:
Manage privileged Azure AD roles (Global Admin, Security Admin, User Admin, etc.)

**PIM for Azure Resources**:
Manage Azure RBAC roles at subscription, resource group, or resource level (Owner, Contributor, etc.)

**Role States**:
- **Eligible**: User can activate the role when needed (requires activation)
- **Active**: User currently has the role assigned (time-limited or permanent)

**Activation Flow**:
1. User navigates to PIM in Azure portal
2. Selects eligible role to activate
3. Provides justification and completes MFA
4. If required, approval request sent to approvers
5. Role activated for specified duration (e.g., 4 hours)
6. After duration expires, role automatically deactivated

**Key Features**:
- [x] **Time-bound access**: Roles expire automatically (1-24 hours)
- [x] **Approval workflows**: Require approvers for sensitive roles
- [x] **MFA on activation**: Force MFA every time role is activated
- [x] **Justification required**: Document business reason for activation
- [x] **Access reviews**: Periodic reviews of who has eligible assignments
- [x] **Audit history**: Complete log of all activations and actions
- [x] **Alerts**: Notifications for suspicious activation patterns
- [x] **Emergency access**: Break-glass accounts for critical situations

**Benefits**:
- Reduces attack surface (no standing admin privileges to steal)
- Provides accountability (know who did what and when)
- Meets compliance requirements (least privilege, audit trails)
- Prevents credential theft from being immediately useful

---

## 2.7 Azure AD Connect

### What is Azure AD Connect?

**Purpose**:
Microsoft tool that synchronizes on-premises Active Directory with Azure AD (Entra ID) to create hybrid identity environments. Enables users to have single identity for both on-prem and cloud resources.

**Core Function**: Bridge between on-premises AD and cloud Azure AD

**Synchronization Direction**:
- **Primary direction**: On-premises AD → Azure AD (one-way sync)
- **Some features**: Bi-directional (password writeback, device writeback)
- **Source of authority**: Typically on-premises AD (users managed on-prem, synced to cloud)

### Synchronization Methods

Three main authentication methods for hybrid environments:

#### Password Hash Synchronization (PHS)
**How it works**:
- Azure AD Connect syncs a hash of the user's password hash from on-prem AD to Azure AD
- Users authenticate directly against Azure AD using synchronized credentials
- Most simple and recommended method

**Pros**:
- Simplest to implement and maintain
- Least infrastructure required (no additional on-prem servers for auth)
- Supports leaked credential detection and Identity Protection
- Enables SSO to cloud apps
- Users can access cloud resources even if on-prem AD is down (resilient)

**Cons**:
- Password hash stored in the cloud (compliance concern for some organizations)
- Small sync delay (typically 2 minutes) for password changes

#### Pass-Through Authentication (PTA)
**How it works**:
- User enters credentials in Azure AD
- Azure AD sends authentication request to on-prem agent
- Agent validates credentials against on-prem AD
- Result sent back to Azure AD
- **Passwords never leave on-prem** (validated locally)

**Pros**:
- Passwords never stored in cloud (meets strict compliance requirements)
- Real-time password validation against on-prem AD policies
- Immediate password change enforcement
- Supports on-prem security features (password expiration, logon hours)

**Cons**:
- Requires one or more lightweight agents installed on-prem (additional infrastructure)
- On-prem dependency (if agents/AD offline, cloud auth fails)
- Limited Identity Protection features compared to PHS

#### Federation (AD FS)
**How it works**:
- Azure AD redirects authentication to on-prem AD FS servers
- AD FS validates credentials and issues SAML token
- Token presented to Azure AD for access
- Most complex option, requires AD FS farm infrastructure

**Pros**:
- Maximum control and customization of authentication
- Support for smartcards, third-party MFA, custom claims
- Can enforce complex on-prem policies

**Cons**:
- High complexity (AD FS servers, load balancers, Web Application Proxies)
- High maintenance and infrastructure cost
- Single point of failure (if AD FS down, cloud access fails)
- Does not support modern Azure AD features well

**Note**: Microsoft recommends migrating from AD FS to PHS for most scenarios.

### Comparison Table

| Method | Authentication Location | Complexity | Cloud Features | Best For |
|--------|------------------------|------------|----------------|----------|
| **PHS** | Cloud (Azure AD) | Low (easiest) | Full support (Conditional Access, Identity Protection) | Most organizations, recommended by Microsoft |
| **PTA** | On-premises (via agent) | Medium | Good support (some limitations) | Organizations with strict password policy compliance |
| **Federation** | On-premises (AD FS) | High (most complex) | Limited support | Legacy scenarios, smartcard requirements (migrate away when possible) |

**Microsoft Recommendation**: Password Hash Synchronization (PHS) for simplicity, resilience, and full cloud feature support.

---

## Practice Questions

### Section 1: Identity Fundamentals

#### Question 1: Authentication vs Authorization
A user successfully enters their username and password to sign into Azure AD. They then try to access a SharePoint site but receive an "Access Denied" message. Which process succeeded and which process failed?

**Answer**:
- **Authentication SUCCEEDED**: The user proved their identity with valid credentials
- **Authorization FAILED**: The user doesn't have permission to access the SharePoint site

**Explanation**: Authentication (proving who you are) happens first and was successful. Authorization (determining what you can do) happens second and failed because the user lacks the necessary permissions to access that specific SharePoint site. Authentication and authorization are separate processes - successful authentication doesn't guarantee access to all resources.

#### Question 2: Identity Provider Role
What is the primary role of an Identity Provider (IdP) in modern authentication, and what are two examples of Identity Providers?

**Answer**:
- **Primary Role**: An Identity Provider creates, maintains, and manages identity information while providing authentication services to applications. It acts as a trusted third party that validates user credentials and issues tokens that applications can trust.
- **Examples**: Azure AD (Entra ID), Active Directory Federation Services (AD FS), Okta, Google Identity

**Explanation**: Identity Providers centralize authentication so applications don't need to manage passwords or build their own authentication systems. Users authenticate once with the IdP, which issues tokens that can be used across multiple applications (Single Sign-On).

#### Question 3: Modern Authentication Tokens
What are the three types of tokens used in modern authentication, and what is the primary purpose of each?

**Answer**:
1. **Access Token**: Grants access to specific resources (APIs, applications) - short-lived (1 hour), cannot be revoked
2. **Refresh Token**: Obtains new access tokens without re-authentication - long-lived (90 days), can be revoked
3. **ID Token**: Proves user's identity (OpenID Connect) - contains user information like name and email

**Explanation**: Access tokens are used to access resources and are short-lived for security. Refresh tokens allow seamless experience by getting new access tokens when they expire. ID tokens tell applications who the user is for personalization. All three work together to provide secure, user-friendly authentication.

### Section 2: Directory Services and Active Directory

#### Question 4: Directory Services Purpose
What is a directory service, and what are three key benefits it provides to an organization?

**Answer**:
- **Definition**: A centralized database system that stores, organizes, and provides access to information about network resources and user identities (users, groups, devices, applications, permissions)
- **Three Key Benefits**:
  1. **Single source of truth**: One place to manage all identity information
  2. **Centralized authentication**: Users authenticate once against the directory
  3. **Reduced administration**: Change user info once, updates everywhere

**Explanation**: Directory services act as the "phone book" for an organization's IT infrastructure. Instead of managing users separately in each application, directory services provide centralized management that reduces complexity, improves security, and enables features like Single Sign-On.

#### Question 5: Active Directory Concepts
Match the Active Directory component with its description:

A. Domain Controller
B. Organizational Unit (OU)
C. Group Policy Object (GPO)
D. Forest

1. Container for organizing objects and delegating administration
2. Windows Server that stores the directory database and handles authentication
3. Configuration settings applied to users and computers
4. Highest level security boundary containing one or more domains

**Answer**:
- A-2 (Domain Controller = server handling authentication)
- B-1 (OU = container for organizing objects)
- C-3 (GPO = configuration settings)
- D-4 (Forest = highest level security boundary)

**Explanation**: These are fundamental AD concepts. Domain Controllers are the servers running AD. OUs organize objects within a domain. GPOs centrally manage configurations. Forests represent the ultimate security boundary containing all domains.

#### Question 6: Azure AD vs Active Directory
Your company is moving from on-premises to the cloud. Which THREE statements correctly describe differences between Azure AD and on-premises Active Directory?

A. Azure AD uses OAuth 2.0 and SAML; Active Directory uses LDAP and Kerberos
B. Azure AD supports Group Policy Objects; Active Directory does not
C. Azure AD is cloud-based and managed by Microsoft; Active Directory requires on-premises servers
D. Azure AD has a hierarchical structure with OUs; Active Directory has a flat structure
E. Azure AD is designed for cloud apps and modern authentication; Active Directory is designed for on-premises resources

**Answer**: A, C, and E are correct

**Explanation**:
- **A is CORRECT**: Different protocols - Azure AD uses modern web protocols, AD uses traditional protocols
- **B is INCORRECT**: Active Directory supports GPOs, Azure AD does not (use Intune instead)
- **C is CORRECT**: Azure AD is a cloud service, AD requires self-managed domain controllers
- **D is INCORRECT**: Reversed - AD has hierarchical structure with OUs, Azure AD has flat structure
- **E is CORRECT**: Different use cases - Azure AD for cloud/modern, AD for on-premises/traditional

#### Question 7: Active Directory Authentication
When a user logs into a domain-joined Windows PC, which protocol does Active Directory use for authentication, and what does it issue to the user?

**Answer**:
- **Protocol**: Kerberos (ticket-based authentication)
- **Issues**: Kerberos ticket

**Explanation**: Kerberos is the primary authentication protocol for Active Directory. After validating credentials against the domain controller, AD issues a Kerberos ticket that the user can present to access network resources without re-entering their password. This enables seamless Single Sign-On within the domain.

### Section 3: Federation and Federated Services

#### Question 8: Federation Fundamentals
What is federation in identity management, and what is the primary benefit it provides for cross-organization collaboration?

**Answer**:
- **Definition**: Federation is a system of trust that allows users to use their home organization's credentials to access resources in partner organizations. Authentication performed by one identity provider is trusted by other systems.
- **Primary Benefit**: Users can access external resources using their familiar credentials without creating separate accounts. When they leave their organization, access is automatically revoked everywhere.

**Explanation**: Think of federation like a passport - your home country authenticates your identity, and other countries trust that authentication. This eliminates password proliferation, centralizes management, and improves security by reducing external accounts.

#### Question 9: Federation Roles
In a federation scenario, what is the difference between an Identity Provider (IdP) and a Service Provider (SP)?

**Answer**:
- **Identity Provider (IdP)**: Authenticates users and issues security tokens containing claims about the user. Stores and manages user credentials.
- **Service Provider (SP) / Relying Party**: Accepts and trusts authentication tokens from the Identity Provider. Provides access to resources based on the token.

**Example**: When Contoso employees access Fabrikam's application:
- Contoso's Azure AD = Identity Provider (authenticates Contoso employees)
- Fabrikam's application = Service Provider (accepts Contoso's authentication tokens)

**Explanation**: The IdP is the "authenticator," the SP is the "consumer" of authentication. This separation allows organizations to manage their own users while providing access to external applications.

#### Question 10: Federation Protocols
Match the federation protocol with its primary use case:

A. SAML 2.0
B. WS-Federation
C. OAuth 2.0 / OpenID Connect

1. Modern cloud apps, mobile apps, APIs, social login
2. Enterprise SSO to SaaS applications like Salesforce
3. Legacy Microsoft applications and on-premises SharePoint

**Answer**:
- A-2 (SAML 2.0 = Enterprise SaaS SSO)
- B-3 (WS-Federation = Legacy Microsoft apps)
- C-1 (OAuth/OIDC = Modern cloud/mobile apps)

**Explanation**: SAML 2.0 is the most common enterprise federation protocol (XML-based). WS-Federation is Microsoft's legacy protocol still used for older applications. OAuth 2.0/OpenID Connect are modern, JSON-based protocols for web and mobile applications.

#### Question 11: AD FS vs Azure AD
Your organization currently uses Active Directory Federation Services (AD FS) for federation. Why does Microsoft recommend migrating from AD FS to Azure AD with Password Hash Synchronization?

**Answer**: Three main reasons:
1. **Reduced Complexity**: AD FS requires multiple servers, load balancers, Web Application Proxies, and certificates - Azure AD eliminates this infrastructure
2. **Better Resilience**: If AD FS is down, cloud access fails - Azure AD authentication works even if on-premises is offline
3. **Modern Features**: AD FS has limited support for modern Azure AD features like Conditional Access, Identity Protection, and passwordless authentication

**Explanation**: While AD FS was necessary in the past, modern Azure AD capabilities provide the same SSO experience with significantly less operational burden. Microsoft recommends PHS for most organizations unless specific requirements (like smartcard authentication) mandate on-premises authentication.

#### Question 12: Federation Security
In a federated environment, if an Identity Provider is compromised, what is the security impact?

**Answer**: Catastrophic - a compromised Identity Provider means compromised access to ALL federated applications that trust it. An attacker could issue valid tokens for any user and access any federated service.

**Explanation**: This is why protecting your Identity Provider is critical. Use strongest security measures: require MFA for all users (especially admins), implement Conditional Access policies, use PIM for admin roles, enable Identity Protection, and monitor for suspicious activity. The Identity Provider is the "keys to the kingdom" in a federated environment.

#### Question 13: Federation Scenarios
An e-commerce website wants to allow customers to sign in using their Google, Facebook, or Microsoft accounts instead of creating yet another username/password. What type of federation is this, and which Azure AD service supports it?

**Answer**:
- **Type**: Social Identity Federation (B2C scenario)
- **Azure AD Service**: Azure AD B2C (Business-to-Consumer)

**Explanation**: Azure AD B2C is designed for customer-facing applications that need to scale to millions of consumers. It federates with social identity providers (Google, Facebook, Microsoft, Apple, etc.) using OAuth 2.0/OpenID Connect. This reduces password fatigue for customers and eliminates password storage liability for the business.

### Section 4: Authentication Methods

#### Question 14: Passwordless Authentication
Your organization wants to eliminate passwords for user sign-ins while maintaining strong security. Which three Microsoft passwordless authentication methods can you implement?

**Answer**: Windows Hello for Business, FIDO2 Security Keys, Microsoft Authenticator App

**Explanation**: These are the three Microsoft-supported passwordless authentication methods. Windows Hello for Business uses biometrics or PIN tied to a device's TPM. FIDO2 security keys are physical hardware keys using public key cryptography. Microsoft Authenticator App provides phone-based passwordless sign-in with biometric or PIN approval. All three methods are more secure than passwords because they use cryptographic keys instead of shared secrets and are resistant to phishing attacks.

#### Question 15: MFA Effectiveness
What percentage of account compromise attacks are blocked by Multi-Factor Authentication (MFA) according to Microsoft?

**Answer**: 99.9% of account compromise attacks are blocked by MFA

**Explanation**: This statistic demonstrates why MFA is one of the most important security controls. Even if an attacker obtains a user's password through phishing or data breach, they cannot access the account without the second factor (phone, authenticator app, security key). This is why MFA should be required for all users, especially administrators.

#### Question 16: Password Protection
What is the difference between the Global Banned Password List and Custom Banned Password Lists in Azure AD Password Protection?

**Answer**:
- **Global Banned Password List**: Microsoft-maintained list of commonly used weak passwords (e.g., "Password1", "Summer2024") - automatically applied to all Azure AD tenants
- **Custom Banned Password List**: Organization-specific list of up to 1000 terms (company name, products, industry terms) that administrators add

**Explanation**: Both lists work together to prevent users from choosing weak or easily guessable passwords. The system is smart enough to detect variations (e.g., "P@ssw0rd" blocked if "password" is banned). This reduces successful password attacks. Requires Azure AD Premium P1/P2 for on-premises integration.

### Section 5: Conditional Access

#### Question 17: Conditional Access Requirements
Which Azure AD edition is required to use Conditional Access policies, and what is the primary purpose of Conditional Access?

**Answer**:
- **Required Edition**: Azure AD Premium P1 (or P2 for risk-based policies)
- **Primary Purpose**: Policy-based engine that evaluates signals (user, location, device, app, risk) and enforces controls (grant, block, require MFA) before allowing access to resources

**Explanation**: Conditional Access is the Zero Trust "policy enforcement point" that implements IF-THEN logic. For example: IF user is admin AND location is untrusted, THEN require MFA and compliant device. This enables organizations to dynamically adjust security requirements based on context rather than applying blanket policies.

#### Question 18: Conditional Access Signals and Controls
Create a Conditional Access policy for the following requirement: "All Global Administrators must use MFA and a compliant device when accessing the Azure Portal from outside the corporate network."

**Answer**:
**IF (Signals)**:
- User/Group: Members of "Global Administrators" role
- Application: Azure Portal
- Location: NOT corporate network (exclude trusted named locations)

**THEN (Controls)**:
- Require multi-factor authentication (AND)
- Require device to be marked as compliant

**Explanation**: This policy uses multiple signals (who, what, where) to determine context, then enforces multiple controls together. The user must satisfy ALL controls (MFA AND compliant device) to gain access. This provides strong security for privileged access from untrusted locations.

#### Question 19: Conditional Access Best Practice
Why should organizations ALWAYS exclude emergency access ("break glass") accounts from ALL Conditional Access policies?

**Answer**: To prevent complete lockout from Azure AD if Conditional Access policies malfunction or are misconfigured.

**Explanation**: If all admin accounts are subject to Conditional Access policies requiring specific conditions (like compliant devices or specific locations), a misconfiguration could lock everyone out. Emergency access accounts with excluded from policies ensure administrators can always regain access to fix issues. These accounts should be carefully secured (long random passwords stored in safe) and monitored for any use.

#### Question 20: Report-Only Mode
What is the purpose of Report-Only mode in Conditional Access policies?

**Answer**: Report-Only mode allows administrators to test Conditional Access policies without actually enforcing them. The policy evaluates users and logs what would have happened, but doesn't block or require anything from users.

**Explanation**: This is critical for testing policies before enforcement. You can see how many users would be affected, identify potential issues, and validate policy logic without disrupting user access. After confirming the policy works as expected in report-only mode, you can safely switch it to enforcement mode.

### Section 6: Identity Protection

#### Question 21: Sign-in Risk vs User Risk
What is the difference between Sign-in Risk and User Risk in Azure AD Identity Protection?

**Answer**:
- **Sign-in Risk**: Risk detected during a specific sign-in attempt (e.g., impossible travel, anonymous IP, unfamiliar location) - indicates the sign-in may not be legitimate
- **User Risk**: Risk that the user's identity itself is compromised (e.g., leaked credentials found on dark web) - indicates the account may be breached

**Explanation**: Sign-in risk is event-based and can be remediated by requiring MFA for that specific sign-in. User risk is identity-based and typically requires a password change to remediate. Identity Protection uses AI and Microsoft threat intelligence to detect both types automatically. Requires Azure AD Premium P2.

#### Question 22: Risk-Based Policies
Your organization wants to automatically require MFA when Azure AD detects a suspicious sign-in attempt. How would you configure this using Identity Protection?

**Answer**:
Create a Sign-in Risk Conditional Access Policy:
- **IF**: Sign-in risk is Medium or High
- **THEN**: Require multi-factor authentication
- **Result**: User must complete MFA to continue; if successful, risk is auto-remediated

**Explanation**: This policy responds dynamically to risk. Normal sign-ins flow without interruption, but suspicious attempts automatically trigger MFA. If the user successfully completes MFA, it indicates the legitimate user has control of the account, and the risk is automatically closed. This provides security without burdening users during normal operations. Requires Azure AD Premium P2.

#### Question 23: Identity Protection Risk Detections
Which of the following are examples of User Risk detections (not Sign-in Risk)? Select all that apply.

A. Atypical travel (impossible travel between locations)
B. Leaked credentials (found on dark web)
C. Anonymous IP address
D. Azure AD threat intelligence detecting unusual user behavior
E. Password spray attack

**Answer**: B and D are User Risk detections

**Explanation**:
- **A (Atypical travel)**: Sign-in Risk - suspicious location for THIS sign-in
- **B (Leaked credentials)**: User Risk - indicates the account itself is compromised
- **C (Anonymous IP)**: Sign-in Risk - this specific sign-in is from suspicious source
- **D (Unusual behavior)**: User Risk - the user's overall behavior pattern is anomalous
- **E (Password spray)**: Sign-in Risk - attack pattern detected during sign-in attempts

### Section 7: Identity Governance

#### Question 24: PIM Zero Standing Privileges
A company wants to implement Zero Standing Privileges for all Global Administrator roles. How does Privileged Identity Management (PIM) help achieve this goal?

**Answer**: PIM allows organizations to assign users as "eligible" for the Global Admin role rather than permanently "active". Users must activate the role when needed (Just-in-Time access), which requires justification, MFA, and optionally approval. The role is time-limited (e.g., 4 hours) and automatically deactivates after the time expires.

**Explanation**: This eliminates permanent admin rights (zero standing privileges). Even if an attacker compromises an eligible admin's credentials, they cannot immediately use admin privileges - they would need to activate the role, complete MFA, and potentially get approval. All activations are logged for audit purposes. Requires Azure AD Premium P2.

#### Question 25: Access Reviews
What is the purpose of Access Reviews in Azure AD, and what are two types of resources that can be reviewed?

**Answer**:
- **Purpose**: Periodic certification process where designated reviewers verify that users still need their assigned access, preventing "access creep" and ensuring compliance
- **Two Types**:
  1. Group membership reviews (security and Microsoft 365 groups)
  2. Application access reviews (who has access to specific apps)
  3. Azure AD role reviews (privileged role assignments)
  4. Azure resource role reviews (Azure RBAC assignments)

**Explanation**: Access Reviews ensure least privilege by systematically reviewing and removing unnecessary access. Reviewers (typically managers or resource owners) approve or deny continued access, and results can be automatically applied. This meets compliance requirements (SOX, HIPAA, GDPR) and reduces security risks from abandoned or excessive permissions.

#### Question 26: Entitlement Management
A company has contractors joining for a 90-day project who need access to specific resources (a Teams channel, SharePoint site, and application). How can Entitlement Management simplify this scenario?

**Answer**:
Create an Access Package containing:
- **Resources**: Teams membership, SharePoint site access, application assignment
- **Policy**: 90-day expiration, requires manager approval
- **Result**: Contractor requests access via self-service portal, manager approves once, contractor gets all three resources, access automatically expires after 90 days

**Explanation**: Entitlement Management bundles related resources into access packages that users can request. Instead of IT manually granting three separate permissions and remembering to revoke them in 90 days, everything is automated. This reduces administrative overhead, ensures consistent access, and prevents forgotten permissions.

#### Question 27: Lifecycle Workflows
What are Lifecycle Workflows in Azure AD, and what is one common workflow example?

**Answer**:
- **Definition**: Automated workflows that execute tasks at specific points in an employee's lifecycle (joiner, mover, leaver)
- **Common Example**: Offboarding workflow - When employee leaves, automatically disable account, revoke all tokens, remove licenses, remove from groups, transfer data, and schedule account deletion after 30 days

**Explanation**: Lifecycle Workflows ensure consistent processes for identity lifecycle management. Instead of IT manually performing multiple steps (and potentially forgetting some), workflows automate the entire process based on employee attributes (hire date, termination date, department changes). This improves security (terminated users immediately lose access) and reduces administrative burden.

### Section 8: Azure AD Connect and Hybrid Identity

#### Question 28: Azure AD Connect Sync Methods
What are the three main authentication methods for hybrid identity environments, and which one does Microsoft recommend for most organizations?

**Answer**:
1. **Password Hash Synchronization (PHS)**: Syncs password hash to Azure AD - RECOMMENDED
2. **Pass-Through Authentication (PTA)**: Validates passwords against on-prem AD via agent
3. **Federation (AD FS)**: Redirects authentication to on-premises AD FS servers

**Microsoft Recommendation**: Password Hash Synchronization (PHS)

**Explanation**: PHS is simplest (least infrastructure), most resilient (works even if on-prem is down), and supports all modern Azure AD features (Identity Protection, leaked credential detection). PTA is suitable for strict compliance requiring passwords never leave premises. Federation (AD FS) is most complex and should be migrated away from in most cases.

#### Question 29: Password Hash Synchronization
How does Password Hash Synchronization (PHS) work, and what are two key benefits?

**Answer**:
- **How it works**: Azure AD Connect syncs a hash of the user's password hash from on-premises AD to Azure AD. Users authenticate directly against Azure AD using synchronized credentials.
- **Two Key Benefits**:
  1. **Resilience**: Users can access cloud resources even if on-premises AD is offline
  2. **Full Feature Support**: Enables Identity Protection features like leaked credential detection

**Explanation**: PHS is the simplest hybrid authentication method. Despite the name, the actual password never syncs - only a hash of the hash. This provides cloud authentication benefits while maintaining on-premises as the source of authority for identity management. Sync typically occurs every 2 minutes for password changes.

#### Question 30: Hybrid Identity Scenarios
Your company has 5,000 users in on-premises Active Directory and is moving to Microsoft 365. They want Single Sign-On, modern security features (MFA, Conditional Access, Identity Protection), and the ability to continue working if on-premises infrastructure fails. What should you implement?

**Answer**:
1. Deploy Azure AD Connect with Password Hash Synchronization (PHS)
2. Enable Azure AD Premium P2 for users
3. Configure Seamless SSO for domain-joined devices
4. Implement modern authentication: MFA, Conditional Access, Identity Protection
5. Roll out passwordless: Windows Hello for Business, Authenticator App

**Explanation**: PHS provides the foundation for hybrid identity while meeting all requirements: SSO (seamless for domain-joined PCs), resilience (works if on-prem is down), and full support for modern security features. This is Microsoft's recommended approach for most hybrid organizations. Users have single identity across on-premises and cloud with maximum security capabilities.

---

## Key Comparison Charts

### Authentication: Something to Know
```
Passwords (weak) → MFA (stronger) → Passwordless (strongest)
```

### Conditional Access Flow
```
User Request → Signals Evaluated → Policy Applied → Grant/Block/Require
```

### PIM Role States
```
No Access → Eligible (can activate) → Active (time-limited)
```

---

## Key Terms Glossary

| Term | Definition |
|------|------------|
| **SSO (Single Sign-On)** | Authenticate once with Azure AD, access multiple applications without re-entering credentials |
| **MFA (Multi-Factor Authentication)** | Security method requiring two or more verification factors (something you know/have/are) - blocks 99.9% of account compromise |
| **Passwordless** | Authentication without passwords using cryptographic keys (Windows Hello, FIDO2, Authenticator App) - strongest security method |
| **Conditional Access** | Policy-based engine that evaluates signals (user, location, device, app, risk) and enforces controls (grant/block/require) - requires Azure AD Premium P1 |
| **Identity Protection** | AI-powered risk detection for sign-in and user risks with automated remediation via Conditional Access - requires Azure AD Premium P2 |
| **PIM (Privileged Identity Management)** | Just-in-Time and Just-Enough-Access for privileged roles with time-limited activation, approval workflows, and MFA - requires Azure AD Premium P2 |
| **Entitlement Management** | Self-service access request workflows with access packages, approvals, reviews, and auto-expiration |
| **Access Reviews** | Periodic certification process where reviewers verify users still need assigned access - prevents access creep |
| **Hybrid Identity** | User accounts synchronized between on-premises Active Directory and Azure AD via Azure AD Connect |
| **Azure AD Connect** | Microsoft tool that synchronizes on-premises AD with Azure AD for hybrid identity environments |
| **B2B (Business-to-Business)** | External partner collaboration - guests use their own credentials to access your organization's resources |
| **B2C (Business-to-Consumer)** | Customer-facing applications for millions of consumers using social/local accounts with customizable branding |
| **OAuth 2.0** | Authorization framework for delegated access used in modern authentication |
| **OpenID Connect** | Identity layer on top of OAuth 2.0 for authentication |
| **Access Token** | Short-lived token (1 hour) proving authorization to access specific resources |
| **Refresh Token** | Long-lived token (90 days) used to obtain new access tokens without re-authentication |
| **RBAC (Role-Based Access Control)** | Authorization model using roles (collections of permissions) assigned to users |
| **Zero Trust** | Security model: "Verify explicitly, assume breach, least privilege access" - identity is the security perimeter |

---

## Summary & Review

### What I Learned
1. Identity is the new security perimeter - moved from network-based to identity-based security in modern cloud environments
2. Authentication (who you are) happens FIRST, then Authorization (what you can do) determines access
3. Modern authentication uses tokens (access, refresh, ID) instead of passwords, enabling SSO and advanced security features
4. Azure AD Premium P1 enables Conditional Access, P2 adds Identity Protection and PIM
5. Passwordless authentication (Windows Hello, FIDO2, Authenticator) is the strongest security method

### Most Important Concepts for Exam
- **Authentication vs Authorization**: Know the difference and when each occurs
- **Azure AD Premium editions**: P1 = Conditional Access, P2 = Identity Protection + PIM
- **Conditional Access**: IF-THEN logic with signals and controls - requires P1
- **MFA blocks 99.9%** of account compromise attacks
- **PIM**: Zero standing privileges, Just-in-Time access, requires P2
- **Hybrid identity sync methods**: PHS (recommended), PTA, Federation (AD FS)
- **Identity Protection**: Sign-in risk vs User risk, requires P2
- **Zero Trust principles**: Verify explicitly, assume breach, least privilege

### Areas to Review
- [ ] Difference between Azure AD roles and Azure RBAC roles
- [ ] Which features require which Azure AD Premium edition (P1 vs P2)
- [ ] Modern authentication protocols (OAuth 2.0, OpenID Connect, SAML)
- [ ] PIM role states (Eligible vs Active) and activation flow
- [ ] Azure AD Connect sync methods and recommendations

### Practice Scenarios

**Scenario 1: Securing Admin Access**
*Problem*: Your organization has 10 Global Administrators with permanent admin rights. You need to implement Zero Trust principles.

*Solution*:
1. Implement PIM (requires Azure AD Premium P2)
2. Convert permanent Global Admin assignments to "eligible" roles
3. Configure activation requirements: MFA, justification, approval from 2 security team members
4. Set time limit: 4-hour activations
5. Create Conditional Access policy: IF admin role activated AND location untrusted, THEN require compliant device + MFA
6. Schedule quarterly access reviews for all eligible admin role assignments

**Scenario 2: Hybrid Identity with Strong Security**
*Problem*: Company has on-premises Active Directory with 5,000 users. Moving to Microsoft 365 but must keep on-prem AD. Want passwordless authentication and risk-based policies.

*Solution*:
1. Deploy Azure AD Connect with Password Hash Synchronization (PHS) - simplest, most resilient
2. Enable Azure AD Premium P2 for all users
3. Roll out passwordless: Windows Hello for Business on corporate PCs, Microsoft Authenticator for mobile
4. Configure Conditional Access policies: Block legacy auth, require MFA for cloud apps
5. Enable Identity Protection: IF sign-in risk medium/high THEN require MFA, IF user risk high THEN require password change
6. Result: Users have single identity, passwordless sign-in, automatic risk response

**Scenario 3: External Partner Collaboration**
*Problem*: Need to give 50 external partners temporary access to specific SharePoint sites and applications. Access should auto-expire after 6 months.

*Solution*:
1. Use Azure AD B2B for partner collaboration
2. Create Entitlement Management access package: "Partner Project Access"
3. Include resources: SharePoint site, Teams membership, required applications
4. Set policy: Require sponsor approval, 6-month expiration, automatic access removal
5. Partners request access via self-service portal using their existing credentials
6. Schedule access reviews at 3 months and 6 months before expiration
7. Result: Automated, auditable, time-limited partner access without creating internal accounts

