# Cloud-Ransomware-Attack-Chain-Case-Studies-Incident-Response-Playbook

> Tabletop-exercise prep guide for Azure / Entra ID and AWS environments.
> Focus: cloud-native ransomware (encrypt, exfiltrate + extort, destroy). Covers how attacks unfold, how to confirm them, how to contain them, and what to ask during a tabletop.

---

## Table of Contents

1. [Key Concept: Cloud Ransomware Is an Identity Attack](#1-key-concept-cloud-ransomware-is-an-identity-attack)
2. [The Cloud Ransomware Attack Chain](#2-the-cloud-ransomware-attack-chain)
3. [Real-World Case Studies (2025–2026)](#3-real-world-case-studies-20252026)
4. [Indicators of Compromise by Stage](#4-indicators-of-compromise-by-stage)
5. [Logs & Services to Check](#5-logs--services-to-check)
6. [Confirming "High Likelihood of Ransomware"](#6-confirming-high-likelihood-of-ransomware)
7. [Incident Responder Containment Playbook](#7-incident-responder-containment-playbook)
8. [Tabletop Exercise Guide](#8-tabletop-exercise-guide)
9. [Key Questions to Ask (Question Bank)](#9-key-questions-to-ask-question-bank)
10. [Hunting Queries](#10-hunting-queries)
11. [Preventive Controls](#11-preventive-controls)
12. [References](#12-references)

---

## 1. Key Concept: Cloud Ransomware Is an Identity Attack

Traditional ransomware drops an encryptor on endpoints. **Cloud ransomware usually needs no malware.** The attacker:

1. Gets a credential (user, service principal, access key, OAuth token).
2. Escalates to a highly privileged role.
3. Uses the **cloud provider's own APIs** to steal, encrypt, or delete data.

| Flavor | What happens | Recovery outlook |
|---|---|---|
| **Encrypt** | Data is re-encrypted with an attacker-held key (S3 SSE-C, attacker-controlled Key Vault key / encryption scope) | Only possible from versions or immutable backups |
| **Exfil + Extort** | Data is stolen and the attacker threatens to leak it. Nothing is encrypted. | Data is available, but you have a breach-notification problem |
| **Destroy** | Data is exfiltrated, then backups and resources are deleted, then a ransom is demanded | Depends entirely on immutable or off-tenant backups |

**Analogy:** Endpoint ransomware is a burglar who breaks in and changes the locks on every room. Cloud ransomware is a burglar who steals the building manager's master keycard, walks in through the front door, and has the building's own maintenance crew demolish the rooms. Nothing looks "broken in." Every action is a legitimate API call by an authorized identity.

---

## 2. The Cloud Ransomware Attack Chain

```
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │ 1. Initial   │──▶│ 2. Credential│──▶│ 3. Discovery │──▶│ 4. Privilege │──▶│ 5. Persist-  │
 │    Access    │   │    Access    │   │              │   │  Escalation  │   │    ence      │
 └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
                                                                                     │
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐
 │ 10. Extortion│◀──│ 9. Impact    │◀──│ 8. Inhibit   │◀──│ 7. Exfil-    │◀──│ 6. Defense   │
 │              │   │ (encrypt /   │   │    Recovery  │   │   tration    │   │    Evasion   │
 │              │   │   delete)    │   │              │   │              │   │              │
 └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

| # | Stage | What the attacker does | Azure / Entra example | AWS example | MITRE ATT&CK |
|---|---|---|---|---|---|
| 1 | **Initial Access** | Gets in | Phished or vished admin, help desk MFA reset, compromised on-prem AD, exposed app RCE | Leaked access key in a Git repo, exposed app RCE | T1078.004, T1566.004, T1190, T1195.002 |
| 2 | **Credential Access** | Harvests more credentials | DCSync / NTDS.dit, Entra Connect sync account, SP secrets, CLI token cache | `~/.aws/credentials`, IMDS, env vars, secrets in CRM records | T1003.006, T1552.001, T1552.005, T1528 |
| 3 | **Discovery** | Maps identities, roles, data | AzureHound / ROADtools, enumerates subscriptions, storage, Recovery Services vaults | `ListBuckets`, `GetAccountAuthorizationDetails`, Pacu | T1087.004, T1580, T1526 |
| 4 | **Privilege Escalation** | Becomes "god mode" | `elevateAccess` → User Access Administrator at root → Owner on all subscriptions | `AttachUserPolicy` AdministratorAccess, `UpdateAssumeRolePolicy` | T1098.003 |
| 5 | **Persistence** | Keeps access after password resets | Rogue federated domain, new SP credentials, new GA, CA policy exclusions | New IAM user or access key, backdoored role trust | T1098.001, T1484.002, T1136.003 |
| 6 | **Defense Evasion** | Blinds you | Deletes diagnostic settings, disables Defender plans | `StopLogging`, `DeleteDetector` (GuardDuty) | T1562.008 |
| 7 | **Exfiltration** | Steals data for leverage | `listKeys`, opens storage network ACLs, AzCopy bulk download | Bulk `GetObject`, cross-account replication, snapshot sharing | T1530, T1537 |
| 8 | **Inhibit Recovery** | Removes your way back | Deletes snapshots, restore points, and vaults; disables soft delete; deletes locks | `DeleteRecoveryPoint`, suspends versioning, short lifecycle expiry | T1490 |
| 9 | **Impact** | Encrypts or destroys | Re-encrypts with an attacker Key Vault key or encryption scope, then deletes the key; mass resource delete | SSE-C overwrite; KMS `ScheduleKeyDeletion`; mass delete | T1486, T1485 |
| 10 | **Extortion** | Demands payment | Ransom via Teams from a compromised account; leak-site threats | Ransom notes dropped into buckets | T1657 |

> **Tabletop insight:** Stages 6 and 8 are your last chance to stop impact. Recovery inhibition almost always precedes encryption or destruction, so alert on it as a P1.

---

## 3. Real-World Case Studies (2025–2026)

### 3.1 Codefinger: AWS S3 SSE-C Ransomware (January 2025)

| Attribute | Detail |
|---|---|
| **Discovered by** | Halcyon (at least two confirmed victims) |
| **Platform** | AWS S3 |
| **Initial access** | Publicly leaked or stolen long-lived AWS access keys |
| **Required permissions** | Only `s3:GetObject` + `s3:PutObject` |
| **Malware used** | None. 100% native AWS API calls. |
| **Exfiltration** | None observed. Pure encryption-for-ransom. |

#### Key clarifications

| Common assumption | What actually happened |
|---|---|
| "They compromised a user's account" | No console login, phishing, or MFA bypass. They used a **leaked or stolen long-term access key** (`AKIA...`) belonging to an **IAM user**, often a service-account-style user created for an app, script, or backup job. |
| "They encrypted the bucket with a customer managed key (KMS CMK)" | They used **SSE-C (customer-*provided* key)**. The attacker generated the AES-256 key on their own machine and sent it with each request. It never lived in the victim's KMS. |
| "Rotate the bucket's key to fix it" | **There is no bucket key to rotate.** The key exists only on the attacker's machine. Rotation affects future writes only and never decrypts existing data. Recovery comes from **versions or backups**. |
| "They authenticated to the S3 bucket" | They authenticated to **AWS IAM** as the IAM user. The bucket allowed the request because that user was **authorized** to read and write it. |

#### AWS credential types

| Credential | Prefix | Belongs to | Expires? |
|---|---|---|---|
| **Long-term access key** (used by Codefinger) | `AKIA...` | An **IAM user** (or root account) | **Never**, until rotated or deleted |
| **Temporary credentials (STS)** | `ASIA...` | An IAM **role session** (EC2, Lambda, SSO, AssumeRole) | Yes: minutes to hours |

**Why a leaked long-term key is so dangerous:**

| Property | Impact |
|---|---|
| Long-lived | A key leaked years ago can still work |
| No MFA | Programmatic API calls don't prompt for MFA (unless a policy explicitly requires it) |
| Works from anywhere | No device or network check by default |
| Looks legitimate | CloudTrail shows a real IAM user making normal S3 calls. Only source IP, volume, and the SSE-C header look off. |

**Common leak sources:** public or private Git repos (scraped by bots within minutes), CI/CD logs and plaintext pipeline variables, infostealers on developer laptops (`~/.aws/credentials`), keys hardcoded in apps, container images, or config files, and keys pasted into tickets, wikis, or CRM records.

#### S3 encryption types: why SSE-C is the weapon

| Encryption type | Who holds the key | Can the victim recover? |
|---|---|---|
| **SSE-S3** | AWS fully manages it | Yes, transparently |
| **SSE-KMS (CMK)** | Stored in the **victim's** KMS; victim controls the key policy | Yes, the victim owns the key |
| **SSE-C** | **Whoever sent the request.** AWS uses it once and discards it, keeping only an HMAC to validate future requests | **Only with that exact key**, which the attacker holds |

> **Analogy:** SSE-KMS is a safe-deposit box where the bank keeps a master key. SSE-C is a box where you bring your own padlock and the bank never sees the key. Codefinger walked in with a valid access badge, put *its own* padlock on every box, and left.

#### Full attack chain

```
 Leaked AKIA key ──▶ Sign requests (SigV4) ──▶ AWS IAM: "You are IAM user 'app-backup'"
                                                        │
                                                        ▼
                                Policy check: may s3:GetObject / s3:PutObject on bucket? ✅
                                                        │
                                                        ▼
               List buckets ──▶ Overwrite every object with SSE-C (attacker key) ──▶
               Set 7-day lifecycle deletion ──▶ Drop ransom notes ──▶ Demand Bitcoin
```

| # | Stage | What Codefinger did | CloudTrail evidence | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | **Obtain credentials** | Acquired a publicly leaked or stolen long-term access key (Access Key ID + Secret Access Key) | Not visible in AWS; found in repo scans or threat intel | T1552.001 Credentials in Files |
| 2 | **Authenticate** | Signed API requests (SigV4) with the key. AWS IAM treated the attacker as **that IAM user**. | `userIdentity.type = IAMUser`, `userIdentity.accessKeyId = AKIA...`, unfamiliar `sourceIPAddress` / user agent | T1078.004 Valid Accounts: Cloud Accounts |
| 3 | **Authorize** | IAM evaluated the user's identity policies, the bucket policy, and any SCP/RCP. The user held `s3:GetObject` + `s3:PutObject`, so requests were allowed. | Successful S3 calls (no `AccessDenied`) | — |
| 4 | **Discovery** | Enumerated the buckets and objects the key could reach | `ListBuckets`, `ListObjects` / `ListObjectsV2` bursts | T1580 Cloud Infrastructure Discovery, T1619 Cloud Storage Object Discovery |
| 5 | **Encrypt (impact)** | Overwrote each object via `CopyObject`/`PutObject` with the SSE-C header and an attacker-generated AES-256 key. AWS encrypted and discarded the key. | `PutObject` / `CopyObject` with `additionalEventData.SSEApplied = SSE_C` (**requires S3 data events**) | T1486 Data Encrypted for Impact |
| 6 | **Inhibit recovery** | Applied an **S3 Lifecycle rule to delete objects in 7 days**, creating a deadline and potentially expiring prior versions | `PutBucketLifecycleConfiguration` | T1490 Inhibit System Recovery, T1485 Data Destruction |
| 7 | **Extortion** | Dropped ransom notes in affected prefixes demanding Bitcoin in exchange for the key | `PutObject` of identical small note files across prefixes | T1657 Financial Theft |

**Notable:** No data exfiltration was observed. The leverage was purely the unrecoverable encryption plus the deletion deadline. AWS CIRT reported detecting large numbers of SSE-C `CopyObject` overwrites and added automatic mitigations, but customers still own prevention.

#### Azure mapping

**Concept mapping**

| AWS | Azure equivalent |
|---|---|
| IAM user | Service principal (app registration) or user |
| Long-term access key (`AKIA`) | App registration **client secret / certificate**, or **storage account key** / account SAS |
| Temporary STS credentials (`ASIA`) | **Managed identity** or **workload identity federation** tokens |
| IAM identity policy | Azure **RBAC role assignment** (e.g., Storage Blob Data Contributor) |
| Bucket policy | Storage account network rules + RBAC scope (no direct resource-policy equivalent) |
| SCP / RCP | **Azure Policy** (deny effects) / management group guardrails |
| S3 bucket / object | Storage account container / blob |
| SSE-C (customer-provided key per request) | **Blob customer-provided keys (CPK)**: a key supplied on each request, not stored by Azure |
| SSE-KMS (CMK) | Storage encryption with **customer-managed key in Key Vault** |
| Encryption scope abuse (attacker key) | **Encryption scopes** backed by an attacker-controlled Key Vault key (seen with Storm-0501) |
| S3 Lifecycle rule | **Lifecycle management policy** |
| S3 Versioning | **Blob versioning** + blob/container **soft delete** |
| S3 Object Lock | **Immutable storage** (time-based retention / legal hold) |
| CloudTrail management events | **Azure Activity log** |
| CloudTrail S3 data events | **StorageBlobLogs** (diagnostic settings) |
| GuardDuty S3 Protection | **Defender for Storage** |

**Attack chain mapping: what a Codefinger-style attack looks like in Azure**

| # | Stage | AWS (Codefinger) | Azure equivalent | Azure evidence |
|---|---|---|---|---|
| 1 | Obtain credentials | Leaked IAM user access key | Leaked **storage account key**, **SAS token**, or **SP client secret** | Repo / secret scanning; Defender for Cloud secret findings |
| 2 | Authenticate | SigV4 as the IAM user | Shared Key auth with the account key, or OAuth token as the SP | `StorageBlobLogs.AuthenticationType` = `AccountKey` / `SAS` / `OAuth`; Entra **service principal sign-in logs** for SP auth |
| 3 | Authorize | IAM policy allows `s3:PutObject` | Account key = **full data-plane access** (no RBAC check); SP needs Storage Blob Data Contributor | RBAC assignments; whether `allowSharedKeyAccess` is enabled |
| 4 | Discovery | `ListBuckets` / `ListObjects` | `ListContainers` / `ListBlobs` | `StorageBlobLogs` list operation bursts |
| 5 | Encrypt | SSE-C overwrite | `PutBlob` / `PutBlockList` / `CopyBlob` with a **customer-provided key**, or rewrite under an attacker-backed **encryption scope** | `StorageBlobLogs` overwrite bursts; encryption scope creation in Activity log; Key Vault `AuditEvent` |
| 6 | Inhibit recovery | 7-day lifecycle rule | Aggressive **lifecycle management policy**; soft delete / versioning disabled; locks removed | Activity log: `managementPolicies/write`, `blobServices/write`, `locks/delete` |
| 7 | Extortion | Ransom notes in buckets | Ransom note blob in every container; possibly a Teams message | `StorageBlobLogs` identical small `PutBlob` across containers |

> **Azure-specific risk:** A storage account key is **worse** than a scoped AWS IAM user key. It grants full data-plane control of the entire account, bypasses RBAC entirely, and has no identity attached in the logs beyond "AccountKey." Disabling shared key access (`allowSharedKeyAccess = false`) removes this whole attack path.

#### Containment

| # | Action | AWS | Azure equivalent |
|---|---|---|---|
| 1 | **Identify the credential** | CloudTrail `userIdentity.accessKeyId` → IAM user | `StorageBlobLogs.AuthenticationType` + `RequesterObjectId` / caller IP; SP sign-in logs |
| 2 | **Kill the credential** | Deactivate the key (keep it for forensics); attach a deny-all inline policy to the IAM user | Rotate **both** storage account keys; revoke user delegation keys; remove SP secrets and disable the SP |
| 3 | **Stop the clock** | Capture, then delete the malicious lifecycle rule | Capture, then remove the malicious lifecycle management policy |
| 4 | **Block the technique** | Deny SSE-C (bucket policy / RCP / SCP) | Disable shared key access; restrict CPK and encryption scope use with Azure Policy |
| 5 | **Freeze the data** | Deny-all bucket policy except a break-glass role | Disable public network access; `CanNotDelete` lock; re-enable soft delete and versioning |
| 6 | **Scope** | Affected buckets, objects, time window, other keys used | Affected accounts, containers, blobs, other identities used |
| 7 | **Hunt persistence** | `CreateAccessKey`, `CreateUser`, `AttachUserPolicy` by the same user | New SP credentials, role assignments, new SAS/keys listed (`listKeys`) |
| 8 | **Recover** | Restore prior object versions or backups | Restore prior blob versions / soft-deleted snapshots / point-in-time restore / immutable backups |
| 9 | **Fix root cause** | Find the leak source; move to roles and short-lived credentials | Find the leak source; move to managed identities / workload identity federation; Entra-only auth |

**Block SSE-C (AWS bucket policy statement):**
```json
{
  "Sid": "DenySSEC",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::<bucket>/*",
  "Condition": {
    "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "false" }
  }
}
```
`Null: false` means "the SSE-C header is present," so the request is denied. `CopyObject` also requires `s3:PutObject`, so this covers both calls.

**Recovery depends on versioning:**

| Bucket / container state | Outcome |
|---|---|
| Versioning **on** | Each overwrite created a new version. The original, readable version remains underneath, so restore it. |
| Versioning on + Object Lock / immutability | Same, and the attacker couldn't delete prior versions |
| Versioning **off** | Original is gone. Recover from backups or replicas only. |

> ⚠️ If the malicious lifecycle rule also expires **noncurrent versions**, it destroys the recovery path. Remove it first.

**Lessons:**
- Block SSE-C with an IAM condition, bucket policy, or **Resource Control Policy (RCP)** unless an app needs it. In Azure, disable shared key access and govern encryption scopes and CPK.
- Eliminate long-lived access keys and client secrets; use roles, managed identities, and short-lived credentials.
- Add network conditions (`aws:SourceIp` / `aws:SourceVpc`, or storage firewall / private endpoints) on sensitive storage.
- Enable versioning and Object Lock / immutability on critical storage, and protect noncurrent versions from lifecycle deletion.
- **Enable CloudTrail S3 data events and StorageBlobLogs.** Without them, you cannot see this attack.
- Alert on `PutBucketLifecycleConfiguration` / lifecycle management policy changes. They are rarely monitored.

---

### 3.2 Scattered Spider + DragonForce: Marks & Spencer (April 2025)

| Attribute | Detail |
|---|---|
| **Actors** | Scattered Spider (aka Octo Tempest, UNC3944, Muddled Libra) using **DragonForce** ransomware-as-a-service |
| **Platform** | Hybrid: on-prem Active Directory + VMware ESXi virtualization |
| **Initial access** | Social engineering. Reporting ties it to credentials from an IT outsourcing provider (TCS) and help desk manipulation. |
| **Impact** | Online ordering halted for 6+ weeks; estimated ~£40M/week in lost sales; customer personal data stolen (payment data reported as not affected) |

**Attack chain:**

1. **Initial access (reported ~Feb 2025):** Social engineering of IT support or a third-party contractor yields valid credentials.
2. **Credential access:** The attackers reportedly stole the **NTDS.dit** file (the AD database of password hashes).
3. **Lateral movement:** Used the cracked hashes to move across the Windows domain.
4. **Exfiltration:** Customer data was stolen.
5. **Impact (April 24, 2025):** The DragonForce encryptor was deployed against **VMware ESXi hosts**, encrypting VMs at the hypervisor layer.
6. **Disclosure:** M&S notified the London Stock Exchange on April 22. In July, the chairman confirmed Scattered Spider and DragonForce involvement before a UK Parliament committee.

**Why it matters for cloud teams:** The entry point was **people, not technology**. Help desk identity verification is a control gap in most organizations. Co-op, hit in the same wave, credited its earlier cloud migration with limiting impact.

**Lessons:**
- Harden help desk verification (video verification, manager callback, no MFA resets over phone alone).
- Treat AD and Entra Connect as **tier-0**.
- Hypervisors (ESXi, and the cloud control plane by analogy) are single points of mass encryption.
- Third-party and MSP access needs the same scrutiny as employee access.

---

### 3.3 ShinyHunters / UNC6040 & UNC6395: Salesforce Data Theft (June–August 2025)

| Attribute | Detail |
|---|---|
| **Actors** | UNC6040 (vishing wave), UNC6395 (Salesloft Drift token theft), UNC6240 (extortion under the "ShinyHunters" name) |
| **Platform** | Salesforce (SaaS) via OAuth integrations |
| **Malware used** | None |
| **Encryption** | None. Pure **exfil + extort**. |
| **Known victims (vishing wave)** | Adidas, Allianz Life, Qantas, and others |

**Wave 1: Vishing (UNC6040)**
1. Attackers call employees posing as IT support.
2. They trick the victim into authorizing a **malicious OAuth connected app** in Salesforce.
3. The app bulk-exports CRM data.

**Wave 2: Supply chain via Salesloft Drift (UNC6395)**
1. **Mar–Jun 2025:** The attacker accesses Salesloft's GitHub account and performs reconnaissance.
2. The attacker pivots into **Drift's AWS environment** and steals OAuth and refresh tokens for customers' Drift–Salesforce integrations.
3. **Aug 8–18, 2025:** Uses valid tokens to run SOQL queries exporting `User`, `Account`, `Case`, and `Opportunity` objects from hundreds of tenants.
4. Searches stolen data for **AWS keys, Snowflake tokens, and passwords** stored in records and support cases, which become fuel for the next breach.
5. **Aug 20:** Salesloft and Salesforce revoke all Drift tokens. **Sep 12:** FBI FLASH alert issued.
6. **Extortion:** Victims are contacted under the ShinyHunters name, and a leak site is launched.

**Indicators:** User agents such as `python-requests/2.32.4`, `Salesforce-Multi-Org-Fetcher/1.0`, `Salesforce-CLI/1.0`; large SOQL exports by an integration identity.

**Lessons:**
- **OAuth apps are identities.** Inventory them, restrict consent, and require admin approval.
- Never store secrets in CRM records or tickets; a data export exposes them.
- SaaS-to-SaaS integrations are supply chain risk. Monitor integration identities for volume anomalies.
- Ransomware readiness must include **SaaS**, not only IaaS.

---

### 3.4 Storm-0501: Cloud-Native Ransomware in Azure (August 2025)

| Attribute | Detail |
|---|---|
| **Actor** | Storm-0501 (financially motivated; active since 2021; previously used Sabbath, BlackCat, Hive, LockBit, Embargo, and others) |
| **Reported by** | Microsoft Threat Intelligence, August 27, 2025 |
| **Victim profile** | Large enterprise with multiple subsidiaries, **multiple Entra tenants**, and **multiple AD domains synced to more than one tenant** |
| **Malware in cloud** | None. Cloud-native tooling only. |

**Attack chain:**

1. **On-prem compromise:** Gained a foothold in AD and moved laterally with **Evil-WinRM**. Used DCSync to harvest credentials. Exploited gaps where Defender for Endpoint wasn't deployed.
2. **Pivot to cloud:** Compromised the **Entra Connect Sync server** and its **Directory Synchronization Account (DSA)**.
3. **Discovery:** Used **AzureHound** with the DSA to enumerate users, roles, and Azure resources.
4. **Privilege escalation:**
   - Found a **non-human synced identity holding Global Administrator with no MFA**.
   - Reset that account's password **on-prem**, which synced to the cloud.
   - Satisfied Conditional Access by signing in from a **hybrid-joined device** already under their control.
5. **Persistence:** Registered an **attacker-owned tenant as a federated domain**, allowing sign-in as any user.
6. **Azure takeover:** Called `Microsoft.Authorization/elevateAccess/action` to obtain **User Access Administrator at root scope**, then assigned itself **Owner on every subscription**.
7. **Exfiltration:** Enumerated storage accounts, opened network access, retrieved access keys (`listKeys`), and bulk-exfiltrated data with **AzCopy**.
8. **Inhibit recovery and destroy:** Deleted snapshots, restore points, Recovery Services vaults, and storage accounts. Where **resource locks or immutability policies blocked deletion**, it tried **encrypting data with a newly created Key Vault key / encryption scope** instead.
9. **Extortion:** Contacted the victim through **Microsoft Teams** using a compromised internal account.

**Why it matters (especially in hybrid Entra Connect environments):** This is the reference playbook for cloud ransomware. Every step abused a legitimate feature. The weakest links were a **synced, MFA-less, standing Global Admin** and an **Entra Connect server not treated as tier-0**.

**Lessons:**
- Entra Connect servers and sync accounts are **tier-0**. Restrict the sync account with Conditional Access (trusted location / workload identity CA), monitor its sign-ins, and never let it be used interactively.
- **No standing Global Admins.** Use cloud-only, PIM-eligible, phishing-resistant MFA admin accounts, never synced accounts.
- Alert on `elevateAccess`, new federated domains, and Owner/UAA assignments at subscription or management group scope.
- Resource locks and immutability **worked**. They forced the attacker to change tactics.
- Have **out-of-band communications**; the attacker was inside Teams.

---

### 3.5 JadePuffer (Storm-3168): First Agentic AI Ransomware (June–September 2026)

| Attribute | Detail |
|---|---|
| **Discovered by** | Sysdig Threat Research (July 2026); Microsoft tracked follow-on Azure activity as **Storm-3168** (blog Sep 25, 2026) |
| **What's new** | First documented ransomware operation run **end-to-end by an autonomous LLM agent** |
| **Initial access** | **CVE-2025-3248**, an unauthenticated RCE in **Langflow** (an open-source AI app builder) on an internet-exposed server |
| **Platforms** | Self-hosted AI stack (Langflow, PostgreSQL, MinIO, MySQL, Nacos) → Azure |

**Attack chain (Sysdig, self-hosted environment):**

1. **Initial access:** Exploited Langflow RCE to run Python.
2. **Credential access:** Dumped Langflow's PostgreSQL database; harvested environment variables, sensitive files, and API keys.
3. **Discovery:** Enumerated MinIO object storage and adapted payloads based on server responses.
4. **Lateral movement:** Connected to an exposed MySQL port as root; attacked Nacos (a config service) several ways at once; probed for container escape.
5. **Impact:** Encrypted **1,342 Nacos configuration items** and deleted the originals. The ransom note claimed AES-256, but researchers assessed it used weaker AES-128-ECB.
6. **AI tells:** Natural-language reasoning comments in the generated code, and **self-correction of failures in about 31 seconds** rather than blind retries.

**Attack chain (Microsoft, Azure tenant, early June 2026):**

1. **Valid accounts:** Used **compromised service principals**.
2. **Discovery:** One SP spent about 15.5 hours on recon (300+ successful reads). A second SP enumerated VMs and resource groups across two subscriptions in **5 seconds**.
3. **Inhibit recovery:** Enumerated and interfered with **resource locks and Recovery Services**.
4. **Impact:** Destructive operations against **storage accounts, Key Vault, Function Apps, and SQL databases**.
5. **Credential collection** that could enable later exfiltration. Microsoft did not observe a ransom note or confirmed exfiltration in this case.

**Why it matters (AI security):**
- **AI apps are a new initial-access surface.** Langflow, LLM gateways, notebooks, and agent frameworks often run with broad credentials.
- **Machine-speed attacks:** Seconds from recon to destruction. Human-paced triage is too slow, so automated containment is required.
- **Workload identities are the blast radius.** Over-privileged service principals turned one foothold into tenant-wide destruction.
- The barrier to entry drops to the cost of running an agent.

**Lessons:**
- Patch and never expose AI dev tooling to the internet; put it behind private access.
- Least-privilege service principals (no Contributor/Owner at subscription scope); prefer managed identities and workload identity federation over secrets.
- Build **SOAR auto-containment** (disable SP / deny-all policy) triggered by destructive bursts.
- Monitor SPs with the same rigor as users (Entra workload identity sign-in logs, ID Protection for workload identities).

---

### 3.6 LiteLLM Supply Chain Attack (October 2026): A Precursor Pattern

A compromised release of **LiteLLM** (a widely used LLM gateway library) installed an infostealer that harvested browser credentials and cookies, **AWS credentials (`~/.aws/`, env vars, IMDS)**, GCP service account keys, **Azure CLI tokens**, LLM provider API keys, SSH keys, and shell history.

**Why it's in a ransomware guide:** Credential theft at scale is the **raw material** for the next Codefinger or Storm-0501. Developer machines and CI runners holding cloud tokens are prime initial-access targets.

**Lessons:** Pin and verify dependencies; scan CI for secrets; issue short-lived, scoped credentials to pipelines (OIDC federation); monitor for cloud tokens used from unfamiliar IPs right after a package update.

---

### 3.7 Case Study Comparison

| Case | Entry | Escalation | Exfil? | Encrypt? | Destroy? | Key failure |
|---|---|---|---|---|---|---|
| Codefinger | Leaked AWS keys | None needed | No | **Yes (SSE-C)** | Lifecycle timer | Long-lived keys; SSE-C allowed |
| M&S | Social engineering / 3rd party | NTDS.dit → domain | Yes | **Yes (ESXi)** | — | Help desk & contractor trust |
| Salesforce wave | Vishing / stolen OAuth | Not needed | **Yes** | No | No | OAuth app governance; secrets in CRM |
| Storm-0501 | On-prem AD | Sync account → GA → elevateAccess | **Yes** | Attempted | **Yes** | Synced MFA-less GA; Connect not tier-0 |
| JadePuffer | AI app RCE / SPs | SP permissions | Credential collection | Yes (self-hosted) | **Yes (Azure)** | Exposed AI tooling; over-privileged SPs |

---

## 4. Indicators of Compromise by Stage

### 4.1 Identity Takeover

| Signal | Azure / Entra | AWS |
|---|---|---|
| Risky / anomalous sign-in | Entra ID Protection risk, impossible travel, new ASN | GuardDuty `UnauthorizedAccess:IAMUser/*`, console login from a new geo |
| Sync account misuse | `Sync_*` / DSA sign-ins from a new IP or interactively | — |
| New credentials | `Add service principal credentials`, `Update application – Certificates and secrets` | `CreateAccessKey`, `CreateLoginProfile` |
| New privileged identities | `Add member to role` (GA, Privileged Role Admin) | `CreateUser` + `AttachUserPolicy` AdministratorAccess |
| Root takeover | `Microsoft.Authorization/elevateAccess/action` | Root account usage |
| Federation backdoor | `Set domain authentication`, `Set federation settings on domain`, new domain added | `CreateSAMLProvider`, `UpdateAssumeRolePolicy` |
| CA weakened | `Update conditional access policy`, new exclusions | — |

### 4.2 Discovery

| Signal | Azure | AWS |
|---|---|---|
| Mass enumeration | Hundreds of reads across subscriptions in minutes; AzureHound / ROADtools user agents | `List*` / `Describe*` bursts; `GetAccountAuthorizationDetails` |

### 4.3 Defense Evasion

| Signal | Azure | AWS |
|---|---|---|
| Logging disabled | `Microsoft.Insights/diagnosticSettings/delete` | `StopLogging`, `DeleteTrail`, `PutEventSelectors` |
| Security tools disabled | Defender plan downgraded (`Microsoft.Security/pricings/write`) | `DeleteDetector`, `DisableSecurityHub` |

### 4.4 Exfiltration

| Signal | Azure | AWS |
|---|---|---|
| Key / token retrieval | `Microsoft.Storage/storageAccounts/listKeys/action`, `generateUserDelegationKey`, SAS generation | — |
| Network opened | `networkAcls.defaultAction = Allow`, public network access enabled | `DeletePublicAccessBlock`, permissive `PutBucketPolicy` |
| Bulk reads | `StorageBlobLogs` GetBlob spike; user agent `AzCopy/10.x`, rclone | Bulk `GetObject`; GuardDuty `Exfiltration:S3/AnomalousBehavior` |
| Off-tenant copies | Object replication to an external account | `PutBucketReplication` cross-account; `ModifySnapshotAttribute` / `ModifyDBSnapshotAttribute` shared externally |
| Egress | VNet/NSG flow logs; firewall logs | VPC Flow Logs |

> ⚠️ **Firewall-bypass gotcha:** If storage private endpoints sit in a subnet that bypasses the firewall (common for cost reasons on large data copies), bulk exfiltration over those endpoints **will not appear in firewall logs**. Rely on `StorageBlobLogs` and flow logs for that path.

### 4.5 Inhibit Recovery (Treat as P1)

| Signal | Azure | AWS |
|---|---|---|
| Soft delete / versioning off | `blobServices/write` with soft delete or versioning disabled | `PutBucketVersioning` → Suspended |
| Locks removed | `Microsoft.Authorization/locks/delete` | Object Lock config changes |
| Backups deleted | Recovery Services soft delete disabled, protected items deleted, vault deleted | `DeleteRecoveryPoint`, `DeleteBackupVault`, `DeleteSnapshot`, `DeleteDBSnapshot` |
| Deletion timer | Lifecycle management policy write with aggressive delete | `PutBucketLifecycleConfiguration` with short expiry |

### 4.6 Impact

| Signal | Azure | AWS |
|---|---|---|
| Mass overwrite | `PutBlob` / `PutBlockList` bursts overwriting existing blobs | `PutObject` / `CopyObject` with `SSEApplied = SSE_C` |
| Key sabotage | New Key Vault key + storage encryption switched to it, then key delete / purge; encryption scope creation | KMS `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`, `ImportKeyMaterial` |
| Mass delete | `DeleteBlob` bursts; storage account, VM, SQL, Key Vault, and resource group deletes | `DeleteObjects` bursts, `DeleteBucket`, `TerminateInstances` |
| Ransom note | Identical small file in every container; Teams message from an internal account | Identical `.txt` in every bucket or prefix |
| M365 / SaaS | Mass `FileModified` / `FileRenamed` (new extensions) / `FileDeleted` in SharePoint/OneDrive | — |

---

## 5. Logs & Services to Check

### 5.1 Azure / Microsoft

| Source | What it tells you | Default? | Retention to verify |
|---|---|---|---|
| **Entra sign-in logs** (interactive, non-interactive, **service principal**, managed identity) | Who signed in, from where, and CA results | On | 30 days (P1/P2); export for longer |
| **Entra audit logs** | Role adds, SP credential adds, federation and domain changes, CA edits, elevate access | On | 30 days; export |
| **Azure Activity log** | Control plane: role assignments, listKeys, locks, deletes, config changes | On | 90 days; export to Log Analytics / Sentinel |
| **Directory-level activity / elevate access events** | Root-scope UAA elevation | Check config | Confirm it reaches your SIEM |
| **StorageBlobLogs / StorageFileLogs / StorageQueueLogs** | Data plane: reads, writes, deletes, auth type, IP, user agent | **Off. Needs diagnostic settings.** | Per workspace |
| **Key Vault AuditEvent** | Key creation, deletion, purge; secret access | Off; diagnostic setting | Per workspace |
| **Recovery Services / Backup reports** | Backup job and deletion activity, soft delete state | Partial | — |
| **Defender for Cloud** (Storage, Resource Manager, Key Vault, Servers) | Alerts: unusual deletion or extraction, malware upload, suspicious management ops | Plan-dependent | — |
| **Defender XDR / Defender for Identity** | Correlated incidents; DCSync; Entra Connect server activity | Licensed | — |
| **Entra ID Protection** | User and workload identity risk | P2 / Workload ID | — |
| **Microsoft Sentinel** | Correlation, UEBA, hunting | Configured | — |
| **M365 Unified Audit Log** | SharePoint/OneDrive mass changes; Teams messages; mailbox access | On | 180 days (varies by license) |
| **VNet / NSG flow logs** | Egress volume and destinations | Off; enable | — |
| **Entra Connect server** (Windows event logs, Connect logs) | Sync account abuse, config changes | Local | Forward to SIEM |

### 5.2 AWS

| Source | What it tells you | Default? |
|---|---|---|
| **CloudTrail management events** | IAM, KMS, backup, and bucket configuration | On (90-day Event History); create an org trail for longer |
| **CloudTrail S3 data events** | `GetObject` / `PutObject` / `DeleteObject`, SSE-C usage | **Off. Biggest blind spot.** |
| **GuardDuty** (+ S3 Protection, Malware Protection) | Exfil, impact, credential anomaly findings | Must enable |
| **AWS Config** | Resource configuration history (before / after) | Must enable |
| **IAM Access Analyzer / credential report** | External access; key age and last use | On demand |
| **S3 server access logs** | Alternative data-plane log | Off |
| **VPC Flow Logs** | Egress | Off |
| **AWS Backup audit / Backup Vault Lock** | Recovery point deletion, vault policy | Configure |
| **Security Hub / Detective** | Aggregated findings; investigation graphs | Must enable |
| **KMS CloudTrail events** | Key policy changes, deletion scheduling | Via CloudTrail |

### 5.3 Third-Party / Other

| Source | Use |
|---|---|
| **CSPM (Falcon CSPM / Wiz)** | Blast radius (who *can* delete or encrypt), misconfiguration drift (soft delete off, public storage), attack path graphs |
| **Firewall (e.g., Palo Alto)** | Egress to unknown destinations; note bypass paths |
| **EDR (CrowdStrike, Defender for Endpoint)** | On-prem pivot: AD, Entra Connect server, admin workstations |
| **SaaS audit logs** (Salesforce Event Monitoring, GitHub audit log) | OAuth app abuse; bulk exports |
| **Backup platform** | Immutable copy status; deletion attempts |
| **ITSM (ServiceNow)** | Change tickets to rule out legitimate activity |

---

## 6. Confirming "High Likelihood of Ransomware"

### 6.1 Kill-Chain Scoring Model

| Stage observed | Example | Weight |
|---|---|---|
| Identity compromise | Risky sign-in, new key or secret, sync account anomaly | 1 |
| Discovery | Mass enumeration burst | 1 |
| Privilege escalation | Owner/UAA at root or subscription; AdministratorAccess | 2 |
| Defense evasion | Logging or security tooling disabled | 2 |
| Exfiltration | Bulk reads, AzCopy/rclone, external replication | 2 |
| **Inhibit recovery** | Soft delete off, backups deleted, locks removed, lifecycle timer | **3** |
| **Impact** | Mass overwrite / delete, key sabotage, ransom note | **3** |

| Total (same identity / IP / time window) | Assessment | Action |
|---|---|---|
| 1–2 | Suspicious | Investigate; validate with the owner |
| 3–5 | **Likely intrusion** | Escalate to IR; begin scoping; prep containment |
| 6+, **or any Inhibit-Recovery + Impact pair** | **High likelihood of ransomware** | Declare incident; contain immediately |

### 6.2 Validation Checklist

- [ ] Is the actor (user / SP / key) expected to perform this operation?
- [ ] Is there an approved change ticket or maintenance window?
- [ ] Is the source IP or ASN in the identity's baseline?
- [ ] Is the volume consistent with known jobs (migrations, backups, IaC deploys)?
- [ ] Did the same identity perform actions across **multiple kill-chain stages**?
- [ ] Were security controls (logging, soft delete, locks, backups) touched?
- [ ] Are ransom notes present in storage, or did anyone receive extortion messages (Teams, email, phone)?
- [ ] Did the identity's credentials change recently (new secret, password reset, MFA re-registration)?

### 6.3 Common False Positives

| Activity | Looks like | Differentiator |
|---|---|---|
| Data migration with AzCopy | Exfil | Known identity, known destination, change ticket |
| IaC teardown of a dev environment | Mass delete | Pipeline identity, dev subscription, matching commit |
| Backup software reading all blobs | Bulk read | Backup SP, scheduled time |
| Key rotation automation | Key changes | Rotation SP, schedule, no deletion of old data |
| Lifecycle policy rollout | Deletion timer | Applied via IaC with a PR |

---

## 7. Incident Responder Containment Playbook

Framework: **NIST SP 800-61** (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident).

### 7.1 Golden Rules

1. **Contain identity first, all at once.** Partial containment tips off the attacker, who may jump straight to mass deletion.
2. **Preserve evidence before you change things.** Attackers delete logs.
3. **Assume your communication tools are compromised** (Storm-0501 used Teams). Switch to out-of-band.
4. **Watch the clock.** Lifecycle deletion timers (7 days in Codefinger) and soft-delete retention windows are hard deadlines.
5. **Don't pay, delete, or restore anything without legal and leadership involvement.**

### 7.2 Phase 0: First 15 Minutes (Triage & Declare)

| Step | Action | Owner |
|---|---|---|
| 0.1 | Declare an incident; assign Incident Commander (IC) | SOC lead |
| 0.2 | Open an **out-of-band** bridge (personal phones, Signal, or a separate tenant) | IC |
| 0.3 | Identify the suspect identities (users, SPs, keys), IPs, and affected subscriptions / accounts | IR lead |
| 0.4 | Notify CISO, Legal, Privacy (PHI/PII?), and Comms | IC |
| 0.5 | Start an evidence and decision log with timestamps | Scribe |

### 7.3 Phase 1: Preserve Evidence

| Azure | AWS |
|---|---|
| Export Entra sign-in and audit logs, Activity log, StorageBlobLogs, Key Vault AuditEvent to an **immutable** storage account in a separate subscription/tenant | Copy CloudTrail to a locked log-archive account (S3 Object Lock) |
| Snapshot the Entra Connect server (if implicated) | Snapshot affected EC2 volumes |
| Record current RBAC assignments, CA policies, federation config, app registrations | Export IAM credential report, `GetAccountAuthorizationDetails`, bucket policies |

### 7.4 Phase 2: Contain the Identity (Simultaneously)

**Azure / Entra**

| Target | Action |
|---|---|
| Compromised user | Disable account → revoke sessions → reset password (twice if on-prem synced) → remove MFA methods the attacker registered |
| Compromised service principal | Remove **all** client secrets and certificates → disable the SP (`accountEnabled = false`) → remove federated credentials |
| Synced / hybrid accounts | Contain **on-prem too** (disable in AD); otherwise sync may revert changes |
| Entra Connect / sync account | Rotate the sync account credential; isolate the server if compromised; consider pausing sync |
| Rogue role assignments | Remove attacker Owner/UAA at subscription and MG scope; remove root-scope UAA from elevate access |
| Persistence | Remove rogue federated domains; remove CA policy exclusions; remove attacker-added GA / Privileged Role Admin |

Example (Microsoft Graph PowerShell / Azure CLI):
```powershell
# Disable user and revoke sessions
Update-MgUser -UserId <UPN> -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId <UPN>

# Disable a service principal
Update-MgServicePrincipal -ServicePrincipalId <SP-ObjectId> -AccountEnabled:$false
```
```bash
# Remove a rogue role assignment
az role assignment delete --assignee <principalId> --role Owner --scope /subscriptions/<subId>
```

**AWS**

| Target | Action |
|---|---|
| Compromised access key | Deactivate (don't delete yet; keep for forensics) |
| Compromised IAM user / role | Attach an inline **deny-all** policy; revoke active role sessions (`AWSRevokeOlderSessions` condition) |
| Org-wide | Apply an emergency **SCP** to the affected OU denying destructive actions except for a break-glass role |

```bash
aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive
aws iam put-user-policy --user-name <user> --policy-name DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

### 7.5 Phase 3: Protect the Data

**Azure Storage**

| Action | Why |
|---|---|
| Rotate **both** storage account keys (key1 and key2) | Invalidates key-based access and account SAS signed with those keys |
| Set `allowSharedKeyAccess = false` | Forces Entra auth only |
| Revoke user delegation keys | Invalidates user-delegation SAS |
| Disable public network access / restore network rules | Cuts off external access |
| Add `CanNotDelete` resource locks on critical storage, Key Vaults, and Recovery Services vaults | Blocks destruction |
| Re-enable soft delete, versioning, container soft delete | Preserves what's left |
| Turn on Key Vault purge protection | Prevents permanent key deletion |

```bash
az storage account keys renew -g <rg> -n <account> --key primary
az storage account keys renew -g <rg> -n <account> --key secondary
az storage account update -g <rg> -n <account> --allow-shared-key-access false --public-network-access Disabled
az storage account revoke-delegation-keys -g <rg> -n <account>
az lock create --name IR-NoDelete --lock-type CanNotDelete -g <rg>
```

**AWS S3**

| Action | Why |
|---|---|
| **Delete malicious lifecycle rules immediately** | Stops the deletion clock |
| Apply a deny-all bucket policy (except break-glass) | Freezes access |
| Deny SSE-C via bucket policy or RCP | Stops further encryption |
| Enable or verify versioning; suspend noncurrent-version expiration | Preserves prior versions |
| Revoke cross-account replication and snapshot sharing | Stops exfil paths |

```bash
aws s3api get-bucket-lifecycle-configuration --bucket <bucket>   # capture evidence first
aws s3api delete-bucket-lifecycle --bucket <bucket>
```

### 7.6 Phase 4: Protect Backups

| Azure | AWS |
|---|---|
| Confirm Recovery Services vault **immutability**, soft delete, and **Multi-User Authorization (MUA)** | Confirm **Backup Vault Lock** (compliance mode) and logically air-gapped vaults |
| Verify backups are restorable (test restore) | Verify recovery points exist and restore |
| Check for off-tenant / offline copies | Check for cross-account / cross-Region copies |

### 7.7 Phase 5: Restore Visibility

- Re-enable diagnostic settings, Defender plans, CloudTrail, and GuardDuty.
- Turn on data-plane logging if it was off. **Go forward visibility matters even mid-incident.**

### 7.8 Phase 6: Eradication (Hunt Persistence)

| Azure / Entra | AWS |
|---|---|
| New app registrations / enterprise apps; credentials added to existing SPs | New IAM users, roles, access keys |
| New or modified federated domains | Modified role trust policies; new SAML/OIDC providers |
| CA policy changes and exclusions | Lambda functions, EventBridge rules (backdoors) |
| New GA, PIM eligibility changes | External principals in KMS key policies and bucket policies |
| Guest users, cross-tenant access settings | Resource shares (RAM) |
| Entra Connect server integrity; AD (DCSync, golden ticket → reset krbtgt twice) | EC2 user data, SSM documents |
| Automation accounts, Logic Apps, runbooks | — |

### 7.9 Phase 7: Scope & Impact

- Which storage accounts, containers, and buckets were **read** (exfil), **overwritten** (encrypted), or **deleted**?
- Did any contain **PHI / PII / regulated data**? (Triggers legal breach assessment.)
- Which identities, subscriptions, and accounts were touched?
- What is the earliest evidence of compromise (dwell time)?

### 7.10 Phase 8: Recovery

| Scenario | Recovery path |
|---|---|
| Azure blobs overwritten | Restore previous blob versions / soft-deleted snapshots; point-in-time restore |
| Azure resources deleted | Recover soft-deleted storage account (within window); restore from immutable vault |
| S3 objects re-encrypted (SSE-C) | **Only** prior object versions or backups. The provider cannot decrypt. |
| Key Vault keys deleted | Recover soft-deleted key (if purge protection is on) |
| Entra tenant compromise | Rebuild trust: rotate all privileged credentials, review federation, re-establish Connect from a clean server |

Restore into a **clean, monitored** environment, and confirm the attacker is out first, or they'll destroy it again.

### 7.11 Phase 9: External Escalation

| Party | When |
|---|---|
| **Microsoft DART / AWS CIRT** | Early, for platform-level help and log access |
| **Legal / Privacy Office** | Immediately if regulated data may be involved (e.g., HIPAA breach risk assessment) |
| **Cyber insurance carrier** | Early; policy may require notice and approved IR firms |
| **Law enforcement (FBI / IC3, CISA)** | Per legal guidance |
| **Ransom payment decisions** | Legal, executive, and **OFAC sanctions** review required |

### 7.12 Containment Decision Matrix

| Situation | Decision | Trade-off |
|---|---|---|
| Attacker has GA / Owner and is active | Contain everything at once, now | May disrupt business apps using the same SPs |
| Exfil only, no destruction yet | Brief observation to scope, then contain | Risk of escalation to destruction; keep the window very short |
| Production SP compromised | Disable and accept downtime vs. rotate secret in place | Disabling is safer; rotating in place risks the attacker reading the new secret |
| Entra Connect server compromised | Pause sync | Identity changes stop flowing; avoids attacker re-syncing |
| Lifecycle deletion timer set | Remove the rule immediately, even before full scoping | Minor evidence trade-off (capture config first) |

---

## 8. Tabletop Exercise Guide

### 8.1 Roles

| Role | Responsibility |
|---|---|
| Facilitator | Runs the scenario, delivers injects, keeps time |
| Incident Commander | Owns decisions and priorities |
| Cloud Security / IR Lead | Technical investigation and containment |
| Identity Team | Entra / AD containment |
| Infrastructure / Cloud Ops | Resource and backup operations |
| SOC | Detection, alert triage, log pulls |
| Legal / Privacy / Compliance | Regulatory obligations, breach determination |
| Communications | Internal and external messaging |
| Executive sponsor | Business impact and ransom decisions |
| Scribe | Timeline and decision log |

### 8.2 Sample Scenario (Storm-0501-Style, Hybrid Azure)

| Inject | Time | Event | Prompts |
|---|---|---|---|
| **1** | T+0 | Defender for Identity alert: suspicious DCSync from a non-DC host | Who owns this? Is the Entra Connect server in scope? |
| **2** | T+2h | Sync account signs in from an unfamiliar IP; AzureHound-like enumeration in Graph | Can we restrict the sync account? Do we see SP sign-ins? |
| **3** | T+4h | A synced service account with Global Admin has its password changed on-prem, then signs into the Azure portal | Why does a synced account have GA? Do we have break-glass accounts? |
| **4** | T+4.5h | `elevateAccess` invoked; Owner granted on 40 subscriptions; a new federated domain appears | What do we contain first? Who has authority to act? |
| **5** | T+6h | `listKeys` on storage accounts holding PHI; 2 TB GetBlob via AzCopy over a private endpoint in a firewall-bypass subnet | Why didn't the firewall see it? Do we have StorageBlobLogs? Is this a reportable breach? |
| **6** | T+7h | Recovery Services soft delete disabled; locks deleted; storage accounts deleted | Are backups immutable? What's our RTO / RPO? |
| **7** | T+8h | Ransom demand arrives via Teams from an internal user's account | How do we communicate now? Who decides on payment? OFAC? |
| **8** | T+24h | A reporter calls asking about a data leak | What do we say? Who approves? |

### 8.3 Alternate Scenarios to Rotate

| Scenario | Tests |
|---|---|
| **Codefinger-style AWS** (leaked key → SSE-C encryption + 7-day lifecycle) | S3 data events, key hygiene, versioning, deadlines |
| **SaaS extortion** (OAuth app exports CRM/M365 data; leak threat) | OAuth app governance, SaaS logging, breach notification |
| **Agentic AI attack** (exposed AI app → SP credentials → resource destruction in minutes) | Automated containment, SP least privilege, AI asset inventory |
| **Insider / third party** (MSP account abused) | Third-party access controls, vendor contracts |

### 8.4 Pre-Exercise Preparation Checklist

- [ ] Inventory of tier-0 assets (GA accounts, Entra Connect servers, break-glass accounts, Owner at root/MG)
- [ ] Know where each log lives, who can query it, and its retention
- [ ] Confirm data-plane logging coverage (StorageBlobLogs, S3 data events) on PHI/PII storage
- [ ] Confirm backup immutability and the last successful test restore
- [ ] List SPs with Owner/Contributor at subscription scope or higher
- [ ] Have containment scripts or runbooks ready and tested (disable user/SP, rotate keys, deny-all)
- [ ] Out-of-band comms plan and contact list (printed / offline)
- [ ] Legal and regulatory notification timelines
- [ ] Contact info for Microsoft DART / AWS CIRT, insurer, outside IR firm
- [ ] Know your CSPM's attack-path view for "who can delete storage"

### 8.5 Success Metrics

| Metric | Target to discuss |
|---|---|
| Time to detect (TTD) | Minutes from first destructive / recovery-inhibition event |
| Time to contain identity | All suspect identities disabled |
| Time to protect backups | Locks / immutability confirmed |
| Data scoped | Affected stores identified with data classification |
| Decision latency | Time from evidence to authorized action |
| Comms | Out-of-band channel live; stakeholders notified |

---

## 9. Key Questions to Ask (Question Bank)

### 9.1 Detection & Visibility
1. Would we detect `elevateAccess`, a new federated domain, or Owner assigned at root/MG scope? How fast, and who gets paged?
2. Do we have **data-plane logs** (StorageBlobLogs, S3 data events) on every storage account or bucket holding sensitive data?
3. What's our log retention, and are logs stored where an attacker with Owner/GA **cannot delete them**?
4. Are Defender for Storage / Resource Manager / Key Vault and GuardDuty S3 Protection enabled everywhere?
5. Do we monitor **service principal and managed identity sign-ins**, not just users?
6. Which egress paths bypass the firewall (private endpoints, bypass subnets), and how do we see traffic on them?
7. Do we alert on recovery-inhibition events (soft delete disabled, locks deleted, backups deleted) as P1?

### 9.2 Identity
1. How many standing Global Admins do we have? Are any **synced from on-prem**? Any without phishing-resistant MFA?
2. Is the **Entra Connect server** treated as tier-0 (EDR, restricted logon, monitored)?
3. Is the sync account restricted by Conditional Access?
4. Which service principals have Owner/Contributor at subscription or MG scope? Who owns them?
5. How many apps use client secrets vs. certificates / managed identities / workload identity federation?
6. How do we verify identity before the help desk resets MFA or a password?
7. Are break-glass accounts tested, monitored, and excluded appropriately?
8. Who can approve OAuth app consent? Do we review third-party app permissions?
9. Do we have long-lived AWS access keys? How old? When were they last used?

### 9.3 Data & Storage
1. Is shared key access disabled on storage accounts? Where is it still enabled and why?
2. Are soft delete, versioning, and point-in-time restore enabled on critical storage?
3. Which storage accounts / buckets hold PHI or PII? Is that classification current?
4. Is SSE-C blocked in AWS? Are critical buckets on Object Lock?
5. Do critical resources have `CanNotDelete` locks? Who can remove them?
6. Is Key Vault purge protection enabled everywhere?

### 9.4 Backup & Recovery
1. Are backups **immutable** and protected by MUA / Vault Lock?
2. Are backups in a **separate tenant / account / security boundary** an attacker with GA couldn't reach?
3. When did we last perform a full test restore? How long did it take vs. RTO?
4. What is the recovery order for critical services (identity first, then what)?
5. If Entra ID itself is compromised, how do we rebuild trust?

### 9.5 Containment & Response
1. Who has authority to disable a production service principal or pause Entra Connect sync at 2 AM?
2. Do we have pre-approved, tested containment runbooks / SOAR playbooks?
3. Can we contain all suspect identities **simultaneously**?
4. If Teams and email are compromised, how do we communicate?
5. How do we preserve evidence before making changes?
6. Do we know how to engage Microsoft DART / AWS CIRT, and do we have the support plan to do so quickly?
7. Could we contain a machine-speed (AI-driven) attack, or does containment rely on humans?

### 9.6 Legal, Regulatory & Business
1. At what point does this become a reportable breach (HIPAA, state laws, contracts)? Who decides?
2. What are our notification timelines and to whom?
3. What is our position on ransom payment? Who decides? Have we planned for OFAC sanctions checks?
4. Does our cyber insurance require specific notification steps or approved vendors?
5. What is the business cost per hour of downtime for key systems?
6. Who speaks to media, patients/customers, regulators, and employees?

### 9.7 Third Parties & Supply Chain
1. Which vendors / MSPs have privileged access to our tenants? How is it monitored?
2. Which SaaS integrations hold OAuth tokens to our data? Could we revoke them quickly?
3. Do CI/CD pipelines use short-lived credentials (OIDC) or stored secrets?
4. Are secrets ever stored in tickets, CRM, wikis, or repos?

### 9.8 AI-Specific
1. Do we have an inventory of AI apps, agents, and tooling (Langflow, notebooks, LLM gateways, Copilot agents)?
2. Are any AI tools internet-exposed or unpatched?
3. What credentials and data can AI agents and their identities reach?
4. Can we disable an AI agent identity quickly if it behaves maliciously?

---

## 10. Hunting Queries

### 10.1 Azure: Control-Plane Destruction Burst (KQL)
```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any ("LISTKEYS/ACTION","REGENERATEKEY","LOCKS/DELETE",
        "STORAGEACCOUNTS/DELETE","ROLEASSIGNMENTS/WRITE","BACKUPPOLICIES","PROTECTEDITEMS/DELETE",
        "VAULTS/DELETE","DIAGNOSTICSETTINGS/DELETE")
| summarize Ops=count(), OpTypes=make_set(OperationNameValue), Targets=dcount(_ResourceId)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where Targets > 5 or Ops > 20
| order by Ops desc
```

### 10.2 Azure: Data-Plane Mass Read / Overwrite / Delete (KQL)
```kql
StorageBlobLogs
| where TimeGenerated > ago(6h)
| where OperationName in ("GetBlob","PutBlob","PutBlockList","DeleteBlob","CopyBlob")
| summarize Count=count() by AccountName, OperationName, CallerIpAddress,
    AuthenticationType, UserAgentHeader, bin(TimeGenerated, 15m)
| where Count > 1000   // tune to baseline; AccountKey auth from a new IP is a red flag
| order by Count desc
```

### 10.3 Azure: AzCopy / rclone Usage (KQL)
```kql
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where UserAgentHeader has_any ("AzCopy","rclone")
| summarize Requests=count(), BytesOut=sum(ResponseBodySize)
    by AccountName, CallerIpAddress, AuthenticationType, RequesterObjectId
| order by BytesOut desc
```

### 10.4 Entra: Privilege Escalation & Persistence (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("elevate", "Set federation settings on domain",
        "Set domain authentication", "Add domain to company",
        "Add service principal credentials", "Update application – Certificates and secrets management",
        "Add member to role", "Update conditional access policy")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

### 10.5 Entra: Sync Account Anomalies (KQL)
```kql
SigninLogs
| union AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName startswith "Sync_" or UserPrincipalName has "ADToAADSyncServiceAccount"
| summarize Count=count(), Apps=make_set(AppDisplayName) by UserPrincipalName, IPAddress, bin(TimeGenerated, 1d)
// Alert on any IP other than the Entra Connect server's egress IP
```

### 10.6 AWS: SSE-C Re-Encryption (Athena)
```sql
SELECT eventtime, useridentity.arn, sourceipaddress, eventname,
       json_extract_scalar(requestparameters,'$.bucketName') AS bucket, count(*) AS n
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutObject','CopyObject')
  AND json_extract_scalar(additionaleventdata,'$.SSEApplied') = 'SSE_C'
GROUP BY 1,2,3,4,5
ORDER BY n DESC;
```

### 10.7 AWS: Recovery Inhibition & Evasion (Athena)
```sql
SELECT eventtime, useridentity.arn, sourceipaddress, eventname, awsregion
FROM cloudtrail_logs
WHERE eventname IN ('PutBucketLifecycleConfiguration','PutBucketVersioning','DeleteBucketPolicy',
                    'PutBucketReplication','ModifySnapshotAttribute','ModifyDBSnapshotAttribute',
                    'DeleteRecoveryPoint','DeleteBackupVault','ScheduleKeyDeletion','DisableKey',
                    'StopLogging','DeleteTrail','DeleteDetector','CreateAccessKey')
  AND eventtime > to_iso8601(current_timestamp - interval '7' day)
ORDER BY eventtime DESC;
```

---

## 11. Preventive Controls

| Control | Stops | Platform |
|---|---|---|
| Entra Connect server + sync account as tier-0; CA on sync account | Storm-0501 pivot | Azure |
| PIM for all privileged roles; cloud-only admin accounts; phishing-resistant MFA | Standing-privilege abuse | Azure |
| Alert on `elevateAccess`, federation changes, root/MG role assignments | Tenant takeover | Azure |
| Disable storage shared key access; Entra auth only | Key-based exfil and encryption | Azure |
| Soft delete, versioning, immutability, `CanNotDelete` locks, Key Vault purge protection | Destroy / encrypt | Azure |
| Recovery Services immutable vault + MUA | Backup deletion | Azure |
| Block SSE-C (RCP / SCP / bucket policy) | Codefinger | AWS |
| Eliminate long-lived access keys; IAM Identity Center + roles | Leaked-key entry | AWS |
| S3 Object Lock, versioning, Backup Vault Lock, logically air-gapped vault | Destroy / encrypt | AWS |
| CloudTrail S3 data events + GuardDuty S3 Protection on sensitive buckets | Visibility | AWS |
| Least-privilege SPs; managed identities; workload identity federation; secret rotation | SP-driven destruction (JadePuffer) | Both |
| OAuth app consent governance; admin approval workflow | Salesforce / Drift pattern | SaaS |
| Help desk identity verification procedures | Scattered Spider | People |
| Patch and privately host AI tooling; AI asset inventory | JadePuffer entry | AI |
| Pinned dependencies; OIDC for CI/CD; secret scanning | Supply chain credential theft | DevOps |
| SOAR auto-containment on destructive bursts | Machine-speed attacks | Both |
| Out-of-band IR communications | Teams-based extortion | Process |

---

## 12. References

- Microsoft Threat Intelligence: Storm-0501 cloud-based ransomware (Aug 2025). Coverage: [BleepingComputer](https://bleepingcomputer.com/news/security/storm-0501-hackers-shift-to-ransomware-attacks-in-the-cloud), [The Register](https://www.theregister.com/2025/08/27/storm0501_ransomware_azure_teams/), [The Hacker News](https://thehackernews.com/2025/08/storm-0501-exploits-entra-id-to.html), [SecurityWeek](https://www.securityweek.com/ransomware-group-exploits-hybrid-cloud-gaps-gains-full-azure-control-in-enterprise-attacks/)
- Codefinger / S3 SSE-C: [BleepingComputer](https://www.bleepingcomputer.com/news/security/ransomware-abuses-amazon-aws-feature-to-encrypt-s3-buckets/), [Help Net Security](https://www.helpnetsecurity.com/2025/01/13/codefinger-encrypting-aws-s3-data-without-ransomware-sse-c/), [SecurityWeek](https://www.securityweek.com/compromised-aws-keys-abused-in-codefinger-ransomware-attacks/), [Rewind](https://rewind.com/blog/codefinger-how-an-emerging-ransomware-threat-exploited-an-aws-s3-encryption-feature-to-hold-data-hostage/)
- Marks & Spencer / Scattered Spider / DragonForce: [Help Net Security](https://www.helpnetsecurity.com/2025/04/29/marks-spencer-ransomware-breach-incident/), [Computer Weekly](https://www.computerweekly.com/news/366623453/Scattered-Spider-on-the-hook-for-MS-cyber-attack), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news-features/how-uk-retail-responded-hack-wave/)
- Salesforce / Salesloft Drift: [BleepingComputer](https://www.bleepingcomputer.com/news/security/salesloft-breached-to-steal-oauth-tokens-for-salesforce-data-theft-attacks/), [The Hacker News](https://thehackernews.com/2025/08/salesloft-oauth-breach-via-drift-ai.html), [Krebs on Security](https://krebsonsecurity.com/2025/09/the-ongoing-fallout-from-a-breach-at-ai-chatbot-maker-salesloft/), [CyberInsider](https://cyberinsider.com/widespread-data-theft-campaign-strikes-salesforce-via-salesloft-drift/)
- JadePuffer / Storm-3168: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/), [BleepingComputer](https://bleepingcomputer.com/news/security/jadepuffer-ransomware-used-ai-agent-to-automate-entire-attack), [Dark Reading](https://www.darkreading.com/cloud-security/jadepuffer-ai-actor-azure-tenant-destructive-cloud-attack), [HackMag](https://hackmag.com/news/jadepuffer)
- LiteLLM supply chain attack: [The Register](https://www.theregister.com/security/2026/10/21/litellm-supply-chain-attack-hoovers-up-passwords-and-secrets/5304548)
- Azure Storage ransomware forensics: [Mitiga](https://www.mitiga.io/blog/ransomware-strikes-azure-storage-are-you-ready)
- NIST SP 800-61 Rev. 3: Incident Response Recommendations
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/

---

*Validate all commands and queries in a non-production environment before use. Table names, operation names, and field names can vary by connector version and tenant configuration.*
