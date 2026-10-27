# Cloud Ransomware: Attack Chain, Case Studies & IR Playbook

> Tabletop-exercise prep guide for Azure / Entra ID and AWS environments.

## Table of Contents

1. [Overview](#1-overview)
2. [Attack Chain](#2-attack-chain)
3. [Case Studies](#3-case-studies)
4. [Indicators & Where to Look](#4-indicators--where-to-look)
5. [Confirming Ransomware](#5-confirming-ransomware)
6. [Containment Playbook](#6-containment-playbook)
7. [Tabletop Exercise](#7-tabletop-exercise)
8. [Key Questions](#8-key-questions)
9. [References](#9-references)

---

## 1. Overview

Cloud ransomware is an **identity attack**. It rarely uses malware. The attacker steals a credential, escalates privileges, then uses the cloud provider's own APIs to steal, encrypt, or delete data.

| Flavor | What happens | Recovery |
|---|---|---|
| **Encrypt** | Data is re-encrypted with an attacker-held key | Only from versions or immutable backups |
| **Exfil + extort** | Data is stolen; the attacker threatens to leak it | Data intact, but it's a breach |
| **Destroy** | Data is exfiltrated, then backups and resources are deleted | Only from immutable or off-tenant backups |

---

## 2. Attack Chain

```
Initial Access → Credential Access → Discovery → Privilege Escalation → Persistence
      → Defense Evasion → Exfiltration → Inhibit Recovery → Impact → Extortion
```

| # | Stage | Azure / Entra example | AWS example | MITRE |
|---|---|---|---|---|
| 1 | Initial access | Vished admin, help desk MFA reset, compromised on-prem AD, exposed app RCE | Leaked access key, exposed app RCE | T1078.004, T1566.004, T1190 |
| 2 | Credential access | DCSync, Entra Connect sync account, SP secrets | `~/.aws/credentials`, IMDS, env vars | T1003.006, T1552 |
| 3 | Discovery | AzureHound; enumerate subscriptions, storage, vaults | `ListBuckets`, `GetAccountAuthorizationDetails` | T1580, T1526 |
| 4 | Privilege escalation | `elevateAccess` → User Access Administrator → Owner on all subscriptions | Attach AdministratorAccess | T1098.003 |
| 5 | Persistence | Rogue federated domain, new SP credentials, CA exclusions | New IAM user / key, backdoored role trust | T1098.001, T1484.002 |
| 6 | Defense evasion | Delete diagnostic settings, disable Defender | `StopLogging`, delete GuardDuty detector | T1562.008 |
| 7 | Exfiltration | `listKeys`, open network ACLs, AzCopy | Bulk `GetObject`, cross-account replication | T1530, T1537 |
| 8 | **Inhibit recovery** | Delete backups / vaults, disable soft delete, delete locks | Delete recovery points, suspend versioning, short lifecycle expiry | T1490 |
| 9 | Impact | Encrypt with attacker Key Vault key / encryption scope; mass delete | SSE-C overwrite; KMS key deletion; mass delete | T1486, T1485 |
| 10 | Extortion | Ransom via Teams from a compromised account | Ransom notes in buckets | T1657 |

> Recovery inhibition (stage 8) almost always comes right before impact. Alert on it as P1.

---

## 3. Case Studies

| Case | Date | Entry | Exfil | Encrypt | Destroy | Key failure |
|---|---|---|---|---|---|---|
| [Codefinger](#31-codefinger-aws-s3-sse-c-jan-2025) | Jan 2025 | Leaked AWS key | No | **Yes** | Lifecycle timer | Long-lived keys; SSE-C allowed |
| [M&S / Scattered Spider](#32-scattered-spider--dragonforce-ms-apr-2025) | Apr 2025 | Social engineering | Yes | **Yes** | — | Help desk & contractor trust |
| [Salesforce / ShinyHunters](#33-shinyhunters-salesforce-junaug-2025) | Jun–Aug 2025 | Vishing / stolen OAuth tokens | **Yes** | No | No | OAuth app governance |
| [Storm-0501](#34-storm-0501-azure-aug-2025) | Aug 2025 | On-prem AD → Entra | **Yes** | Attempted | **Yes** | Synced MFA-less Global Admin |
| [JadePuffer](#35-jadepuffer--storm-3168-agentic-ai-jun-sep-2026) | Jun–Sep 2026 | AI app RCE / SPs | Credentials | Yes | **Yes** | Exposed AI tooling; over-privileged SPs |

### 3.1 Codefinger: AWS S3 SSE-C (Jan 2025)

Discovered by Halcyon; at least two victims. No malware and no exfiltration. Every step was a native AWS API call.

**Key clarifications**

| Common assumption | Reality |
|---|---|
| A user account was compromised | A **leaked long-term access key** (`AKIA...`) belonging to an **IAM user** was used. No console login, no MFA prompt. |
| They authenticated to the bucket | They authenticated to **AWS IAM** as that user. The bucket allowed the requests because the user was **authorized** (`s3:GetObject` + `s3:PutObject`). |
| A customer managed key (KMS) was used | **SSE-C (customer-*provided* key)**: the attacker sent their own AES-256 key with each request. AWS used it and **discarded it**. |
| Rotate the key to fix it | There is **no key in your account to rotate**. Rotation only affects future writes. Recovery comes from versions or backups. |

| Encryption type | Who holds the key | Can you recover? |
|---|---|---|
| SSE-S3 | AWS | Yes |
| SSE-KMS (CMK) | Your KMS | Yes |
| **SSE-C** | Whoever sent the request | **Only with the attacker's key** |

> **Analogy:** SSE-KMS is a safe-deposit box where the bank keeps a master key. SSE-C is bring-your-own padlock, and the bank never sees the key. Codefinger used a valid badge to put its own padlock on every box.

**Attack chain**

| # | Stage | What happened | CloudTrail evidence |
|---|---|---|---|
| 1 | Obtain credentials | Leaked or stolen access key (from a repo, CI log, laptop, etc.) | Not visible in AWS |
| 2 | Authenticate | Signed requests with the key; IAM treated the attacker as that IAM user | `userIdentity.accessKeyId`, unfamiliar source IP |
| 3 | Authorize | User's policies allowed read/write on the bucket | Successful S3 calls |
| 4 | Discovery | Listed reachable buckets and objects | `ListBuckets`, `ListObjects` |
| 5 | Encrypt | Overwrote every object using SSE-C with an attacker key | `PutObject`/`CopyObject` with `SSEApplied = SSE_C` (**S3 data events required**) |
| 6 | Inhibit recovery | Set a **7-day lifecycle deletion** rule | `PutBucketLifecycleConfiguration` |
| 7 | Extortion | Dropped ransom notes demanding Bitcoin for the key | Identical note files across prefixes |

**Azure mapping**

| AWS | Azure equivalent |
|---|---|
| IAM user + long-term access key | Service principal + client secret, or **storage account key** / SAS |
| STS temporary credentials | Managed identity / workload identity federation |
| IAM policy | RBAC role assignment |
| SSE-C | Blob **customer-provided keys (CPK)**, or an attacker-backed **encryption scope** |
| SSE-KMS (CMK) | Customer-managed key in Key Vault |
| Lifecycle rule | Lifecycle management policy |
| Versioning / Object Lock | Blob versioning + soft delete / immutable storage |
| CloudTrail S3 data events | StorageBlobLogs |
| Block SSE-C with RCP/SCP | Disable shared key access; govern CPK / encryption scopes with Azure Policy |

> **Azure-specific risk:** A storage account key grants full data-plane access, **bypasses RBAC**, and logs only as "AccountKey." Setting `allowSharedKeyAccess = false` removes this attack path.

**Codefinger-specific response**
- Find the key via `userIdentity.accessKeyId`, deactivate it, and deny-all the IAM user.
- **Remove the lifecycle rule first.** The deletion clock is running, and it may also expire prior versions.
- Block SSE-C (bucket policy, RCP, or SCP).
- Restore from prior object versions. If versioning was off, only backups can help.

### 3.2 Scattered Spider + DragonForce: M&S (Apr 2025)

| Stage | What happened |
|---|---|
| Initial access (~Feb 2025) | Social engineering; reporting ties it to credentials from an IT outsourcing provider |
| Credential access | Stole AD **NTDS.dit** (password hashes) |
| Lateral movement | Used the hashes across the Windows domain |
| Exfiltration | Customer personal data stolen |
| Impact (Apr 24) | **DragonForce** encrypted VMware ESXi hosts |
| Business impact | Online orders halted 6+ weeks; ~£40M/week estimated lost sales |

**Lessons:** Harden help desk identity verification. Treat AD and Entra Connect as tier-0. Scrutinize third-party access.

### 3.3 ShinyHunters: Salesforce (Jun–Aug 2025)

| Stage | What happened |
|---|---|
| Wave 1 (UNC6040) | Vishing tricked employees into authorizing a **malicious OAuth app** in Salesforce |
| Wave 2 (UNC6395) | Attacker breached Salesloft's GitHub → Drift's AWS → stole Drift–Salesforce **OAuth tokens** |
| Exfiltration (Aug 8–18) | SOQL bulk exports from hundreds of tenants; searched records for AWS keys and passwords |
| Response | Tokens revoked Aug 20; FBI FLASH alert Sep 12 |
| Extortion | Leak threats under the ShinyHunters name |

**Lessons:** OAuth apps are identities, so govern consent. Never store secrets in CRM records or tickets. Include SaaS in ransomware planning.

### 3.4 Storm-0501: Azure (Aug 2025)

| Stage | What happened |
|---|---|
| On-prem compromise | Evil-WinRM lateral movement, DCSync |
| Pivot to cloud | Compromised the **Entra Connect sync server** and its sync account |
| Discovery | AzureHound enumeration |
| Escalation | Found a **synced, MFA-less Global Admin**; reset its password on-prem (synced to cloud); met CA via a hybrid-joined device |
| Persistence | Added an attacker tenant as a **federated domain** |
| Azure takeover | `elevateAccess` → User Access Administrator → **Owner on all subscriptions** |
| Exfiltration | `listKeys` + AzCopy from storage accounts |
| Destroy | Deleted snapshots, restore points, vaults, and storage accounts; where locks/immutability blocked it, tried encrypting with a new Key Vault key |
| Extortion | Ransom demand via **Teams** from a compromised account |

**Lessons:** Entra Connect servers and sync accounts are tier-0. No standing or synced Global Admins. Alert on `elevateAccess` and federation changes. Locks and immutability worked. Have out-of-band comms ready.

### 3.5 JadePuffer / Storm-3168: Agentic AI (Jun–Sep 2026)

| Stage | What happened |
|---|---|
| Initial access | **CVE-2025-3248** RCE in internet-exposed **Langflow** |
| Credential access | Dumped databases, env vars, API keys |
| Impact (self-hosted) | Encrypted 1,342 Nacos config items; self-corrected errors in ~31 seconds |
| Azure activity | Compromised **service principals**; 15.5 hours of recon, then a second SP enumerated two subscriptions in **5 seconds** |
| Destroy (Azure) | Targeted locks and Recovery Services; deleted storage, Key Vault, Function Apps, SQL |

Sysdig assessed this as the first documented ransomware run end-to-end by an LLM agent.

**Lessons:** Don't expose AI tooling to the internet. Use least-privilege service principals. Machine-speed attacks need **automated containment**.

---

## 4. Indicators & Where to Look

| Stage | Azure / Entra | AWS |
|---|---|---|
| **Identity takeover** | Entra sign-in logs (risky sign-ins, sync account from a new IP, SP sign-ins); Entra audit logs (`elevateAccess`, federation changes, SP credential adds, role adds, CA edits) | CloudTrail: `CreateAccessKey`, `CreateUser`, `AttachUserPolicy`, `UpdateAssumeRolePolicy`; GuardDuty credential findings |
| **Discovery** | Activity log / Graph: mass reads across subscriptions | CloudTrail: `List*` / `Describe*` bursts |
| **Defense evasion** | Activity log: diagnostic settings deleted, Defender plans changed | CloudTrail: `StopLogging`, `DeleteTrail`, `DeleteDetector` |
| **Exfiltration** | Activity log: `listKeys`, network rules opened; **StorageBlobLogs**: GetBlob spikes, AzCopy/rclone user agents; flow logs | **S3 data events**: GetObject spikes; `PutBucketReplication` cross-account; snapshot sharing; GuardDuty exfil findings; VPC Flow Logs |
| **Inhibit recovery** | Activity log: soft delete / versioning off, locks deleted, backup items / vaults deleted, lifecycle policy changes | CloudTrail: `PutBucketVersioning` (Suspended), `DeleteRecoveryPoint`, `PutBucketLifecycleConfiguration` |
| **Impact** | StorageBlobLogs: mass overwrite / delete; Key Vault AuditEvent: key create / delete / purge; M365 UAL: mass file changes | S3 data events: SSE-C overwrites, `DeleteObjects` bursts; KMS `ScheduleKeyDeletion` |

**Logs that are off by default (enable these before an incident):**

| Log | Why it matters |
|---|---|
| Azure **StorageBlobLogs** (diagnostic settings) | The only record of who read, overwrote, or deleted blobs |
| Key Vault **AuditEvent** | Key creation, deletion, and purge |
| VNet / NSG **flow logs** | Egress volume |
| AWS **CloudTrail S3 data events** | The only way to see SSE-C encryption and bulk reads |
| **GuardDuty** S3 Protection | S3 anomaly detection |

> ⚠️ **Firewall blind spot:** Traffic to storage private endpoints in a firewall-bypass subnet never reaches the firewall. Only StorageBlobLogs and flow logs show exfiltration on that path.

---

## 5. Confirming Ransomware

Score activity from the same identity, IP, or time window:

| Stage observed | Weight |
|---|---|
| Identity compromise | 1 |
| Discovery | 1 |
| Privilege escalation | 2 |
| Defense evasion | 2 |
| Exfiltration | 2 |
| **Inhibit recovery** | **3** |
| **Impact** | **3** |

| Score | Assessment | Action |
|---|---|---|
| 1–2 | Suspicious | Validate with the owner |
| 3–5 | Likely intrusion | Escalate to IR; scope |
| 6+, or **any inhibit recovery + impact** | **High likelihood of ransomware** | Declare and contain |

**Rule out false positives:**

1. Is there a change ticket?
2. Is it a known pipeline, backup, or migration identity?
3. Is the source IP in the identity's baseline?
4. Did the identity touch more than one kill-chain stage?

---

## 6. Containment Playbook

**Golden rules**
1. Contain all suspect identities **at the same time**. Partial containment tips off the attacker.
2. Preserve evidence before changing anything.
3. Assume Teams and email are compromised. Use out-of-band comms.
4. Lifecycle deletion timers and soft-delete windows are hard deadlines.

| Phase | Azure / Entra | AWS |
|---|---|---|
| **1. Declare** | Name an Incident Commander; open an out-of-band bridge; notify CISO, Legal, Privacy, Comms | Same |
| **2. Preserve evidence** | Export Entra, Activity, StorageBlobLogs, and Key Vault logs to immutable storage in a separate subscription | Copy CloudTrail to a locked log-archive account |
| **3. Kill identities** | Disable users and revoke sessions; remove SP secrets/certs and disable SPs; disable synced accounts **on-prem too**; rotate the sync account; remove rogue role assignments, root-scope UAA, and federated domains | Deactivate access keys; attach deny-all policies; revoke role sessions; emergency SCP on the affected OU |
| **4. Protect data** | Rotate **both** storage keys; disable shared key access; revoke user delegation keys; disable public access; add `CanNotDelete` locks; re-enable soft delete and versioning; enable Key Vault purge protection | **Remove malicious lifecycle rules**; deny-all bucket policy except break-glass; block SSE-C; revoke cross-account replication and snapshot sharing |
| **5. Protect backups** | Verify immutable vault, soft delete, and Multi-User Authorization | Verify Backup Vault Lock and air-gapped copies |
| **6. Restore visibility** | Re-enable diagnostic settings and Defender plans | Re-enable CloudTrail, data events, GuardDuty |
| **7. Eradicate** | Hunt for new app registrations, SP credentials, CA exclusions, new admins, federation changes, guest access; check Entra Connect server and AD (reset krbtgt twice) | Hunt for new IAM users/roles/keys, trust policy changes, Lambda backdoors, external principals in key and bucket policies |
| **8. Scope** | Which data was read, overwritten, or deleted; whether PHI/PII was involved; earliest compromise | Same |
| **9. Recover** | Restore blob versions, soft-deleted data, or immutable backups into a clean, monitored environment | Restore prior object versions or backups |
| **10. Escalate** | Microsoft DART, Legal/Privacy (HIPAA breach assessment), cyber insurer, FBI/IC3; OFAC review before any payment | AWS CIRT; same |

**Decision points**

| Situation | Decision |
|---|---|
| Attacker holds Global Admin / Owner and is active | Contain everything immediately, accepting business disruption |
| Production SP is compromised | Disable it rather than rotating in place (the attacker may read the new secret) |
| Entra Connect server is compromised | Pause sync |
| A lifecycle deletion rule is set | Capture the config, then remove it immediately |

---

## 7. Tabletop Exercise

### Roles

| Role | Responsibility |
|---|---|
| Facilitator | Delivers injects, keeps time |
| Incident Commander | Owns decisions |
| Cloud Security / IR | Investigation and containment |
| Identity | Entra / AD containment |
| Cloud Ops | Resources and backups |
| Legal / Privacy | Breach determination, notifications |
| Comms | Internal and external messaging |
| Executive | Business impact, ransom decisions |
| Scribe | Timeline and decision log |

### Scenario (Storm-0501-style, hybrid Azure)

| Inject | Time | Event | Discussion |
|---|---|---|---|
| 1 | T+0 | Defender for Identity: DCSync from a non-DC host | Is the Entra Connect server in scope? |
| 2 | T+2h | Sync account signs in from an unfamiliar IP; mass Graph enumeration | Is the sync account restricted? |
| 3 | T+4h | A synced service account with Global Admin signs into the Azure portal | Why does a synced account hold GA? |
| 4 | T+4.5h | `elevateAccess`; Owner on 40 subscriptions; new federated domain | What do we contain first? Who has authority? |
| 5 | T+6h | `listKeys` on PHI storage; 2 TB AzCopy via a private endpoint in the firewall-bypass subnet | Why didn't the firewall see it? Is this reportable? |
| 6 | T+7h | Backup soft delete disabled; locks and storage accounts deleted | Are backups immutable? What are our RTO/RPO? |
| 7 | T+8h | Ransom demand via Teams | How do we communicate now? Who decides on payment? |
| 8 | T+24h | A reporter calls | What do we say, and who approves it? |

**Alternate scenarios:**
- Codefinger-style AWS: tests S3 data events, key hygiene, versioning
- SaaS OAuth extortion: tests app governance and breach notification
- Agentic AI destruction: tests automated containment and SP least privilege

### Prep Checklist

- [ ] Tier-0 inventory: Global Admins, Entra Connect servers, break-glass accounts, Owners at root/management group
- [ ] Data-plane logging status on PHI/PII storage
- [ ] Backup immutability and the date of the last test restore
- [ ] SPs with Owner/Contributor at subscription scope or higher
- [ ] Tested containment runbooks / SOAR playbooks
- [ ] Out-of-band comms plan and offline contact list
- [ ] Legal notification timelines
- [ ] Microsoft DART, AWS CIRT, insurer, and IR firm contacts

---

## 8. Key Questions

**Detection**
1. Would we detect `elevateAccess`, a new federated domain, or Owner at root scope? How fast, and who gets paged?
2. Is data-plane logging on for every sensitive storage account and bucket?
3. Can an attacker with Global Admin / Owner delete our logs?
4. Do we monitor service principal sign-ins?
5. Which egress paths bypass the firewall?

**Identity**
1. How many standing Global Admins do we have? Are any synced or lacking phishing-resistant MFA?
2. Is the Entra Connect server treated as tier-0, and is the sync account restricted by CA?
3. Which SPs hold Owner/Contributor at subscription scope?
4. How does the help desk verify identity before an MFA reset?
5. Do we have long-lived AWS access keys or client secrets?

**Data & Backups**
1. Is shared key access disabled? Are SSE-C and encryption scopes governed?
2. Are soft delete, versioning, locks, and Key Vault purge protection enabled on critical resources?
3. Are backups immutable and outside the reach of a compromised Global Admin?
4. When was the last full test restore, and did it meet RTO?

**Response**
1. Who can disable a production SP or pause sync at 2 AM?
2. Can we contain all identities at the same time?
3. How do we communicate if Teams and email are compromised?
4. Could we contain a machine-speed (AI-driven) attack?

**Legal & Business**
1. When does this become a reportable breach (HIPAA, state law), and who decides?
2. What is our ransom payment position, and who decides? Have we planned for an OFAC sanctions check?
3. What does our cyber insurance require?
4. What does an hour of downtime cost for critical systems?

**Third Parties & AI**
1. Which vendors and OAuth integrations can reach our data, and how fast can we revoke them?
2. Do pipelines use short-lived credentials?
3. Do we have an inventory of AI apps and agents? Are any internet-exposed?
4. Can we disable a malicious AI agent identity quickly?

---

## 9. References

- **Storm-0501:** [BleepingComputer](https://bleepingcomputer.com/news/security/storm-0501-hackers-shift-to-ransomware-attacks-in-the-cloud), [The Hacker News](https://thehackernews.com/2025/08/storm-0501-exploits-entra-id-to.html), [SecurityWeek](https://www.securityweek.com/ransomware-group-exploits-hybrid-cloud-gaps-gains-full-azure-control-in-enterprise-attacks/)
- **Codefinger:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ransomware-abuses-amazon-aws-feature-to-encrypt-s3-buckets/), [Help Net Security](https://www.helpnetsecurity.com/2025/01/13/codefinger-encrypting-aws-s3-data-without-ransomware-sse-c/)
- **M&S / Scattered Spider:** [Help Net Security](https://www.helpnetsecurity.com/2025/04/29/marks-spencer-ransomware-breach-incident/), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news-features/how-uk-retail-responded-hack-wave/)
- **Salesforce / Salesloft Drift:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/salesloft-breached-to-steal-oauth-tokens-for-salesforce-data-theft-attacks/), [Krebs on Security](https://krebsonsecurity.com/2025/09/the-ongoing-fallout-from-a-breach-at-ai-chatbot-maker-salesloft/)
- **JadePuffer / Storm-3168:** [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/), [BleepingComputer](https://bleepingcomputer.com/news/security/jadepuffer-ransomware-used-ai-agent-to-automate-entire-attack)
- NIST SP 800-61 Rev. 3 · [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
