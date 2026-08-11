# Initial detections

Confidence is a documented score: `0.5 + source_quality(0–0.2) + rule_strength(0–0.2) + context(0–0.1)`, capped at 0.99. Tune thresholds per tenant and preserve the inputs.

## Required detections

| Name | Data sources | Logic (pseudo-rule) | Severity / ATT&CK |
|---|---|---|---|
| Brute force followed by successful login | Entra, VPN, firewall, Windows | `>=5 failures(actor,ip) in 10m` then success same actor within 15m | High; T1110, T1078 |
| Impossible-travel login | Entra/M365 identity | Two successful logins for user whose geodesic speed exceeds policy, excluding trusted VPN/proxy | High; T1078 |
| New administrator account | Entra, Windows, IAM | Account creation followed by admin-role assignment outside approved change window | High; T1136.002 |
| Privilege escalation | Windows, cloud, IAM, EDR | Privilege/role increase or exploit signal followed by privileged resource access | Critical; T1068, T1548 |
| Suspicious PowerShell | Windows/EDR | Encoded/download/hidden PowerShell or unusual parent/child chain | High; T1059.001 |
| New scheduled task | Windows | New task with user-writable path, encoded command, or unusual creator | High; T1053.005 |
| Disabled antivirus | EDR/Windows | AV/EDR protection disabled or exclusions added, absent approved change | High; T1562.001 |
| Firewall configuration change | Firewall/cloud network | Rule/ACL/NAT change by unusual actor or broadens exposure | High; T1562.004 |
| Unusual data transfer | Firewall/proxy/cloud/storage | Egress volume or destination z-score above baseline and sensitive asset involved | High; T1041 |
| Compromised account accesses critical asset | Identity, events, assets | High-confidence compromise signal then first/rare access to critical service | Critical; T1078 |

For each detection, the operational template is below.

### 1. Brute force followed by successful login

- **Description:** Repeated failures followed by success can indicate password attack and account compromise.
- **Required data sources:** Entra ID/M365, VPN, firewall, Windows authentication.
- **Logic:** Group by actor/IP; five failures in ten minutes, then success within fifteen; suppress known test users and approved scanners.
- **Severity/confidence:** High; base 0.5 plus source quality, consecutive sequence, and privileged/critical target context.
- **ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts).
- **False positives:** Shared NAT, password manager retries, service accounts; use device, ASN, and approved source context.
- **Investigation:** Verify MFA/device/IP, preceding failures, account changes, and critical-resource access.
- **Response:** Step-up MFA/password reset recommendation, session revocation, analyst/customer approval before disablement.
- **Test events:** Six failed VPN logins then success from same IP; approved scanner control.

### 2. Impossible-travel login

- **Description:** Successful logins from locations impossible to reach within elapsed time.
- **Required data sources:** Entra sign-ins, identity geography, VPN/proxy allow-list.
- **Logic:** Compare consecutive successful events; flag speed above policy and no trusted egress explanation.
- **Severity/confidence:** High; increase for MFA failure, new device, or privileged identity.
- **ATT&CK:** T1078.
- **False positives:** Corporate VPN egress, mobile networks, clock error; suppress trusted egress and require corroboration.
- **Investigation:** Review device IDs, MFA, token/session history, and user confirmation.
- **Response:** Revoke sessions and reset credentials after approval; add trusted egress only after verification.
- **Test events:** Fiji and Europe sign-ins five minutes apart; VPN egress control.

### 3. New administrator account

- **Description:** New identity gains administrative authority without an approved change.
- **Required data sources:** Entra/IAM, Windows, change-management records.
- **Logic:** `create_user -> assign_admin_role` within 30m and no matching approved change.
- **Severity/confidence:** High; critical for tenant/global/domain admin.
- **ATT&CK:** T1136.002 (Create Account: Domain Account).
- **False positives:** Joiner/mover/leaver automation and break-glass procedures.
- **Investigation:** Identify creator, source IP, consent/change ticket, subsequent actions.
- **Response:** Suspend new account and remove role only through approved workflow; preserve evidence.
- **Test events:** Unapproved user creation plus global-admin assignment; approved HR fixture.

### 4. Privilege escalation

- **Description:** A process or identity obtains authority beyond its baseline.
- **Required data sources:** EDR, Windows, cloud IAM, vulnerability context.
- **Logic:** Detect role/token/group elevation or exploit signal followed by privileged action.
- **Severity/confidence:** Critical; confidence increases with exploit telemetry and critical asset target.
- **ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control Mechanism).
- **False positives:** Admin maintenance, patching, approved automation.
- **Investigation:** Parent process, vulnerability, command line, identity, and change record.
- **Response:** Isolate endpoint or revoke session via approval; patch and collect forensic evidence.
- **Test events:** Non-admin process exploits vulnerable service then accesses admin-only object.

### 5. Suspicious PowerShell

- **Description:** PowerShell execution patterns associated with download, obfuscation, or bypass.
- **Required data sources:** Windows Security/PowerShell, EDR, proxy/DNS.
- **Logic:** Encoded command, hidden window, download cradle, or unusual parent plus network call.
- **Severity/confidence:** High; weight script block logging and EDR corroboration.
- **ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell).
- **False positives:** Signed IT automation; allow-list by publisher, path, and service identity.
- **Investigation:** Decode safely in sandbox, inspect parent, destination, user, and persistence.
- **Response:** Mock isolate/block and assign task; live action requires approval.
- **Test events:** `powershell -enc` plus outbound request; signed maintenance control.

### 6. New scheduled task

- **Description:** Persistence via a newly created or modified scheduled task.
- **Required data sources:** Windows Task Scheduler, EDR, process telemetry.
- **Logic:** New task from user-writable path, unusual creator, hidden trigger, or encoded command.
- **Severity/confidence:** High; weight unsigned binary and post-login creation.
- **ATT&CK:** T1053.005 (Scheduled Task/Job: Scheduled Task).
- **False positives:** Software installers and patch management.
- **Investigation:** Task XML, binary hash, creator, trigger, parent process, prevalence.
- **Response:** Disable task after approval, quarantine artifact, and preserve XML/hash.
- **Test events:** New hidden task executing `%TEMP%` binary; installer control.

### 7. Disabled antivirus

- **Description:** Security tooling is disabled or exclusions broadened.
- **Required data sources:** EDR/AV, Windows, endpoint management.
- **Logic:** Protection disabled or exclusion added, followed by suspicious process within 30m.
- **Severity/confidence:** High; critical when tamper protection is bypassed.
- **ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools).
- **False positives:** Approved maintenance windows and agent upgrades.
- **Investigation:** Actor, policy, endpoint state, follow-on process, change approval.
- **Response:** Restore policy/agent through approved adapter; isolate if corroborated.
- **Test events:** Exclusion added then unsigned PowerShell; maintenance control.

### 8. Firewall configuration change

- **Description:** Network policy changes can create exposure or permit command and control.
- **Required data sources:** Firewall/cloud network audit, change management.
- **Logic:** New broad allow rule, disabled inspection, or NAT change by unusual actor.
- **Severity/confidence:** High; increase for internet-facing critical assets.
- **ATT&CK:** T1562.004 (Impair Defenses: Disable or Modify System Firewall).
- **False positives:** Approved releases and network maintenance.
- **Investigation:** Diff before/after, actor, target, ticket, traffic after change.
- **Response:** Preview rollback and require network owner approval.
- **Test events:** `0.0.0.0/0` inbound allow to critical host; approved change control.

### 9. Unusual data transfer

- **Description:** Egress materially exceeds a baseline or reaches a rare destination.
- **Required data sources:** Firewall/proxy, cloud storage, asset criticality/classification.
- **Logic:** Volume/destination rarity above tenant baseline and source holds sensitive data.
- **Severity/confidence:** High; weight confirmed archive/encryption and identity compromise.
- **ATT&CK:** T1041 (Exfiltration Over C2 Channel).
- **False positives:** Backups, replication, software updates; baseline known jobs.
- **Investigation:** Destination ownership, files/classification, process, user, timing.
- **Response:** Preserve logs, propose block/quarantine, and obtain customer approval.
- **Test events:** Critical database sends 10× baseline to new external IP; backup control.

### 10. Compromised account accesses a critical asset

- **Description:** A compromised identity reaches a high-business-impact service.
- **Required data sources:** Identity, alerts, assets/business services, application logs.
- **Logic:** Compromise alert within 24h then rare access to critical asset or service.
- **Severity/confidence:** Critical; combine compromise confidence, asset criticality, and access rarity.
- **ATT&CK:** T1078.
- **False positives:** Break-glass/admin access with documented approval.
- **Investigation:** Session/device, accessed objects, lateral movement, owner confirmation.
- **Response:** Revoke sessions and protect critical asset after approval; open incident.
- **Test events:** Confirmed phishing-compromise event then first database-admin access.

## Backlog from the plan

Unusual login location; malware alert followed by lateral movement; unusual service-account activity; vendor-specific firewall/EDR; cloud privilege escalation; application/database audit; and correlation across identity, endpoint, network, and business context.
