# Hardening (M8)

Baseline and re-assessment with **PingCastle 4.0.0.20** (`--healthcheck`). Reports: [`reports/pingcastle/baseline-2026-10-06.html`](../reports/pingcastle/baseline-2026-10-06.html) and [`reports/pingcastle/after-hardening-2026-10-07.html`](../reports/pingcastle/after-hardening-2026-10-07.html).

## Result

| PingCastle score (0 best, 100 worst) | Baseline | After hardening | After patching + LAPS |
|---|---|---|---|
| **Global** | **55** | 20 | **10** |
| Stale objects | 50 | 10 | 10 |
| Privileged groups | 50 | 0 | **0** |
| Trusts | 0 | 0 | 0 |
| Anomalies | 55 | 20 | **5** |

17 findings fixed, none introduced. All 27 live detection tests pass after hardening and again after patching. Reports: `baseline-2026-10-06`, `after-hardening-2026-10-07`, `after-laps-2026-10-07` in `reports/pingcastle/`.

## Patching and Windows LAPS

- **DC01 patched** from build 20348.587 (original evaluation ISO, ~3.5 years of missing updates) to **20348.5622** (2026-09 cumulative update) with `scripts/windows/Invoke-LabWindowsUpdate.ps1`. Three passes, one reboot, ~1 GB downloaded. The Windows Update API refuses remote sessions, so the script runs as a one-shot SYSTEM task.
- **Windows LAPS** (`scripts/host/Enable-LabLAPS.ps1`): schema extended, computers in the Workstations and Servers OUs may write their own password, and GPO **LAB - Windows LAPS** sets AD backup, **encryption in AD** (decryptable by Domain Admins only), 20 characters, full complexity and 30-day rotation.
- Verified from DC01 with metadata only: WS01's local Administrator password was backed up encrypted, `DecryptionStatus: Success`, authorized decryptor `FTOU7\Domain Admins`, expires after 30 days.
- **Lesson:** `Update-LapsADSchema` fails over the lab's key-based SSH logon ("insufficient access rights"), because that logon has no network credentials for the cmdlet's own LDAP connection. The schema step was run by Fathia in an interactive DC01 session. Administrator was in Schema Admins only for that step, and both the add and the removal were caught by rules 100500 / 100502.

## What was changed

All changes are scripted and idempotent. Snapshots `03-pre-hardening` (DC01) and `pre-hardening` (WS01) were taken first.

| PingCastle rule | Pts | Fix | How |
|---|---|---|---|
| P-Delegated | 20 | Admin accounts marked "sensitive and cannot be delegated" | `Invoke-ADHardening.ps1` |
| S-OldNtlm | 15 | LAN Manager auth level 5: NTLMv2 only, LM/NTLMv1 refused | `New-LabSecurityBaselineGPO.ps1` (GptTmpl.inf) |
| P-ProtectedUsers | 10 | `adm.amira` added to Protected Users | `Invoke-ADHardening.ps1` |
| P-RecycleBin | 10 | AD Recycle Bin enabled (irreversible by design) | `Invoke-ADHardening.ps1` |
| A-MinPwdLen | 10 | Domain minimum password length 7 → 14 | `Invoke-ADHardening.ps1` |
| A-DC-Spooler | 10 | Print Spooler stopped and disabled on DC01 | `Invoke-ADHardening.ps1` |
| S-AesNotEnabled | 10 | AES-only (`msDS-SupportedEncryptionTypes = 24`) on the 3 accounts with SPNs | `Invoke-ADHardening.ps1` |
| A-AuditDC | 10 | Added DPAPI Activity and Sensitive Privilege Use auditing | `New-LabAuditPolicyGPO.ps1` |
| P-SchemaAdmin | 10 | Schema Admins emptied (re-add only for a schema change) | `Invoke-ADHardening.ps1` |
| S-ADRegistration | 10 | `ms-DS-MachineAccountQuota` 10 → 0 (only admins join computers) | `Invoke-ADHardening.ps1` |
| A-HardenedPaths | 5 | SYSVOL / NETLOGON require mutual authentication and integrity | `New-LabSecurityBaselineGPO.ps1` |
| S-DC-SubnetMissing | 5 | 192.168.145.0/24 declared in Sites and Services | `Invoke-ADHardening.ps1` |
| A-NoServicePolicy | 0 | `PSO-ServiceAccounts` (20+ chars) on `GG-ServiceAccounts` | `Invoke-ADHardening.ps1` |
| P-UnprotectedOU | 0 | Domain Controllers OU protected from accidental deletion | `Invoke-ADHardening.ps1` |
| A-NoGPOLLMNR | 0 | LLMNR disabled | `New-LabSecurityBaselineGPO.ps1` |
| A-AuditPowershell | 0 | PowerShell module logging (all modules) | `New-LabAuditPolicyGPO.ps1` |

Verification: `Test-LabAuditPolicy.ps1` and `Test-LabSecurityBaseline.ps1` report OK on DC01 and WS01. After a reboot, DC01 passed dcdiag (Services, Advertising, SysVolCheck, NetLogons, KnowsOfRoleHolders) and WS01's secure channel was intact.

### SIEM hardening

- **Wazuh agent enrollment now requires a password** (`scripts/wazuh/enable_enrollment_password.sh`). Before, any host on the network could register as an agent. The password is random, readable only by root/wazuh in `/var/ossec/etc/authd.pass`, and was never displayed. Existing agents were unaffected.

## Review 2026-10-08: lab hygiene fixes

A full review of the lab and repo found issues that PingCastle does not check:

| Finding | Risk | Fix |
|---|---|---|
| `C:\LabScripts` / `C:\LabBackups` on WS01 were **Modify for Authenticated Users**; on DC01 `C:\LabScripts` / `C:\LabMedia` let **Users create files**. Folders made directly under `C:\` inherit the root's defaults. | Any signed-in user could plant or swap a script that an admin or a SYSTEM task later runs (privilege escalation, CWE-732), or read the Security log backups. | `scripts/windows/Protect-LabFolders.ps1`: Administrators + SYSTEM only, inheritance removed, ownership reset. The scripts that create these folders now lock them at creation. |
| `Initialize-DC01.ps1` staged its SYSTEM task script under a **predictable name** in `C:\Windows\Temp`. | A user could pre-create that file and keep control of it. Negligible on a fresh server, wrong pattern anyway. | Random file name; the script deletes itself before the reboot. |
| Wazuh server accepted **SSH passwords** and had **no host firewall**. | Password guessing from the lab network; API (55000) reachable from every lab host. | `scripts/wazuh/harden_server.sh`: key-only SSH, `PermitRootLogin no`; ufw allows only 22/443/1514/1515 from 192.168.145.0/24. Verified: key login OK, password login refused, agents active, dashboard up, 55000 closed to the network. |
| `Deploy-WazuhConfig.ps1` pushed **agent group configs without validation**. | A typo would reach every agent in the group. | Every `agent.conf` is now checked with `verify-agent-conf` before anything is installed. |
| **Sensitive Privilege Use** (4673/4674) was ~30% of all DC01 events and ~16% on WS01. | Noise and storage for little value. | Moved to a new DC-only GPO **LAB - DC Audit Policy** (linked to the Domain Controllers OU, higher precedence). The domain-wide GPO sets it to No Auditing for workstations. DPAPI Activity stays on everywhere (quiet, high value). |

## Remaining findings

| Rule | Pts | Decision |
|---|---|---|
| S-NoPreAuth | 5 | **Accepted (intentional).** `svc_scanner` is lab content for credential-attack detection testing. Fix later with `Set-ADAccountControl svc_scanner -DoesNotRequirePreAuth $false`. |
| S-OS-W10 | 5 | **Accepted.** Windows 10 is out of support; a Windows 11 Enterprise evaluation VM would replace it in a real environment. |
| A-NotEnoughDC | 5 | **Accepted.** A second DC does not fit in the host's RAM. |

## Decisions

- **Built-in Administrator stays out of Protected Users.** It is the break-glass account and the lab automation account; Protected Users would block NTLM fallback and cached logons for it. PingCastle no longer flags P-ProtectedUsers with only `adm.amira` added.
- **Domain lockout policy left unchanged** for now (threshold 0). Enabling it is planned together with the credential-attack detections, so its effect can be measured.

## Detected during hardening

The hardening run itself showed up in Wazuh, as it should:

- Administrator removed from Schema Admins → **100502** (custom) and 60166 (level 12)
- Admin accounts marked non-delegable → 60110 "User account changed" (8) ×2
- Audit policy applied by GPO on DC01 and WS01 → 60112 (8), kept at default level by design

**False positives from the lab's own tooling:** on WS01, default Sysmon rules 92057 (level 12, "PowerShell executed a base64 encoded command") and 92213 (level 15, "Executable file dropped in folder commonly used by malware") fired on lab automation. `Invoke-LabCommand.ps1` sends scripts with `-EncodedCommand`, and PowerShell writes `__PSScriptPolicyTest_*` files to Temp on start. Tuning is in the backlog.
