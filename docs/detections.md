# Detections

Custom Wazuh rules live in [`rules/ad_identity_rules.xml`](../rules/ad_identity_rules.xml) (ID range 100500–100599) and are deployed with `scripts/host/Deploy-WazuhConfig.ps1`, which validates the ruleset before restarting the manager.

## Summary

| Suite | Rules | Live tests | Last run |
|---|---|---|---|
| Privileged group membership changes | 100500–100505 | 10/10 | 2026-10-07 |
| DC and logging tampering | 100510–100516 | 8/8 | 2026-10-07 |
| Privileged account lifecycle | 100520–100525 | 9/9 | 2026-10-07 |
| False-positive tuning | 100530–100535 | 11/11 (+1 control) | 2026-10-08 |

Run any suite end to end from the host: `scripts/host/Invoke-DetectionTests.ps1 -Suite <privileged_groups|dc_tampering|account_changes>`. It runs the suite's test script(s) on the VMs, then `scripts/wazuh/check_test_alerts.py` compares the alerts with `tests/<suite>.expect.json`. Every test change is reverted by the test script itself.

### How tests are built

`wazuh-logtest` cannot decode Windows Event Channel events (an internal decoder only applies to agent traffic), so every rule is tested **live**: a script performs the real, harmless action on a lab VM and the checker verifies which rule and level Wazuh produced. Each suite includes **negative tests** that confirm ordinary activity stays at the default level.

## Privileged group membership changes — MITRE ATT&CK T1098 (Account Manipulation)

**Why it matters:** adding an account to a group such as Domain Admins or Backup Operators is one of the most direct ways to gain lasting control of a domain, and one of the most common steps after an account is compromised.

**What Wazuh already does:** the default ruleset alerts on about 40 well-known groups (rules 60154–60193), e.g. 60159 Domain Admins (level 12). Those alerts are titled "... Group Changed" for both additions and removals, and name neither the member nor the person who made the change.

**What the custom rules add:**

| Rule | Level | Fires when | Built on |
|---|---|---|---|
| 100500 | 12 | Member **added** to a tier-0 / high-impact group, with member and actor in the title | 60154, 60159, 60164, 60166, 60167, 60168, 60173–60176 |
| 100502 | 8 | Member **removed** from one of those groups | same |
| 100501 | 12 | Member added to **DnsAdmins** (no well-known SID, no default rule) | 60144 |
| 100503 | 8 | Member removed from DnsAdmins | 60145 |
| 100505 | 14 | A privileged group was changed by an account **outside the approved admins** (FTOU7\Administrator, FTOU7\adm.amira), matched **by SID** | 100500, 100501 |

Groups are matched by SID wherever possible, so the rules keep working on non-English systems and after a group is renamed.

### Testing

`wazuh-logtest` cannot decode Windows Event Channel events (they use an internal decoder that only applies to events arriving from agents), so the rules are tested **live**:

1. `scripts/windows/Invoke-PrivGroupTests.ps1` on DC01 makes 10 real membership changes and reverts each within seconds. The last two run as SYSTEM, so they are logged under the DC's machine account `DC01$`.
2. `scripts/wazuh/check_test_alerts.py` on the Wazuh server matches each change to the alert it produced.

**Result 2026-10-06: 10/10 passed.**

| # | Change | Actor | Expected | Result |
|---|---|---|---|---|
| 1 | omar.chaabane → Backup Operators (add) | Administrator | 100500 / 12 | PASS |
| 2 | omar.chaabane → Backup Operators (remove) | Administrator | 100502 / 8 | PASS |
| 3 | sami.dridi → Domain Admins (add) | Administrator | 100500 / 12 | PASS |
| 4 | sami.dridi → Domain Admins (remove) | Administrator | 100502 / 8 | PASS |
| 5 | omar.chaabane → DnsAdmins (add) | Administrator | 100501 / 12 | PASS |
| 6 | omar.chaabane → DnsAdmins (remove) | Administrator | 100503 / 8 | PASS |
| 7 | omar.chaabane → GG-Sales (add) — negative test | Administrator | 60141 / 5 (default) | PASS |
| 8 | omar.chaabane → GG-Sales (remove) — negative test | Administrator | 60142 / 5 (default) | PASS |
| 9 | omar.chaabane → Backup Operators (add) | DC01$ (SYSTEM) | 100505 / 14 | PASS |
| 10 | omar.chaabane → Backup Operators (remove) | DC01$ (SYSTEM) | 100502 / 8 | PASS |

Raw sample events from the first round of tests are kept in `tests/events/privileged_groups/` (exported with `scripts/wazuh/export_events.py`) for reuse in a detection-as-code pipeline.

### Tuning notes

- The approved-admin list is inline in rule 100505 and matches **SIDs**, not names (changed 2026-10-08). Names can be renamed, and every machine has a local account called "Administrator", which a name-based allowlist would have trusted. With more admins, move the SIDs to a Wazuh CDB list.
- If local Administrators membership is ever managed by GPO (Restricted Groups), those changes are made by the computer account and would trigger 100505. Add the expected machine accounts to the allowlist in that case.

## DC and logging tampering — T1562.002, T1070.001, T1543.003, T1053.005

**Why it matters:** attackers who reach a domain controller often turn auditing off, clear logs, or add a service or scheduled task to keep their access. The defaults alert on most of these at low levels (4–9) and never consider *where* it happened.

| Rule | Level | Fires when | Built on |
|---|---|---|---|
| 100510 | 12 | Audit policy changed on a DC by a **user** account (4719) | 60112 (8) |
| 100512 | 13 | Security log cleared on any host (1102) | 60117 / 63103 |
| 100513 | 10 | Any other event log cleared (104), names the log | 63104 (5) |
| 100514 | 12 | Service installed on a DC (4697, names the installer) | 60103 (no default) |
| 100515 | 6 | Service installed on another host (4697) | 60103 (no default) |
| 100516 | 12 | Scheduled task created on a DC (4698) | 60228 (4) |

DCs are recognised by hostname (`DC<n>.`). With more DCs or a different naming scheme, use a CDB list.

**Tuning decision:** Group Policy applying audit settings also logs 4719, under the computer account (`DC01$`). Those events keep the default level 8 rather than being suppressed: an attacker running as SYSTEM produces exactly the same event, so silencing it would create a blind spot.

**Test results 2026-10-07: 8/8 passed** (`scripts/windows/Invoke-TamperTests-DC.ps1`, `Invoke-TamperTests-WS.ps1`). Logs are only cleared on WS01, after a backup to `C:\LabBackups\` (`wevtutil cl <log> /bu:<file>`), and their events were already in Wazuh.

| Test | Expected | Result |
|---|---|---|
| Audit policy changed on DC01 by Administrator | 100510 / 12 | PASS |
| Same change as SYSTEM (`DC01$`) | 60112 / 8 (default kept) | PASS |
| Service installed on DC01 | 100514 / 12 | PASS |
| Scheduled task created on DC01 | 100516 / 12 | PASS |
| Security log cleared on WS01 | 100512 / 13 | PASS |
| Windows PowerShell log cleared on WS01 | 100513 / 10 | PASS |
| Service installed on WS01 | 100515 / 6 | PASS |
| Negative: scheduled task on WS01 | 60228 / 4 (default) | PASS |

Lessons from building this suite: the log-clearing events keep their details under `win.logFileCleared.*`, and task names are stored with a doubled backslash (`\\LabTestTask`). `scripts/wazuh/show_events.py` prints the exact decoded field names of any event, which avoids guessing.

## Privileged account lifecycle — T1136.002, T1098

**Why it matters:** creating a new admin account, re-enabling a dormant one, or resetting an admin's password are quiet ways to gain or keep privileged access.

Admin accounts in this lab: objects in `OU=Admins,OU=FTOU7`, names starting `adm.`, and the built-in Administrator (RID 500).

| Rule | Level | Fires when | Built on |
|---|---|---|---|
| 100520 | 10 | Account object created in the Admins OU (5137) | 60230 (4) |
| 100521 | 10 | Admin-named account created (4720) | 60109 (8) |
| 100522 | 12 | Admin-named account enabled or re-enabled (4722) | 60109 (8) |
| 100524 | 12 | Built-in Administrator (RID 500) enabled (4722) | 60109 (8) |
| 100523 | 10 | Password of an admin-named account reset (4724) | 60103 (no default) |
| 100525 | 10 | Password of the built-in Administrator reset (4724) | 60103 (no default) |

**Telemetry gap found and fixed:** DC01 logged attribute changes (5136) but never object creation (5137) in the lab OUs, because the default AD audit settings (SACLs) do not audit "create child" there. `scripts/windows/Set-LabDirectorySACL.ps1` adds an audit entry on `OU=FTOU7` (Everyone, Success, CreateChild + DeleteChild, inherited by all child OUs), which also makes object deletion (5141) visible.

**Test results 2026-10-07: 9/9 passed** (`scripts/windows/Invoke-AccountTests.ps1`, using a temporary `adm.testops` admin account and a `test.user` negative case, both deleted at the end).

| Test | Expected | Result |
|---|---|---|
| adm.testops object created in Admins OU (5137) | 100520 / 10 | PASS |
| adm.testops created (4720) | 100521 / 10 | PASS |
| adm.testops enabled / re-enabled (4722) | 100522 / 12 | PASS |
| adm.testops password reset (4724) | 100523 / 10 | PASS |
| adm.testops disabled (4725) | 60111 / 8 (default) | PASS |
| Negative: test.user object created (5137) | 60230 / 4 | PASS |
| Negative: test.user created (4720) | 60109 / 8 | PASS |
| Negative: test.user enabled (4722) | 60109 / 8 | PASS |
| Negative: test.user password set (4724) | no custom alert | PASS |

**Not live-tested on purpose:** 100524 and 100525 (built-in Administrator enabled or reset). Testing them would mean disabling and changing the domain's real Administrator account.

**Expected noise:** creating an enabled admin account produces 5137 + 4720 + 4724 (initial password) + 4722, so a single creation raises four alerts. A future improvement is to group them in the dashboard by `subjectLogonId`.

## False-positive tuning — 100530–100535

Once the lab behaved like a real environment (an interactive admin sign-in, Windows Update, LAPS), several rules fired on legitimate Windows activity. Over about two hours: 100514 ×18, 100516 ×11, 100525 ×1, plus the default Sysmon rules 92213 ×6 (level 15) and 92057 ×3 (level 12) on WS01.

**Principle: nothing is silenced.** No rule is set to level 0. Benign patterns are re-ranked to a low level under their own rule ID (still searchable), and every exclusion needs several fields to match at once. Fields were read from real alerts first (`scripts/wazuh/show_alert_fields.py`). Note: decoded Windows field values contain doubled backslashes, hence `\\+` in the path patterns.

| Rule | Level | Benign pattern | All of these must match |
|---|---|---|---|
| 100530 | 3 | Per-user service instances created at every interactive sign-in (`CDPUserSvc_25fab5`, …) | service type `0xd0`/`0xe0` (user service + instance bits), created by SYSTEM, name ends in `_<hex>` |
| 100531 | 3 | Microsoft Defender platform updates | created by SYSTEM, binary in `ProgramData\Microsoft\Windows Defender\Platform\<version>\` or `system32\drivers\wd\` |
| 100532 | **8** | Windows servicing tasks after updates | created by SYSTEM, task under `\Microsoft\Windows\`. **Lowered to medium only:** attackers also hide tasks there |
| 100533 | 3 | Explorer's task at an admin's interactive sign-in | task name exactly `\CreateExplorerShellUnelevatedTask` **and** action `C:\Windows\Explorer.EXE /NoUACCheck` (added 2026-10-08, so the name cannot be reused to hide another payload) |
| 100534 | 3 | Windows LAPS rotating the local Administrator password | reset by SYSTEM, on a non-DC host |
| 100535 | 3 | PowerShell's own execution-policy test file at every start | image `powershell.exe`/`pwsh.exe`, file `AppData\Local\Temp\__PSScriptPolicyTest_<8>.<3>.ps1` |

**Fixed the tool, not the rule:** rule 92057 ("PowerShell executed a base64 encoded command") fired on every call of the lab's SSH helper, which used `-EncodedCommand`. That is attacker tradecraft, so the rule stays untouched. `scripts/host/Invoke-LabCommand.ps1` now copies a script file to `C:\LabScripts\run\`, runs it in the existing SSH PowerShell session and deletes it. To allow local scripts, the "LAB - Security Baseline" GPO sets the execution policy to **RemoteSigned** (local scripts run, downloaded scripts must be signed).

**Test results 2026-10-07: 10/10 passed** (`Invoke-TuningTests-DC.ps1`, `Invoke-TuningTests-WS.ps1`). Each downgrade has a negative twin proving the suspicious variant still alerts at full severity:

| Test | Expected | Result |
|---|---|---|
| T1 Defender-path service created by SYSTEM | 100531 / 3 | PASS |
| T2 same path, created by Administrator | 100514 / 12 (still alerts) | PASS |
| T3 per-user service *template* (type 0x50) by Administrator | 100514 / 12 (still alerts) | PASS |
| T4 task `\Microsoft\Windows\LabTuneSys` by SYSTEM | 100532 / 8 | PASS |
| T5 task `\Microsoft\Windows\LabTuneAdm` by Administrator | 100516 / 12 (still alerts) | PASS |
| T6 `\CreateExplorerShellUnelevatedTask` running `Explorer.EXE /NoUACCheck` | 100533 / 3 | PASS |
| T6b same task name with a `cmd.exe` payload | 100516 / 12 (still alerts) | PASS |
| T8 `Reset-LapsPassword` (rotation by SYSTEM) | 100534 / 3 | PASS |
| T9 PowerShell start (policy-test file) | 100535 / 3 | PASS |
| T10 other `.ps1` dropped in Temp | 92213 / 15 (still alerts) | PASS |
| T11 deliberate harmless `-EncodedCommand` | 92057 / 12 (rule intact) | PASS |

**T7 control: Windows LAPS blocks manual resets.** Trying to set the LAPS-managed local Administrator password by hand (as a local admin) is refused with `STATUS_POLICY_CONTROLLED_ACCOUNT` (0xC000A08B, "The account is controlled by external policy and cannot be modified"). So the negative case for 100534 cannot occur on a LAPS-managed account; the test asserts the refusal instead.

**100530 verified with a real sign-in (2026-10-08):** An interactive DC01 console sign-in created 14 per-user service instances (`CDPUserSvc_100fcea`, `WpnUserService_100fcea`, …). All 14 landed at **level 3** (100530) instead of 12. The same sign-in produced the real `\CreateExplorerShellUnelevatedTask`, which matched the stricter 100533 (name + `Explorer.EXE /NoUACCheck`).

**Expected medium-level noise:** after reboots and updates, Windows re-registers servicing tasks on DC01 (`UpdateOrchestrator\MusUx_UpdateInterval`, `Defrag\ScheduledDefrag`, `Windows Defender Scheduled Scan`), which arrive as 100532 (level 8) by design.

**Regression:** all other suites re-run with the tuning rules loaded: 27/27 still pass (37/37 in total).