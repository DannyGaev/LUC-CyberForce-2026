# Windows Defense (AD, Mail/File, HMI)

Scripts for the three Windows boxes. Everything here was prepared **before** the competition
(AI-assisted prep is allowed; AI for live defense is not). Webhook URLs and passwords are **never**
stored in this repo. They live in the documentation channel and the Credentials sheet.

| Box | Hostname | IP | Type |
|---|---|---|---|
| AD (Win 2022) | AD | 10.0.15.141 | Traditional, scored: LDAP 389/tcp, SNMP 161/udp |
| Mail/File (Win 2019) | IP-0A000F8C | 10.0.15.140 | Traditional, scored: SMTP 25, HFS 1080 |
| HMI (Win 2019) | IP-0A000F8E | 10.0.15.142 | **Assume Breach: watch and report only, no hardening** |

---

## Files

| File | What it does | Runs how |
|---|---|---|
| `CF-WinDefense.ps1` | Hands-on toolkit: snapshot the box, find problems, harden, hunt | By a person (first 15 min, then when an alert says "go look") |
| `CF-WinRelay.ps1` | Alerts to Discord + automated audit + log export | 3 scheduled tasks, always on |
| `yara-scan.ps1` | YARA scan of drop folders every 10 min | Scheduled task `CF YARA Scan` |
| `CF-MailBait.ps1` | Turns the Mail canary into a bait-password trap | Once, on Mail only |

All of them are **report-only on HMI**. CF-WinDefense detects HMI (Ignition installed or its hostname)
and refuses every change there.

---

## CF-WinRelay.ps1: Windows to Discord

Installs to `C:\Tools\cfrelay\relay.ps1`. Data and state live in `C:\CF\relay\`. Both folders are locked
to Administrators and SYSTEM. Three scheduled tasks run as SYSTEM at low priority:

| Task | Every | Posts to | What |
|---|---|---|---|
| System Health Relay | 1 min | Machines/`<box>` + early-warning/`rdp` | New events: **LOOK NOW** and **EARLY WARNING** |
| System Health Check | 5 min | Machines/`<box>` | Automated audit: anything **new** since the last check |
| System Health Archive | 15 min | logs/`<box>` | Readable `.log` files of key events; full `.evtx` zip kept on the box |

**LOOK NOW** (machine channel). Each alert says what happened, when (UTC), who, and where:
- Canary account logged in, canary file opened, **bait password used** (Mail)
- Suspicious programs: a service (HFS, mail, Tomcat, Java, SQL) starting a shell (web shell), base64 or
  encoded PowerShell, hidden PowerShell with a policy bypass, programs or scripts run from Temp, AppData,
  Public, or the ProgramData root, and watched tools (certutil, bitsadmin, mshta, psexec, nc, wmic, whoami...)
- PowerShell's own "suspicious script" flag, with the script text (PowerShell's auto-generated module code is filtered out)
- New users, enabled users, password resets, group membership adds, new services, new scheduled tasks
- Security or System log cleared, audit policy changed, Defender detection, Defender turned off or an exclusion added
- **Trap files** appearing: `C:\Windows\Temp\ignition_ui.ps1` (HMI) and `C:\Scripts\fixsmartermail.ps1` (Mail).
  SYSTEM tasks run these at logon and the files don't exist, so if one shows up, someone is building a backdoor.
- New YARA hits
- **Intruder profile:** an RDP login from a non-team IP, or any canary login, posts their IP, their machine
  name, RDP client name, auth type, who is on the box, and their connections. After that, **every program
  they run in that session for 60 minutes** is posted (SESSION FEED).

**EARLY WARNING** (`early-warning/rdp` channel). Signs red team is getting ready:
- Kerberoasting (RC4 ticket for a service account, or any ticket for the canary SPN)
- AS-REP roasting (ticket for an account without pre-auth)
- Failed logons to admin accounts, password spraying (one IP, 4+ users), brute force (5+ failures/min),
  Kerberos password failures, lockouts, any touch of the canary
- Each one says **why it failed** ("right username, WRONG password" vs "username does not exist"), the
  attacker's machine name, and how they tried (RDP or network).

**LIFELINE** (every minute, part of System Health Relay). This keeps **our** RDP access working.
- **Every box:** a LOOK NOW alert when a firewall rule is added, changed, or deleted, or a firewall profile setting changes (who did it and with what program).
- **AD and Mail auto-fix:** RDP turned off (registry or policy), the RDP port moved off 3389, the Remote Desktop
  service stopped or disabled, a firewall profile turned off, someone else's block rule covering 3389
  (rules named `CF *` are ours and are left alone), our `CF Allow In RDP` rule removed or disabled, and
  `blueteam`/`bt_recovery` disabled. Each fix is posted as **LIFELINE - AUTO-FIXED** and logged to `C:\CF\relay\lifeline.log`.
- **HMI:** the same checks, **alert only**, never fixed.
- It can't undo a **password change**. That's what the break-glass account is for.

### Break-glass admin (`bt_recovery`)
A second admin on AD (domain, Domain Admins) and Mail (local Administrators). Its long random password is
kept **only** in the Credentials sheet. Use it if red team changes the blueteam password. Not on HMI.

**System Health Check** (the automated version of CF-WinDefense's Audit) posts anything new in:
admin group members, enabled users, services and **auto-start services**, scheduled tasks, Run keys,
startup folders, WMI persistence, listening ports, and **port forwards** (`netsh interface portproxy`).
It also posts when a **scored port stops listening** (and when it comes back), and when someone tampers with
our monitoring. If Sysmon is stopped, it restarts it. If our tasks are disabled, it re-enables them. If our
relay tasks are deleted, it re-creates them.

### Install / update

```powershell
# install (each box; use that box's webhooks; copy/paste URLs, don't retype them)
cd C:\Tools; Unblock-File .\CF-WinRelay.ps1
.\CF-WinRelay.ps1 -Mode Install -AlertWebhook '<General box>' -LogWebhook '<Logging box>' -EarlyWebhook '<RDP early-warning>'

# update an installed box (keeps webhooks)
Copy-Item .\CF-WinRelay.ps1 C:\Tools\cfrelay\relay.ps1 -Force
C:\Tools\cfrelay\relay.ps1 -Mode Install-Tasks

# other modes
C:\Tools\cfrelay\relay.ps1 -Mode Status      # tasks, webhooks (masked), baseline size
C:\Tools\cfrelay\relay.ps1 -Mode Test        # test message to both channels + one log export
C:\Tools\cfrelay\relay.ps1 -Mode SetEarly -EarlyWebhook '<url>'
C:\Tools\cfrelay\relay.ps1 -Mode Uninstall
Remove-Item C:\CF\relay\snapshot.txt           # reset the drift baseline (next check re-captures it)
```

**If red team removes it:** copy `CF-WinRelay.ps1` back to `C:\Tools` and run the Install line again
(about 1 minute per box).

---

## CF-WinDefense.ps1: hands-on toolkit

Output goes to `C:\CF\<HOSTNAME>\`: `changes.log` (every change, with its undo command), findings, snapshots, quarantine.

| Mode | Use |
|---|---|
| `Baseline` | Snapshot users, groups, services, tasks, Run keys, ports, firewall... (first 2 minutes) |
| `Audit` | Flag risky settings and persistence (HIGH / MED / INFO) |
| `Compare` | Diff against the baseline |
| `Harden` | Menu of hardening items, each confirmed one at a time and logged. `safe` = 1,2,4,5,6,7,8,9,12,13,15,16,17,22 |
| `Hunt` | Look for active intrusion (web shells, odd parents, LSASS access, new admins, encoded PowerShell...) |
| `Watch` | Live loop that prints new suspicious events every N seconds |
| `Load` | Dot-source the helpers: `Block-CFIP`, `Stop-CFProc`, `Move-CFQuarantine`, `Remove-CFWmiPersistence` |

Rules built in: never touch SCORE1/SCORE2/PATCH, block **single IPs only** (no subnets, no allow-lists),
no changes on HMI. Our own tasks and the canary are labeled "OURS, leave it" in Audit output.
Harden option 1 keeps the SmarterMail Defender exclusions. Option 21 asks before replacing the team's Sysmon config.
Option 22 blocks outbound network access for download tools (certutil, mshta, regsvr32, bitsadmin, hh, wscript, cscript).

---

## yara-scan.ps1

YARA (VirusTotal release) with the YARA Forge **core** rules compiled to `C:\Tools\yara\core.yarc`.
It scans Temp, Public, `C:\Scripts`, `C:\inetpub`, `C:\Shares`, startup folders, and each user's
Desktop/Downloads/Documents/Temp. It skips files over 20 MB and takes about 18-30 seconds. Hits go to
`C:\CF\yara\hits.log` (`time UTC | box | rule path`), which the relay posts. Known false positive:
`CAPE_Risepro` on Sysinternals `handle.exe`. HMI runs it with `-p 1` at low priority.

```powershell
cd C:\Tools\yara; .\yarac64.exe -w '<rules>\yara-rules-core.yar' C:\Tools\yara\core.yarc
icacls C:\Tools\yara /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
$a  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\Tools\yara\yara-scan.ps1'
$tr = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'CF YARA Scan' -Action $a -Trigger $tr -User SYSTEM -RunLevel Highest
```

---

## Deception (ours, do not "clean up")

- `svc_backup_old` on **AD** (domain account): random unknown password plus a fake SPN, so any Kerberoast
  or login attempt alerts.
- `svc_backup_old` on **Mail** (local account): denied every logon type. Its bait password is in
  `C:\Shares\IT_passwords_old.txt` on the HFS share. Using it gives **no access** but fires a LOOK NOW alert
  (status `0xC000015B`). Set up with `CF-MailBait.ps1 -BaitPass '<from Credentials sheet>'`.
- `C:\Shares\IT_passwords_old.txt` has read auditing on (Event 4663). Reads by YARA and Defender are ignored.

---

## Verify before running on Saturday

Run `Get-FileHash <file>` on the box and compare it to the hash in the team notes. **If it differs, don't
run it.** Copy a fresh one from this repo instead.

## Evidence capture (pktmon)

```powershell
pktmon filter add -i <IP>        # or -p <port>
pktmon start --capture --pkt-size 0 --file-name C:\CF\evidence.etl
pktmon stop
pktmon etl2pcap C:\CF\evidence.etl --out C:\CF\evidence.pcapng
pktmon filter remove
```
Keep captures short and filtered on HMI.
