<#
  CF-WinRelay.ps1  -  Windows -> Discord alerting, early warning, drift checks, log export
  CyberForce 2026 (LUC team). Prepared before the competition.

  THREE KINDS OF MESSAGES
    LOOK NOW       (box's Machines channel)  something suspicious just happened - who, what, when, where
    EARLY WARNING  (early-warning channel)   signs red team is getting ready: kerberoasting, password
                                             guessing on admin accounts, password spraying, lockouts
    LOGS           (box's logs channel)      readable .log files every 15 min
    LIFELINE (every 1 min): keeps OUR RDP access working. On AD/Mail it auto-fixes RDP turned off (registry or
    policy), RDP port moved, Remote Desktop service stopped/disabled, firewall profile turned off, someone's block
    rule covering 3389, our 'CF Allow In RDP' rule removed/disabled, blueteam disabled. HMI: alert only.
    Firewall rule added/changed/deleted and profile changes are LOOK NOW alerts on every box.
    INTRUDER PROFILE + SESSION FEED: on a non-team RDP logon or a canary login, posts their IP, machine
    name, RDP client name, auth type, who is on the box, their connections - then every program they
    run in that session for the next 60 minutes. Bait-password use (Mail) is a LOOK NOW alert.

  SCHEDULED TASKS (all run as SYSTEM, low priority, report-only)
    System Health Relay    every 1 min   new events -> LOOK NOW / EARLY WARNING
    System Health Check    every 5 min   "automated Audit": new admins, users, services, tasks, Run keys,
                                         startup items, WMI persistence, listening ports, scored ports
                                         down, our monitoring tampered with (restores our relay tasks)
    System Health Archive  every 15 min  readable .log files to Discord + full .evtx zip kept on the box

  USAGE (admin PowerShell, from the folder this file is in)
    .\CF-WinRelay.ps1 -Mode Install -AlertWebhook '<machine url>' -LogWebhook '<log url>' [-EarlyWebhook '<early url>']
    .\CF-WinRelay.ps1 -Mode SetEarly -EarlyWebhook '<early url>'    # add/replace early-warning webhook later
    .\CF-WinRelay.ps1 -Mode Test | Status | Uninstall
  To update an installed box:  Copy-Item .\CF-WinRelay.ps1 C:\Tools\cfrelay\relay.ps1 -Force
                               C:\Tools\cfrelay\relay.ps1 -Mode Install-Tasks

  It never blocks, kills, deletes or "fixes" anything (except restarting Sysmon and re-creating its own
  tasks), so it is safe on the Assume Breach HMI. Webhooks live only in C:\Tools\cfrelay\relay.cfg.
#>
param(
    [ValidateSet('Install','Install-Tasks','SetEarly','Alert','Check','Export','Test','Status','Uninstall')]
    [string]$Mode = 'Status',
    [string]$AlertWebhook,
    [string]$LogWebhook,
    [string]$EarlyWebhook
)

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ======================= settings =======================
$Base       = 'C:\Tools\cfrelay'
$Script     = Join-Path $Base 'relay.ps1'
$Data       = 'C:\CF\relay'
$CfgFile    = Join-Path $Base 'relay.cfg'
$StateFile  = Join-Path $Data 'state.txt'        # Alert mode
$CheckState = Join-Path $Data 'check-state.txt'  # Check mode flags
$SnapFile   = Join-Path $Data 'snapshot.txt'     # Check mode last snapshot
$LogDir     = Join-Path $Data 'logs'
$Unsent     = Join-Path $Data 'unsent.log'
$YaraLog    = 'C:\CF\yara\hits.log'
$Box        = $env:COMPUTERNAME

$TaskRelay   = 'System Health Relay'
$TaskCheck   = 'System Health Check'
$TaskArchive = 'System Health Archive'
$WatchTasks  = @($TaskRelay, $TaskCheck, $TaskArchive, 'CF YARA Scan')

# Assume Breach box (HMI runs Ignition): lifeline is alert-only there, no auto-repair
$IsAssumeBreach = (Test-Path 'C:\Program Files\Inductive Automation') -or ($env:COMPUTERNAME -eq 'IP-0A000F8E')
# our way in - lifeline keeps these working
$RdpPort       = 3389
$LifelineUsers = @('blueteam','bt_recovery')
$LifelineLog   = Join-Path $Data 'lifeline.log'

# canaries
$Canaries    = @('svc_backup_old')
$CanaryFiles = @('IT_passwords_old')
# known trap files: SYSTEM tasks point at these missing scripts. If one appears, someone is using it.
$TrapFiles   = @('C:\Windows\Temp\ignition_ui.ps1', 'C:\Scripts\fixsmartermail.ps1')
# our scanners may read the canary file without alerting
$IgnoreProcs = @('yara64.exe','MsMpEng.exe')
# team IPs (same list as the Linux monitor)
$TeamIPs     = @('10.0.15.146','10.0.15.166','10.0.15.181','10.0.15.151')
# our own command lines - never alert on these
$OwnPattern  = 'cfrelay\\relay\.ps1|yara\\yara-scan\.ps1|yara64\.exe'
# PowerShell's auto-generated module code - flagged by PowerShell on every import, harmless
$GeneratedPattern = 'Microsoft\.PowerShell\.Cmdletization|cmdletization_BindCommonParameters|\$script:ObjectModelWrapper'

# programs worth a heads-up whenever they start
$WatchProcs  = @('certutil.exe','bitsadmin.exe','mshta.exe','curl.exe','wget.exe','psexec.exe','psexesvc.exe',
                 'nc.exe','ncat.exe','vssadmin.exe','ntdsutil.exe','regsvr32.exe','wmic.exe','whoami.exe')
# services that should never start a shell (web shell / exploited service sign)
$ServiceParents = @('w3wp.exe','httpd.exe','tomcat7.exe','tomcat8.exe','tomcat9.exe','hfs.exe','mailservice.exe',
                    'syncbrs.exe','sqlservr.exe','mysqld.exe','java.exe','javaw.exe','ignitiongateway.exe','spoolsv.exe')
$Shells         = @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe')

# early warning thresholds (per source IP, per 1-minute run)
$BruteLimit  = 5     # failed logons from one IP
$SprayLimit  = 4     # different usernames from one IP
$KerbLimit   = 3     # Kerberos pre-auth failures from one IP

# scored ports - alert if one stops listening
$ScoredTcp   = @(25, 389, 1080)
$ScoredUdp   = @(161)
# high-port listeners from these processes change all the time - ignore in drift checks
$DynamicPortProcs = @('svchost','lsass','wininit','services','spoolsv','java','javaw','chromium','dns','ismserv',
                      'dfsrs','Microsoft.ActiveDirectory.WebServices','System','mysqld','IgnitionGateway')

# Alert mode: what to read each minute (RID = last record id seen)
$C = $Canaries[0]
$AlertQueries = [ordered]@{
    'Security' = @(
        "*[System[(EventID=1102 or EventID=4625 or EventID=4663 or EventID=4688 or EventID=4697 or EventID=4698 or EventID=4719 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4726 or EventID=4728 or EventID=4732 or EventID=4740 or EventID=4756 or EventID=4771) and EventRecordID &gt; RID]]",
        "*[System[EventID=4624 and EventRecordID &gt; RID] and EventData[Data[@Name='LogonType']='10']]",
        "*[System[EventID=4624 and EventRecordID &gt; RID] and EventData[Data[@Name='TargetUserName']='$C']]",
        "*[System[EventID=4769 and EventRecordID &gt; RID] and EventData[Data[@Name='TicketEncryptionType']='0x17']]",
        "*[System[EventID=4769 and EventRecordID &gt; RID] and EventData[Data[@Name='ServiceName']='$C']]",
        "*[System[EventID=4768 and EventRecordID &gt; RID] and EventData[Data[@Name='PreAuthType']='0']]",
        "*[System[EventID=4768 and EventRecordID &gt; RID] and EventData[Data[@Name='TargetUserName']='$C']]",
        "*[System[EventID=4776 and EventRecordID &gt; RID] and EventData[Data[@Name='TargetUserName']='$C']]"
    )
    'System' = @("*[System[(EventID=104 or EventID=7045) and EventRecordID &gt; RID]]")
    'Microsoft-Windows-Windows Defender/Operational' = @("*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007) and EventRecordID &gt; RID]]")
    'Microsoft-Windows-PowerShell/Operational' = @("*[System[EventID=4104 and Level=3 and EventRecordID &gt; RID]]")
    'Microsoft-Windows-Sysmon/Operational' = @("*[System[(EventID=6 or EventID=8 or EventID=25) and EventRecordID &gt; RID]]")
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = @("*[System[(EventID=2003 or EventID=2004 or EventID=2005 or EventID=2006 or EventID=2033 or EventID=2052 or EventID=2097 or EventID=2099) and EventRecordID &gt; RID]]")
}

# Export mode
$ExportLogs = @('Security','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational',
                'Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-TaskScheduler/Operational')
$ExportWindowMs = 1020000   # 17 minutes (15 min task + 2 min overlap)
$ExportMaxEvents  = 400     # newest N events per log in the readable files
$ExportMaxSeconds = 45      # stop formatting after this long (keeps HMI light)
$DiscordMaxMB   = 9.5
# events that go into the readable Discord .log files (TIME = last ~17 min); everything is in the .evtx zip
$TextSelect = @{
    'Security' = @(
        "*[System[(EventID=1102 or EventID=4625 or EventID=4648 or EventID=4663 or EventID=4697 or (EventID&gt;=4698 and EventID&lt;=4702) or EventID=4719 or (EventID&gt;=4720 and EventID&lt;=4738) or EventID=4740 or EventID=4756 or EventID=4771) and TIME]]",
        "*[System[EventID=4624 and TIME] and EventData[Data[@Name='LogonType']='10']]"
    )
    'System'   = @("*[System[(EventID=104 or EventID=1074 or EventID=6005 or EventID=6006 or EventID=7034 or EventID=7036 or EventID=7040 or EventID=7045) and TIME]]")
    'Microsoft-Windows-Sysmon/Operational'     = @("*[System[(EventID=1 or EventID=6 or EventID=8 or EventID=25) and TIME]]")
    'Microsoft-Windows-PowerShell/Operational' = @("*[System[EventID=4104 and TIME]]")
    'Microsoft-Windows-Windows Defender/Operational' = @("*[System[TIME]]")
    'Microsoft-Windows-TaskScheduler/Operational'    = @("*[System[(EventID=106 or EventID=140 or EventID=141) and TIME]]")
}
$OwnScripts = @('C:\Tools\cfrelay\relay.ps1','C:\Tools\yara\yara-scan.ps1')

# ======================= helpers =======================
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Cfg {
    $cfg = @{ alert = ''; log = ''; early = '' }
    if (Test-Path $CfgFile) {
        foreach ($line in Get-Content $CfgFile) {
            if ($line -match '^(alert|log|early)=(.*)$') { $cfg[$matches[1]] = $matches[2].Trim() }
        }
    }
    return $cfg
}

function Save-Cfg($cfg) {
    Set-Content -Path $CfgFile -Value @("alert=$($cfg.alert)", "log=$($cfg.log)", "early=$($cfg.early)") -Encoding ascii
}

function Read-KV($path) {
    $s = @{}
    if (Test-Path $path) {
        foreach ($line in Get-Content $path) {
            $i = $line.LastIndexOf('=')
            if ($i -gt 0) { $s[$line.Substring(0,$i)] = [long]$line.Substring($i+1) }
        }
    }
    return $s
}

function Write-KV($path, $s) {
    $lines = foreach ($k in $s.Keys) { "$k=$($s[$k])" }
    Set-Content -Path $path -Value $lines -Encoding ascii
}

function Get-LatestRecordId($logName) {
    try { return [long](Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop).RecordId }
    catch { return [long]0 }
}

function Get-EvData($e) {
    $h = @{}
    try {
        $x = [xml]$e.ToXml()
        foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = [string]$d.'#text' } }
        if ($x.Event.UserData) {
            foreach ($n in $x.Event.UserData.ChildNodes) {
                foreach ($c in $n.ChildNodes) { $h[$c.LocalName] = [string]$c.InnerText }
            }
        }
    } catch {}
    return $h
}

# one-line, trimmed text for a field
function Short($text, $max = 300) {
    if (-not $text) { return '' }
    $t = (([string]$text) -replace '\s+',' ').Trim() -replace '`',"'"
    if ($t.Length -gt $max) { return $t.Substring(0,$max) + '...' }
    return $t
}

function Name-Only($name) { if (-not $name) { return '' }; return ($name -split '\\')[-1].Trim().TrimEnd('$') }

function Test-Canary($name) {
    $n = Name-Only $name
    foreach ($c in $Canaries) { if ($n -and $n -ieq $c) { return $true } }
    return $false
}

function Resolve-Sid($sid) {
    try { return (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value }
    catch { return $sid }
}

function Test-IsDC {
    try { return ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { return $false }
}

# names of admin accounts on this box (local Administrators group, plus Domain Admins on a DC)
function Get-AdminNames {
    $names = New-Object System.Collections.Generic.List[string]
    $names.Add('Administrator'); $names.Add('blueteam')
    $out = & net.exe localgroup Administrators 2>$null
    $in = $false
    foreach ($l in $out) {
        if ($l -match '^-{5,}') { $in = $true; continue }
        if ($l -match 'command completed') { break }
        if ($in -and $l.Trim()) { $names.Add((Name-Only $l.Trim())) }
    }
    return $names
}

# build one alert: tag line + who/what/when/where details
function New-Msg($tag, $what, $when, $who, $where, $detail) {
    $m = "**[$tag] $what**"
    if ($when)   { $m += "`nWhen: $when UTC" }
    if ($who)    { $m += "`nWho: $who" }
    $m += "`nBox: $Box"
    if ($where)  { $m += " | $where" }
    if ($detail) { $m += "`n$detail" }
    return $m
}

function Send-Discord($url, [string[]]$msgs) {
    if (-not $url -or -not $msgs -or $msgs.Count -eq 0) { return }
    $chunks = @(); $cur = ''
    foreach ($m in $msgs) {
        if ($m.Length -gt 1800) { $m = $m.Substring(0,1800) + '...' }
        if (($cur.Length + $m.Length + 2) -gt 1900) { $chunks += $cur; $cur = '' }
        $cur += $m + "`n`n"
    }
    if ($cur) { $chunks += $cur }
    foreach ($c in $chunks) {
        $body = @{ username = $Box; content = $c } | ConvertTo-Json -Compress
        $sent = $false
        for ($try = 1; $try -le 3 -and -not $sent; $try++) {
            try {
                Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $body -ErrorAction Stop | Out-Null
                $sent = $true
            } catch { Start-Sleep -Seconds (2 * $try) }
        }
        if (-not $sent) { Add-Content -Path $Unsent -Value $c }
        Start-Sleep -Milliseconds 800
    }
}

function Send-Now($msgs)   { $cfg = Get-Cfg; Send-Discord $cfg.alert $msgs }
function Send-Early($msgs) {
    $cfg = Get-Cfg
    if ($cfg.early) { Send-Discord $cfg.early $msgs } else { Send-Discord $cfg.alert $msgs }
}

function Send-DiscordFiles($url, [string[]]$paths, $message) {
    if (-not $url -or -not $paths -or $paths.Count -eq 0) { return $false }
    try {
        Add-Type -AssemblyName System.Net.Http
        $client = New-Object System.Net.Http.HttpClient
        $form   = New-Object System.Net.Http.MultipartFormDataContent
        $form.Add((New-Object System.Net.Http.StringContent($message)), 'content')
        $form.Add((New-Object System.Net.Http.StringContent($Box)), 'username')
        $i = 0
        foreach ($p in $paths) {
            $bytes = [IO.File]::ReadAllBytes($p)
            $file  = New-Object System.Net.Http.ByteArrayContent -ArgumentList (,$bytes)
            $type  = 'text/plain'; if ($p -like '*.zip') { $type = 'application/zip' }
            $file.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($type)
            $form.Add($file, "files[$i]", [IO.Path]::GetFileName($p))
            $i++
        }
        $resp = $client.PostAsync($url, $form).Result
        $ok = $resp.IsSuccessStatusCode
        $client.Dispose()
        return $ok
    } catch { return $false }
}

# add a message unless the same thing was already reported in the last $minutes (stops repeats)
function Add-Once($list, $state, $key, $msg, $minutes) {
    if ($key -eq 'auto') { $key = [string]$msg -replace 'When: [^\n]*','' }
    $sha = New-Object Security.Cryptography.SHA1Managed
    $k = 'once:' + (([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$key)))) -replace '-','').Substring(0,16)
    $nowMin = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 60)
    if ($state.ContainsKey($k) -and ($nowMin - $state[$k]) -lt $minutes) { return }
    $state[$k] = $nowMin
    $list.Add($msg)
}

# plain-English reason for a failed logon (4625 Status/SubStatus)
function Get-FailReason($d) {
    $codes = @{
        '0xc000006a' = 'right username, WRONG password'; '0xc0000064' = 'username does not exist'
        '0xc0000072' = 'account is disabled';            '0xc0000234' = 'account is locked out'
        '0xc0000071' = 'password expired';               '0xc000006f' = 'outside allowed logon hours'
        '0xc000015b' = 'RIGHT password, but this logon type is denied'; '0xc0000193' = 'account expired'
        '0xc0000133' = 'clock out of sync';              '0xc0000413' = 'blocked by firewall/authentication policy'
    }
    $sub = ([string]$d.SubStatus).ToLower(); $st = ([string]$d.Status).ToLower()
    if ($codes.ContainsKey($sub)) { return $codes[$sub] }
    if ($codes.ContainsKey($st))  { return $codes[$st] }
    return "status $st / $sub"
}

# details we can see about someone who is only TRYING to get in
function Get-AttemptInfo($d) {
    $types = @{ '2'='at the keyboard'; '3'='network (SMB/WinRM/RDP with NLA)'; '4'='batch/task'; '5'='service'; '7'='unlock'; '8'='network cleartext'; '10'='RDP'; '11'='cached' }
    $lt = [string]$d.LogonType; $ltn = $types[$lt]; if (-not $ltn) { $ltn = "type $lt" }
    return "Why it failed: $(Get-FailReason $d)`nTheir machine name: $($d.WorkstationName)   How: $ltn   Auth: $($d.AuthenticationPackageName)   Process: $($d.LogonProcessName)"
}

# snapshot of an intruder's session: who, from where, from what machine, what's connected
function Get-IntruderProfile($d) {
    $ip = [string]$d.IpAddress
    $p  = "Account: $($d.TargetDomainName)\$($d.TargetUserName)"
    $p += "`nFrom IP: $ip   Their machine name: $($d.WorkstationName)"
    $p += "`nLogon type: $($d.LogonType)   Auth: $($d.AuthenticationPackageName) $($d.LmPackageName)   Logon process: $($d.LogonProcessName)"
    $p += "`nLogon ID: $($d.TargetLogonId)  (every command they run in this session will be posted here for 60 min)"
    # RDP client name / address from the user's volatile environment
    try {
        $ve = Get-ChildItem "Registry::HKEY_USERS\$($d.TargetUserSid)\Volatile Environment" -ErrorAction Stop
        foreach ($k in $ve) {
            $cn = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).CLIENTNAME
            if ($cn) { $p += "`nRDP client name: $cn" }
        }
    } catch {}
    try {
        $q = (& query.exe user 2>$null) -join "`n"
        if ($q) { $p += "`nWho is on the box now:`n" + $q }
    } catch {}
    if ($ip -and $ip -ne '-') {
        try {
            $procs = @{}; foreach ($x in Get-Process) { $procs[[int]$x.Id] = $x.ProcessName }
            $conns = Get-NetTCPConnection -RemoteAddress $ip -ErrorAction Stop | Select-Object -First 8
            foreach ($c in $conns) { $p += "`nConnection: local $($c.LocalPort) <-> $($c.RemoteAddress):$($c.RemotePort) $($c.State) ($($procs[[int]$c.OwningProcess]))" }
        } catch {}
    }
    return $p
}

# why a new process looks suspicious (empty = fine)
function Get-ProcReasons($img, $cmd, $parent) {
    $r = New-Object System.Collections.Generic.List[string]
    $exe  = ([IO.Path]::GetFileName([string]$img)).ToLower()
    $pexe = ([IO.Path]::GetFileName([string]$parent)).ToLower()
    if ($cmd -and $cmd -match $OwnPattern) { return $r }
    if ($WatchProcs -contains $exe) { $r.Add("watched tool ($exe)") }
    if (($ServiceParents -contains $pexe) -and ($Shells -contains $exe)) { $r.Add("a SERVICE ($pexe) started a shell ($exe) - possible web shell / exploit") }
    if ($cmd -and $cmd -match '[A-Za-z0-9+/]{120,}={0,2}') { $r.Add('long base64 blob in command line') }
    if ($exe -match '^(powershell|pwsh)\.exe$' -and $cmd -match '\s[-/]e(c|n|nc|ncodedcommand)?\s+\S{20,}') { $r.Add('PowerShell encoded command') }
    if ($exe -match '^(powershell|pwsh)\.exe$' -and $cmd -match 'hidden' -and $cmd -match 'bypass') { $r.Add('hidden PowerShell with policy bypass') }
    if ($Shells -contains $exe -and $cmd -match '\\(Temp|Tmp)\\|\\Users\\Public\\|\\PerfLogs\\') { $r.Add('shell running a script from a user-writable folder') }
    if ($img -match '\\(Temp|Tmp)\\|\\Users\\Public\\|\\AppData\\|\\PerfLogs\\|\\Windows\\Tasks\\|^C:\\ProgramData\\[^\\]+$') { $r.Add('ran from a user-writable folder') }
    return $r
}

# ======================= LIFELINE (every 1 min) - keep RDP working for us =======================
function Write-LifeLog($m) {
    Add-Content -Path $LifelineLog -Value ("{0} UTC | {1}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $m)
}

function Invoke-Lifeline($state, $out) {
    $fix = -not $IsAssumeBreach
    $t = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $problems = New-Object System.Collections.Generic.List[string]

    # 1. RDP turned off in the registry (normal setting or a policy setting)
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    try {
        if ((Get-ItemProperty $ts -ErrorAction Stop).fDenyTSConnections -ne 0) {
            if ($fix) { Set-ItemProperty $ts -Name fDenyTSConnections -Value 0; $problems.Add('RDP was turned OFF (fDenyTSConnections=1) - turned it back on') }
            else { $problems.Add('RDP is turned OFF (fDenyTSConnections=1)') }
        }
    } catch {}
    try {
        $pol = Get-ItemProperty $tsPol -ErrorAction Stop
        if ($pol.fDenyTSConnections -eq 1) {
            if ($fix) { Set-ItemProperty $tsPol -Name fDenyTSConnections -Value 0; $problems.Add('RDP was turned OFF by POLICY - set the policy back to allow') }
            else { $problems.Add('RDP is turned OFF by policy') }
        }
    } catch {}

    # 2. RDP port moved away from 3389
    $wst = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $restartTs = $false
    try {
        $port = (Get-ItemProperty $wst -ErrorAction Stop).PortNumber
        if ($port -ne $RdpPort) {
            if ($fix) { Set-ItemProperty $wst -Name PortNumber -Value $RdpPort; $restartTs = $true; $problems.Add("RDP port was CHANGED to $port - set back to $RdpPort") }
            else { $problems.Add("RDP port was CHANGED to $port") }
        }
    } catch {}

    # 3. Remote Desktop service disabled or stopped
    $svc = Get-CimInstance Win32_Service -Filter "Name='TermService'" -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartMode -eq 'Disabled') {
            if ($fix) { Set-Service TermService -StartupType Manual; $problems.Add('Remote Desktop service was DISABLED - re-enabled it') }
            else { $problems.Add('Remote Desktop service is DISABLED') }
        }
        if ($svc.State -ne 'Running' -or $restartTs) {
            if ($fix) {
                try { Restart-Service TermService -Force -ErrorAction Stop; $problems.Add('Remote Desktop service was not running correctly - (re)started it') }
                catch { $problems.Add('Remote Desktop service is NOT running and could not be started') }
            } else { $problems.Add('Remote Desktop service is NOT running') }
        }
    }

    # 4. firewall: profile turned off, our RDP allow rule missing, someone else's block rule covering RDP
    try {
        foreach ($pf in Get-NetFirewallProfile -ErrorAction Stop) {
            if (-not $pf.Enabled) {
                if ($fix) { Set-NetFirewallProfile -Name $pf.Name -Enabled True; $problems.Add("Firewall profile $($pf.Name) was turned OFF - turned it back on") }
                else { $problems.Add("Firewall profile $($pf.Name) is OFF") }
            }
        }
        if ($fix -and -not (Get-NetFirewallRule -DisplayName 'CF Allow In RDP' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'CF Allow In RDP' -Direction Inbound -Protocol TCP -LocalPort $RdpPort -Action Allow -Profile Any | Out-Null
            Write-LifeLog "Created 'CF Allow In RDP' (TCP $RdpPort, any source - port rule, not an IP allow-list)"
        }
        $ourAllow = Get-NetFirewallRule -DisplayName 'CF Allow In RDP' -ErrorAction SilentlyContinue
        if ($fix -and $ourAllow -and $ourAllow.Enabled -ne 'True') {
            Enable-NetFirewallRule -DisplayName 'CF Allow In RDP'; $problems.Add("Our RDP allow rule was DISABLED - re-enabled it")
        }
        $blocks = Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
                  Where-Object { $_.DisplayName -notlike 'CF *' }
        foreach ($r in $blocks) {
            # program/service-specific block rules can't touch RDP - skip them
            $app = $r | Get-NetFirewallApplicationFilter
            if (($app.Program -and $app.Program -ne 'Any') -or ($app.Service -and $app.Service -ne 'Any')) { continue }
            $pfil = $r | Get-NetFirewallPortFilter
            $af   = $r | Get-NetFirewallAddressFilter
            $ports = @($pfil.LocalPort)
            $hitsRdp = ($ports -contains 'Any') -or ($ports -contains "$RdpPort") -or (@($ports | Where-Object { $_ -match '^(\d+)-(\d+)$' -and [int]$matches[1] -le $RdpPort -and [int]$matches[2] -ge $RdpPort }).Count -gt 0)
            if ($hitsRdp) {
                $desc = "'$($r.DisplayName)' ports=$($ports -join ',') from=$(@($af.RemoteAddress) -join ',')"
                if ($fix) { Disable-NetFirewallRule -Name $r.Name; $problems.Add("Someone else's firewall BLOCK rule covered RDP - disabled it: $desc") }
                else { $problems.Add("A firewall BLOCK rule covers RDP: $desc") }
            }
        }
    } catch {}

    # 5. our admin account disabled or locked
    foreach ($u in $LifelineUsers) {
        try {
            $acct = Get-CimInstance Win32_UserAccount -Filter "Name='$u' and Domain='$env:USERDOMAIN'" -ErrorAction Stop | Select-Object -First 1
            if ($acct) {
                if ($acct.Disabled) {
                    if ($fix) { & net.exe user $u /active:yes | Out-Null; $problems.Add("Account '$u' was DISABLED - re-enabled it") }
                    else { $problems.Add("Account '$u' is DISABLED") }
                }
                if ($acct.Lockout) { $problems.Add("Account '$u' is LOCKED OUT (password guessing?) - use the backup admin, it unlocks after the lockout timer") }
            }
        } catch {}
    }

    # 6. is anything actually listening on the RDP port?
    if (-not (Get-NetTCPConnection -State Listen -LocalPort $RdpPort -ErrorAction SilentlyContinue)) {
        $problems.Add("Nothing is listening on TCP $RdpPort")
    }

    if ($problems.Count -gt 0) {
        foreach ($p in $problems) { Write-LifeLog $p }
        $tag = if ($fix) { 'LIFELINE - AUTO-FIXED' } else { 'LIFELINE (HMI - alert only, not fixed)' }
        $detail = ($problems | ForEach-Object { '- ' + $_ }) -join "`n"
        if ($fix) { $detail += "`nSomeone tried to lock us out. Check the firewall/RDP alerts above for who did it." }
        Add-Once $out $state ('lifeline|' + ($problems -join '|')) (New-Msg $tag 'Someone is cutting off our RDP access' $t '' '' $detail) 5
    }
}

# ======================= ALERT (every 1 min) =======================
function Invoke-Alert {
    $state  = Read-KV $StateFile
    $now    = New-Object System.Collections.Generic.List[string]
    $early  = New-Object System.Collections.Generic.List[string]
    $fails  = @{}   # ip -> list of usernames (4625)
    $failHosts = @{} # ip -> attacker machine name
    $kfails = @{}   # ip -> count (4771)
    $admins = Get-AdminNames

    foreach ($logName in $AlertQueries.Keys) {
        $latest = Get-LatestRecordId $logName
        if (-not $state.ContainsKey($logName)) { $state[$logName] = $latest; continue }   # first run: start from now
        $last = $state[$logName]
        if ($latest -lt $last) { $last = 0 }      # log cleared/reset
        if ($latest -eq $last) { continue }

        $xml = "<QueryList><Query Id='0' Path='$logName'>"
        foreach ($q in $AlertQueries[$logName]) { $xml += "<Select Path='$logName'>" + ($q -replace 'RID', $last) + "</Select>" }
        $xml += "</Query></QueryList>"
        $events = @()
        try { $events = @(Get-WinEvent -FilterXml ([xml]$xml) -Oldest -MaxEvents 500 -ErrorAction Stop) } catch {}

        foreach ($e in $events) {
            $d = Get-EvData $e
            $t = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            $subj = "$($d.SubjectDomainName)\$($d.SubjectUserName)"
            switch ($e.Id) {
                1102 { $now.Add((New-Msg 'LOOK NOW' 'Security log CLEARED' $t $subj 'Security log' 'Someone is covering tracks. Check Discord .log history for what happened before this.')) }
                104  { $now.Add((New-Msg 'LOOK NOW' "Event log CLEARED ($($d.Channel))" $t $subj '' '')) }
                4624 {
                    if (Test-Canary $d.TargetUserName) {
                        $now.Add((New-Msg 'LOOK NOW' 'CANARY ACCOUNT LOGGED IN SUCCESSFULLY - treat as compromise' $t $d.TargetUserName "from $($d.IpAddress)" (Get-IntruderProfile $d)))
                        $state["watch:$($d.TargetLogonId)"] = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 60)
                    } elseif ($d.IpAddress -and ($TeamIPs -notcontains $d.IpAddress) -and @('-','127.0.0.1','::1') -notcontains $d.IpAddress) {
                        Add-Once $now $state "rdp|$($d.TargetUserName)|$($d.IpAddress)" (New-Msg 'LOOK NOW' 'RDP logon from a NON-TEAM IP - intruder profile' $t "$($d.TargetDomainName)\$($d.TargetUserName)" "from $($d.IpAddress)" ((Get-IntruderProfile $d) + "`nIf this is not a teammate: snapshot evidence (pktmon, screenshots) before kicking them.")) 30
                        $state["watch:$($d.TargetLogonId)"] = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 60)
                        if ($d.TargetLinkedLogonId -and $d.TargetLinkedLogonId -ne '0x0') { $state["watch:$($d.TargetLinkedLogonId)"] = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 60) }
                    }
                }
                4625 {
                    $u = Name-Only $d.TargetUserName
                    $ip = $d.IpAddress; if (-not $ip -or $ip -eq '-') { $ip = 'local' }
                    if (-not $fails.ContainsKey($ip)) { $fails[$ip] = New-Object System.Collections.Generic.List[string] }
                    $fails[$ip].Add($u)
                    if ($d.WorkstationName -and $d.WorkstationName -ne '-') { $failHosts[$ip] = $d.WorkstationName }
                    $bait = ($d.Status -ieq '0xc000015b') -or ($d.SubStatus -ieq '0xc000015b')
                    if ((Test-Canary $u) -and $bait) {
                        $now.Add((New-Msg 'LOOK NOW' 'Someone used the BAIT PASSWORD from IT_passwords_old.txt' $t $u "from $ip (their machine: $($d.WorkstationName))" "Logon type $($d.LogonType), auth $($d.AuthenticationPackageName). They read the bait file on the HFS share and are trying the password. They got NO access."))
                    } elseif (Test-Canary $u) {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'Someone tried the CANARY account' $t $u "from $ip" ((Get-AttemptInfo $d) + "`nRed team is testing credentials they found.")) 15
                    } elseif ($admins -contains $u) {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' "Failed logon to ADMIN account '$u'" $t $u "from $ip" (Get-AttemptInfo $d)) 15
                    }
                }
                4771 {
                    $u = Name-Only $d.TargetUserName
                    $ip = $d.IpAddress -replace '^::ffff:',''
                    if (-not $kfails.ContainsKey($ip)) { $kfails[$ip] = 0 }
                    $kfails[$ip]++
                    if (Test-Canary $u) {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'Kerberos password guess on the CANARY account' $t $u "from $ip" '') 15
                    } elseif ($admins -contains $u) {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' "Kerberos password failure on ADMIN account '$u'" $t $u "from $ip" '') 15
                    }
                }
                4768 {
                    $ip = $d.IpAddress -replace '^::ffff:',''
                    if (Test-Canary $d.TargetUserName) {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'Ticket requested for the CANARY account' $t $d.TargetUserName "from $ip" '') 15
                    } else {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'AS-REP roasting: ticket for an account with NO pre-auth' $t $d.TargetUserName "from $ip" 'Turn pre-auth back on for this account (traditional boxes only).') 15
                    }
                }
                4769 {
                    $ip = $d.IpAddress -replace '^::ffff:',''
                    $svc = [string]$d.ServiceName
                    if (Test-Canary $svc) {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'KERBEROASTING: someone requested a ticket for the CANARY service account' $t $d.TargetUserName "from $ip" 'They are collecting password hashes to crack. Expect attacks on service accounts soon.') 15
                    } elseif ($svc -notmatch '\$$' -and $svc -ne 'krbtgt') {
                        Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' "Possible Kerberoasting: weak (RC4) ticket for service '$svc'" $t $d.TargetUserName "from $ip" '') 15
                    }
                }
                4776 { if (Test-Canary $d.TargetUserName) { Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'NTLM check on the CANARY account' $t $d.TargetUserName "from host $($d.Workstation)" "status $($d.Status)") 15 } }
                4740 { Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' 'Account LOCKED OUT (password guessing?)' $t $d.TargetUserName "caller computer $($d.TargetDomainName)" '') 15 }
                4663 {
                    $obj = [string]$d.ObjectName
                    $hit = $false; foreach ($f in $CanaryFiles) { if ($obj -match [regex]::Escape($f)) { $hit = $true } }
                    $proc = [IO.Path]::GetFileName([string]$d.ProcessName)
                    if ($hit -and ($IgnoreProcs -notcontains $proc)) {
                        $now.Add((New-Msg 'LOOK NOW' 'CANARY FILE OPENED' $t $subj $obj "Program: $($d.ProcessName)"))
                    }
                }
                4688 {
                    if ($state.ContainsKey("watch:$($d.SubjectLogonId)")) {
                        $now.Add((New-Msg 'SESSION FEED' "Intruder session $($d.SubjectLogonId) ran: $([IO.Path]::GetFileName([string]$d.NewProcessName))" $t $subj '' ("Command: " + (Short $d.CommandLine 700))))
                    }
                    $why = Get-ProcReasons $d.NewProcessName $d.CommandLine $d.ParentProcessName
                    if ($why.Count -gt 0) {
                        Add-Once $now $state 'auto' (New-Msg 'LOOK NOW' ("Suspicious program: " + ($why -join '; ')) $t $subj $d.NewProcessName ("Parent: $($d.ParentProcessName)`nCommand: " + (Short $d.CommandLine 700))) 10
                    }
                }
                4697 { $now.Add((New-Msg 'LOOK NOW' "New SERVICE installed: $($d.ServiceName)" $t $subj (Short $d.ServiceFileName) "Account: $($d.ServiceAccount)")) }
                4698 { $now.Add((New-Msg 'LOOK NOW' "Scheduled task CREATED: $($d.TaskName)" $t $subj '' 'Check what it runs: (Get-ScheduledTask -TaskPath <path> -TaskName <name>).Actions')) }
                4719 { $now.Add((New-Msg 'LOOK NOW' 'Audit policy CHANGED (logging may be turned off)' $t $subj '' '')) }
                4720 { $now.Add((New-Msg 'LOOK NOW' "User CREATED: $($d.TargetDomainName)\$($d.TargetUserName)" $t $subj '' '')) }
                4722 { $now.Add((New-Msg 'LOOK NOW' "User ENABLED: $($d.TargetDomainName)\$($d.TargetUserName)" $t $subj '' '')) }
                4724 { $now.Add((New-Msg 'LOOK NOW' "Password RESET: $($d.TargetDomainName)\$($d.TargetUserName)" $t $subj '' 'Was this a teammate?')) }
                4726 { $now.Add((New-Msg 'LOOK NOW' "User DELETED: $($d.TargetDomainName)\$($d.TargetUserName)" $t $subj '' '')) }
                { $_ -in 4728,4732,4756 } {
                    $member = $d.MemberName; if (-not $member -or $member -eq '-') { $member = Resolve-Sid $d.MemberSid }
                    $now.Add((New-Msg 'LOOK NOW' "Added to group $($d.TargetDomainName)\$($d.TargetUserName): $member" $t $subj '' ''))
                }
                7045 { $now.Add((New-Msg 'LOOK NOW' "New SERVICE: $($d.ServiceName)" $t $d.AccountName (Short $d.ImagePath) "Start type: $($d.StartType)")) }
                1116 { $now.Add((New-Msg 'LOOK NOW' "Defender DETECTED: $($d.'Threat Name')" $t $d.'Detection User' (Short $d.Path) "Process: $($d.'Process Name')")) }
                1117 { $now.Add((New-Msg 'LOOK NOW' "Defender ACTION: $($d.'Action Name') on $($d.'Threat Name')" $t '' (Short $d.Path) '')) }
                5001 { $now.Add((New-Msg 'LOOK NOW' 'Defender real-time protection DISABLED' $t '' '' 'Turn it back on (traditional boxes): Set-MpPreference -DisableRealtimeMonitoring $false')) }
                5007 {
                    $nv = [string]$d.'New Value'
                    if ($nv -match 'Exclusions|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableAntiSpyware') {
                        $now.Add((New-Msg 'LOOK NOW' 'Defender SETTING CHANGED (exclusion or protection off)' $t '' '' (Short $nv 600)))
                    }
                }
                4104 {
                    $path = [string]$d.Path
                    $text = [string]$d.ScriptBlockText
                    # skip: our own scripts, PowerShell's auto-generated module code (ScheduledTasks, Defender,
                    # NetTCPIP... these get flagged on every import), and parts 2+ of long scripts
                    if ($path -match $OwnPattern) { break }
                    if ($text -match $GeneratedPattern) { break }
                    if ($d.MessageNumber -and [int]$d.MessageNumber -gt 1) { break }
                    $first = if ($text.Length -gt 300) { $text.Substring(0,300) } else { $text }
                    Add-Once $now $state "4104|$first" (New-Msg 'LOOK NOW' 'PowerShell flagged a SUSPICIOUS script' $t ([string]$e.UserId) $path ("Script: " + (Short $text 900))) 60
                }
                { $_ -in 2004,2097 } { $now.Add((New-Msg 'LOOK NOW' "Firewall rule ADDED: $($d.RuleName)" $t (Resolve-Sid $d.ModifyingUser) (Short $d.ModifyingApplication) "Action: $($d.Action)  Direction: $($d.Direction)  Ports: $($d.LocalPorts)  Remote: $($d.RemoteAddresses)")) }
                { $_ -in 2005,2099 } { $now.Add((New-Msg 'LOOK NOW' "Firewall rule CHANGED: $($d.RuleName)" $t (Resolve-Sid $d.ModifyingUser) (Short $d.ModifyingApplication) "Active: $($d.Active)  Action: $($d.Action)  Ports: $($d.LocalPorts)")) }
                { $_ -in 2006,2052 } { $now.Add((New-Msg 'LOOK NOW' "Firewall rule DELETED: $($d.RuleName)" $t (Resolve-Sid $d.ModifyingUser) (Short $d.ModifyingApplication) '')) }
                2033 { $now.Add((New-Msg 'LOOK NOW' 'ALL firewall rules DELETED' $t (Resolve-Sid $d.ModifyingUser) (Short $d.ModifyingApplication) 'Our port blocks are gone. Re-run the firewall block from the team notes.')) }
                2003 { $now.Add((New-Msg 'LOOK NOW' "Firewall profile setting CHANGED ($($d.SettingType) = $($d.SettingValueString))" $t (Resolve-Sid $d.ModifyingUser) (Short $d.ModifyingApplication) '')) }
                8  { $now.Add((New-Msg 'LOOK NOW' 'Code injected into another process (Sysmon 8)' $t '' "$($d.SourceImage) -> $($d.TargetImage)" '')) }
                25 { $now.Add((New-Msg 'LOOK NOW' 'Process tampering (Sysmon 25)' $t $d.User $d.Image $d.Type)) }
                6  { if ($d.Signed -ne 'true') { $now.Add((New-Msg 'LOOK NOW' 'UNSIGNED driver loaded (Sysmon 6)' $t '' $d.ImageLoaded '')) } }
            }
        }
        # caught up? jump to newest; otherwise continue from the last event we read
        if ($events.Count -lt 500) { $state[$logName] = $latest }
        elseif ($events.Count -gt 0) { $state[$logName] = [long]$events[-1].RecordId }
    }

    # password guessing patterns
    foreach ($ip in $fails.Keys) {
        $users = @($fails[$ip] | Sort-Object -Unique)
        if ($users.Count -ge $SprayLimit) {
            Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' "Password SPRAYING: $($fails[$ip].Count) failed logons for $($users.Count) different users" '' '' "from $ip (their machine: $($failHosts[$ip]))" ("Users: " + (($users | Select-Object -First 10) -join ', '))) 15
        } elseif ($fails[$ip].Count -ge $BruteLimit) {
            Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' "Password BRUTE FORCE: $($fails[$ip].Count) failed logons in 1 minute" '' ($users -join ', ') "from $ip (their machine: $($failHosts[$ip]))" '') 15
        }
    }
    foreach ($ip in $kfails.Keys) {
        if ($kfails[$ip] -ge $KerbLimit) {
            Add-Once $early $state 'auto' (New-Msg 'EARLY WARNING' "$($kfails[$ip]) Kerberos password failures in 1 minute" '' '' "from $ip" 'Password guessing against the domain.') 15
        }
    }

    # trap files (the SYSTEM tasks pointing at missing scripts)
    foreach ($tf in $TrapFiles) {
        $key = "trap:$tf"
        if (Test-Path $tf) {
            if (-not $state.ContainsKey($key)) {
                $i = Get-Item $tf -Force
                $owner = ''; try { $owner = (Get-Acl $tf).Owner } catch {}
                $hash = ''; try { $hash = (Get-FileHash $tf).Hash } catch {}
                $now.Add((New-Msg 'LOOK NOW' 'TRAP FILE APPEARED - someone is setting up a SYSTEM-level backdoor' $i.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') $owner $tf "Size $($i.Length) bytes, SHA256 $hash. A SYSTEM task runs this at logon. Do NOT open it by running it."))
                $state[$key] = 1
            }
        } elseif ($state.ContainsKey($key)) { $state.Remove($key) }
    }

    # new YARA hits
    if (Test-Path $YaraLog) {
        $lines = @(Get-Content $YaraLog)
        $seen = 0; if ($state.ContainsKey('yara')) { $seen = $state['yara'] }
        if ($lines.Count -lt $seen) { $seen = 0 }
        for ($i = $seen; $i -lt $lines.Count; $i++) { $now.Add((New-Msg 'LOOK NOW' 'YARA match' '' '' '' $lines[$i])) }
        $state['yara'] = [long]$lines.Count
    }

    try { Invoke-Lifeline $state $now } catch {}

    $nowMin = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 60)
    foreach ($k in @($state.Keys)) {
        if ($k -like 'once:*'  -and ($nowMin - $state[$k]) -gt 120) { $state.Remove($k) }
        if ($k -like 'watch:*' -and ($nowMin - $state[$k]) -gt 60)  { $state.Remove($k) }
    }
    Write-KV $StateFile $state
    if ($now.Count -gt 0)   { Send-Now $now.ToArray() }
    if ($early.Count -gt 0) { Send-Early $early.ToArray() }
}

# ======================= CHECK (every 5 min) - automated Audit =======================
function Get-Snapshot {
    $s = New-Object System.Collections.Generic.List[string]
    $isDC = Test-IsDC

    # admins
    foreach ($a in (Get-AdminNames | Select-Object -Skip 2)) { $s.Add("Admin group member|$a") }
    if ($isDC) {
        foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins') {
            try { foreach ($m in Get-ADGroupMember $g -Recursive -ErrorAction Stop) { $s.Add("Admin group member|$g\$($m.SamAccountName)") } } catch {}
        }
        try { foreach ($u in Get-ADUser -Filter 'Enabled -eq $true' -ErrorAction Stop) { $s.Add("Enabled user|$($u.SamAccountName)") } } catch {}
    } else {
        try { foreach ($u in Get-LocalUser | Where-Object Enabled) { $s.Add("Enabled user|$($u.Name)") } } catch {}
    }

    # services (+ which ones are set to start automatically)
    try {
        foreach ($sv in Get-CimInstance Win32_Service) {
            $s.Add("Service|$($sv.Name) -> $($sv.PathName)")
            if ($sv.StartMode -eq 'Auto') { $s.Add("Auto-start service|$($sv.Name)") }
        }
    } catch {}

    # port forwards (netsh interface portproxy) - a classic pivot/backdoor
    foreach ($kind in 'v4tov4','v4tov6','v6tov4','v6tov6') {
        try {
            $props = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\$kind\tcp" -ErrorAction Stop
            foreach ($n in $props.PSObject.Properties) {
                if ($n.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { $s.Add("Port forward|$kind $($n.Name) -> $($n.Value)") }
            }
        } catch {}
    }

    # scheduled tasks
    try {
        foreach ($t in Get-ScheduledTask) {
            $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; '
            $s.Add("Scheduled task|$($t.TaskPath)$($t.TaskName) -> $act")
        }
    } catch {}

    # Run keys
    $runKeys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    foreach ($hive in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
        if ($hive.PSChildName -notmatch '_Classes$') { $runKeys += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run" }
    }
    foreach ($k in $runKeys) {
        try {
            $p = Get-ItemProperty $k -ErrorAction Stop
            foreach ($n in $p.PSObject.Properties) {
                if ($n.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { $s.Add("Run key|$k\$($n.Name) -> $($n.Value)") }
            }
        } catch {}
    }

    # Startup folders
    $startDirs = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')
    foreach ($u in Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue) {
        $startDirs += Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($dir in $startDirs) {
        foreach ($f in Get-ChildItem $dir -File -Force -ErrorAction SilentlyContinue) {
            if ($f.Name -ne 'desktop.ini') { $s.Add("Startup item|$($f.FullName)") }
        }
    }

    # WMI persistence
    try { foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop) { $s.Add("WMI consumer|$($c.Name)") } } catch {}

    # listening ports
    $procs = @{}; foreach ($p in Get-Process) { $procs[[int]$p.Id] = $p.ProcessName }
    try {
        foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
            $pn = $procs[[int]$c.OwningProcess]
            if ($c.LocalPort -ge 49152 -and ($DynamicPortProcs -contains $pn)) { continue }
            $s.Add("Listening port|tcp $($c.LocalPort) ($pn)")
        }
    } catch {}
    foreach ($port in $ScoredTcp) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) { $s.Add("Scored port|tcp $port") }
    }
    foreach ($port in $ScoredUdp) {
        if (Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue) { $s.Add("Scored port|udp $port") }
    }

    return ($s | Sort-Object -Unique)
}

function Register-RelayTasks {
    $settings = New-ScheduledTaskSettingsSet -Priority 7 -MultipleInstances IgnoreNew -StartWhenAvailable `
                  -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $list = @(
        @{ n = $TaskRelay;   m = 'Alert';  every = 1  },
        @{ n = $TaskCheck;   m = 'Check';  every = 5  },
        @{ n = $TaskArchive; m = 'Export'; every = 15 }
    )
    $made = @()
    foreach ($t in $list) {
        if (Get-ScheduledTask -TaskName $t.n -ErrorAction SilentlyContinue) { continue }
        $arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`" -Mode $($t.m)"
        $tr  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $t.every)
        Register-ScheduledTask -TaskName $t.n -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg) `
            -Trigger $tr -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        $made += $t.n
    }
    return $made
}

function Invoke-Check {
    $flags = Read-KV $CheckState
    $msgs  = New-Object System.Collections.Generic.List[string]
    $t     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')

    # --- is our monitoring still alive? ---
    $sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    if (-not $sysmon) { $sysmon = Get-Service Sysmon -ErrorAction SilentlyContinue }
    if (-not $sysmon) {
        if (-not $flags.ContainsKey('sysmon-missing')) { $msgs.Add((New-Msg 'LOOK NOW' 'Sysmon service is GONE (uninstalled?)' $t '' '' 'Reinstall Sysmon with the team config.')); $flags['sysmon-missing'] = 1 }
    } else {
        $flags.Remove('sysmon-missing')
        if ($sysmon.Status -ne 'Running') {
            try { Start-Service $sysmon.Name -ErrorAction Stop; $res = 'restarted it' } catch { $res = 'could NOT restart it' }
            $msgs.Add((New-Msg 'LOOK NOW' "Sysmon was STOPPED - $res" $t '' '' ''))
        }
    }
    foreach ($tn in $WatchTasks) {
        $task = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq 'Disabled') {
            try { Enable-ScheduledTask -TaskName $tn -ErrorAction Stop | Out-Null; $res = 're-enabled it' } catch { $res = 'could NOT re-enable it' }
            $msgs.Add((New-Msg 'LOOK NOW' "Our task '$tn' was DISABLED - $res" $t '' '' ''))
        }
    }
    $restored = Register-RelayTasks
    foreach ($r in $restored) { $msgs.Add((New-Msg 'LOOK NOW' "Our task '$r' was DELETED - restored it" $t '' '' 'Someone is removing our monitoring.')) }
    if (-not (Get-ScheduledTask -TaskName 'CF YARA Scan' -ErrorAction SilentlyContinue) -and (Test-Path 'C:\Tools\yara\yara-scan.ps1')) {
        if (-not $flags.ContainsKey('yara-missing')) { $msgs.Add((New-Msg 'LOOK NOW' "YARA task 'CF YARA Scan' is GONE" $t '' '' 'Re-create it (see YARA notes).')); $flags['yara-missing'] = 1 }
    } else { $flags.Remove('yara-missing') }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) {
            if (-not $flags.ContainsKey('rtp-off')) { $msgs.Add((New-Msg 'LOOK NOW' 'Defender real-time protection is OFF' $t '' '' '')); $flags['rtp-off'] = 1 }
        } else { $flags.Remove('rtp-off') }
    } catch {}

    # --- drift: what changed since the last check? ---
    $cur = @(Get-Snapshot)
    if (Test-Path $SnapFile) {
        $prev = @(Get-Content $SnapFile)
        $prevSet = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]$prev)
        $curSet  = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]$cur)
        $added   = @($cur  | Where-Object { -not $prevSet.Contains($_) })
        $removed = @($prev | Where-Object { -not $curSet.Contains($_) })

        $byCat = @{}
        foreach ($a in $added) {
            $cat, $item = $a -split '\|', 2
            if ($cat -eq 'Scored port') { $msgs.Add((New-Msg 'LOOK NOW' "Scored service is BACK UP: $item" $t '' '' '')); continue }
            if (-not $byCat.ContainsKey($cat)) { $byCat[$cat] = New-Object System.Collections.Generic.List[string] }
            $byCat[$cat].Add($item)
        }
        foreach ($cat in $byCat.Keys) {
            $items = $byCat[$cat]
            $list = (($items | Select-Object -First 12 | ForEach-Object { '- ' + (Short $_ 250) }) -join "`n")
            if ($items.Count -gt 12) { $list += "`n- ...and $($items.Count - 12) more" }
            $msgs.Add((New-Msg 'LOOK NOW' "NEW $cat since last check ($($items.Count))" $t '' '' $list))
        }
        foreach ($r in $removed) {
            $cat, $item = $r -split '\|', 2
            if ($cat -eq 'Scored port') {
                $msgs.Add((New-Msg 'LOOK NOW' "SCORED SERVICE DOWN: $item is no longer listening" $t '' '' 'This costs points every check. Restart the service now (snapshot revert is the last resort).'))
            } elseif ($cat -eq 'Admin group member') {
                $msgs.Add((New-Msg 'LOOK NOW' "Removed from admin group: $item" $t '' '' 'Was this a teammate?'))
            } elseif ($cat -eq 'Service' -and $item -match '^Sysmon') {
                $msgs.Add((New-Msg 'LOOK NOW' "Service REMOVED: $item" $t '' '' ''))
            }
        }
    } else {
        Send-Now @((New-Msg 'INFO' "Baseline captured: $($cur.Count) items (admins, users, services, tasks, Run keys, startup, WMI, ports)" $t '' '' 'From now on, anything new shows up here.'))
    }
    Set-Content -Path $SnapFile -Value $cur -Encoding utf8
    Write-KV $CheckState $flags
    if ($msgs.Count -gt 0) { Send-Now $msgs.ToArray() }
}

# ======================= EXPORT (every 15 min) =======================
function Invoke-Export {
    $cfg   = Get-Cfg
    $nowT  = Get-Date
    $stamp = $nowT.ToUniversalTime().ToString('yyyyMMdd_HHmm')
    $work  = Join-Path $LogDir "tmp_$stamp"
    New-Item -ItemType Directory -Force $work | Out-Null
    $short = @{
        'Security' = 'Security'; 'System' = 'System'
        'Microsoft-Windows-Sysmon/Operational' = 'Sysmon'
        'Microsoft-Windows-PowerShell/Operational' = 'PowerShell'
        'Microsoft-Windows-Windows Defender/Operational' = 'Defender'
        'Microsoft-Windows-TaskScheduler/Operational' = 'TaskScheduler'
    }
    $textFiles = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($log in $ExportLogs) {
        $name = $short[$log]; if (-not $name) { $name = ($log -replace '[\\/ ]','_') }
        & wevtutil.exe epl "$log" (Join-Path $work "$name.evtx") "/q:*[System[TimeCreated[timediff(@SystemTime) <= $ExportWindowMs]]]" /ow:true 2>$null

        $events = @()
        $sel = $TextSelect[$log]
        if ($sel) {
            $T = "TimeCreated[timediff(@SystemTime) &lt;= $ExportWindowMs]"
            $xml = "<QueryList><Query Id='0' Path='$log'>"
            foreach ($q in $sel) { $xml += "<Select Path='$log'>" + ($q -replace 'TIME', $T) + "</Select>" }
            if ($log -eq 'Microsoft-Windows-PowerShell/Operational') {
                foreach ($own in $OwnScripts) { $xml += "<Suppress Path='$log'>*[EventData[Data[@Name='Path']='$own']]</Suppress>" }
            }
            $xml += "</Query></QueryList>"
            try { $events = @(Get-WinEvent -FilterXml ([xml]$xml) -MaxEvents $ExportMaxEvents -ErrorAction Stop) } catch {}
        }
        if ($events.Count -eq 0) { Write-Host "  ${name}: 0 events"; continue }
        $txt = Join-Path $work "$($Box)_$($name)_$stamp.log"
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($e in ($events | Sort-Object RecordId)) {
            if ($sw.Elapsed.TotalSeconds -gt $ExportMaxSeconds) { $lines.Add("(stopped early to keep the box fast - full detail is in the .evtx zip on the box)"); break }
            $msg = ''
            if ($e.Id -eq 4104 -and $e.Properties.Count -ge 3) {
                if ([string]$e.Properties[2].Value -match $GeneratedPattern) { continue }
                # script block text straight from the event data (formatting these is very slow)
                $msg = "Script block: " + [string]$e.Properties[2].Value + "  | Path: " + [string]$e.Properties[4].Value
            } else {
                try { $msg = $e.FormatDescription() } catch {}
                if (-not $msg) { $msg = ($e.Properties | ForEach-Object { [string]$_.Value }) -join ' | ' }
            }
            $lines.Add(('{0} UTC | {1,5} | {2}' -f $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $e.Id, (Short $msg 600)))
        }
        Write-Host ("  {0}: {1} events, {2:N1}s so far" -f $name, $events.Count, $sw.Elapsed.TotalSeconds)
        Set-Content -Path $txt -Value $lines -Encoding utf8
        $textFiles += $txt
    }

    $evtx = @(Get-ChildItem $work -Filter *.evtx -ErrorAction SilentlyContinue)
    if ($evtx.Count -gt 0) {
        Compress-Archive -Path (Join-Path $work '*.evtx') -DestinationPath (Join-Path $LogDir "$($Box)_$stamp.zip") -Force
    }
    if ($textFiles.Count -gt 0) {
        $msg   = "$Box logs, last ~17 min, ending $stamp UTC"
        $total = ($textFiles | ForEach-Object { (Get-Item $_).Length } | Measure-Object -Sum).Sum / 1MB
        if ($total -le $DiscordMaxMB) {
            if (-not (Send-DiscordFiles $cfg.log $textFiles $msg)) { Add-Content $Unsent "log upload failed: $stamp" }
        } else {
            foreach ($f in $textFiles) {
                if (((Get-Item $f).Length / 1MB) -le $DiscordMaxMB) { Send-DiscordFiles $cfg.log @($f) $msg | Out-Null }
                else { Send-Discord $cfg.log @("$msg - $([IO.Path]::GetFileName($f)) too big for Discord; full .evtx kept on box in $LogDir") }
                Start-Sleep -Seconds 1
            }
        }
    }
    Remove-Item $work -Recurse -Force
    Get-ChildItem $LogDir -Filter *.zip | Sort-Object LastWriteTime -Descending |
        Select-Object -Skip 300 | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ======================= INSTALL / STATUS =======================
function Test-Webhook($u) { return ($u -and $u -match '^https://(discord|discordapp)\.com/api/webhooks/') }

function Install-Relay {
    if (-not (Test-Admin)) { Write-Host 'Run this in an ADMIN PowerShell.' -ForegroundColor Red; return }
    if (-not (Test-Webhook $AlertWebhook) -or -not (Test-Webhook $LogWebhook)) {
        Write-Host '-AlertWebhook and -LogWebhook must be Discord webhook URLs (keep the quotes).' -ForegroundColor Red; return
    }
    if ($EarlyWebhook -and -not (Test-Webhook $EarlyWebhook)) { Write-Host '-EarlyWebhook is not a Discord webhook URL.' -ForegroundColor Red; return }

    New-Item -ItemType Directory -Force $Base, $Data, $LogDir | Out-Null
    if ($PSCommandPath -ne $Script) { Copy-Item $PSCommandPath $Script -Force }
    Save-Cfg @{ alert = $AlertWebhook; log = $LogWebhook; early = $EarlyWebhook }

    & icacls.exe $Base /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
    & icacls.exe 'C:\CF' /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null

    $subs = @('Logon','Credential Validation','Kerberos Authentication Service','Kerberos Service Ticket Operations',
              'User Account Management','Security Group Management','Process Creation','Account Lockout',
              'Other Object Access Events','Audit Policy Change','Security System Extension')
    foreach ($s in $subs) { & auditpol.exe /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }
    & reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

    foreach ($f in $StateFile, $SnapFile, $CheckState) { if (Test-Path $f) { Remove-Item $f -Force } }
    foreach ($n in $TaskRelay, $TaskCheck, $TaskArchive) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue }
    Register-RelayTasks | Out-Null
    Invoke-Alert      # start alert reading from "now"
    Invoke-Check      # capture the drift baseline

    Send-Discord $AlertWebhook @("Relay installed on $Box. LOOK NOW alerts every 1 min, drift check every 5 min.")
    Send-Discord $LogWebhook   @("Relay installed on $Box. Log files every 15 min.")
    if ($EarlyWebhook) { Send-Discord $EarlyWebhook @("Relay installed on $Box. Early warnings will post here.") }
    Write-Host "Installed. Script: $Script   Data: $Data" -ForegroundColor Green
    if (-not $EarlyWebhook) { Write-Host 'No early-warning webhook yet - early warnings go to the machine channel. Add later with -Mode SetEarly.' -ForegroundColor Yellow }
}

function Show-Status {
    foreach ($n in $WatchTasks) {
        $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
        if ($t) {
            $i = Get-ScheduledTaskInfo -TaskName $n
            Write-Host ("{0,-24} {1,-8} last run {2}  result {3}" -f $n, $t.State, $i.LastRunTime, $i.LastTaskResult)
        } else { Write-Host "$n : NOT INSTALLED" -ForegroundColor Yellow }
    }
    $cfg = Get-Cfg
    foreach ($k in 'alert','log','early') {
        $v = $cfg[$k]; if ($v) { $v = $v.Substring(0, [Math]::Min(45, $v.Length)) + '...' } else { $v = 'not set' }
        Write-Host "$k webhook: $v"
    }
    if (Test-Path $SnapFile) { Write-Host "Drift baseline: $(@(Get-Content $SnapFile).Count) items" }
    if (Test-Path $Unsent)   { Write-Host "Unsent messages waiting in $Unsent" -ForegroundColor Yellow }
}

switch ($Mode) {
    'Install'       { Install-Relay }
    'Install-Tasks' {
        # after copying a new relay.ps1 over the old one: re-create tasks, keep webhooks and state
        foreach ($n in $TaskRelay, $TaskCheck, $TaskArchive) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue }
        Register-RelayTasks | Out-Null
        if (-not (Test-Path $SnapFile)) { Invoke-Check }
        Write-Host 'Tasks re-created with the current script.' -ForegroundColor Green
    }
    'SetEarly' {
        if (-not (Test-Webhook $EarlyWebhook)) { Write-Host 'Give -EarlyWebhook a Discord webhook URL.' -ForegroundColor Red; break }
        $cfg = Get-Cfg; $cfg.early = $EarlyWebhook; Save-Cfg $cfg
        Send-Discord $EarlyWebhook @("Early warnings from $Box will post here.")
        Write-Host 'Early-warning webhook saved.' -ForegroundColor Green
    }
    'Alert'   { Invoke-Alert }
    'Check'   { Invoke-Check }
    'Export'  { Invoke-Export }
    'Test'    {
        $t = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Send-Now   @((New-Msg 'TEST' 'Machine channel test' $t $env:USERNAME '' 'If you can read this, LOOK NOW alerts work.'))
        Send-Early @((New-Msg 'TEST' 'Early-warning test' $t $env:USERNAME '' 'If you can read this, EARLY WARNING alerts work.'))
        Invoke-Export
        Write-Host 'Sent tests to the machine + early-warning channels and ran one log export.'
    }
    'Status'    { Show-Status }
    'Uninstall' {
        foreach ($n in $TaskRelay, $TaskCheck, $TaskArchive) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue }
        Write-Host 'Tasks removed. Files left in place:' $Base $Data
    }
}
