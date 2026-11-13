<#
.SYNOPSIS
    CyberForce 2026 - Windows live-defense toolkit.

.DESCRIPTION
    One script for the Windows boxes: snapshot the machine, flag risky settings,
    harden it from a numbered menu (every change logged with its undo command),
    diff against your baseline, hunt the event logs, and watch live for new
    processes, connections, users, services, and tasks.

    Output goes to C:\CF\<HOSTNAME>\  (changes.log, findings, snapshots, quarantine).

.EXAMPLE
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\CF-WinDefense.ps1 -Mode Baseline      # first 2 minutes
    .\CF-WinDefense.ps1 -Mode Audit         # flag risky settings + suspicious persistence
    .\CF-WinDefense.ps1 -Mode Harden        # numbered menu, asks before each change
    .\CF-WinDefense.ps1 -Mode Compare       # what changed since the baseline
    .\CF-WinDefense.ps1 -Mode Hunt -Minutes 60
    .\CF-WinDefense.ps1 -Mode Watch -Interval 10   # leave running in its own window
    . .\CF-WinDefense.ps1 -Mode Load        # load Block-CFIP, Stop-CFProc, Move-CFQuarantine, Get-CFEvents

.NOTES
    Run in Windows PowerShell 5.1 (or 7) as Administrator.
    Put the scoring engine's IP (one per line) in C:\CF\protected_ips.txt so Block-CFIP refuses to block it.
    Put Sysmon64.exe and a sysmonconfig*.xml next to this script for Harden option 21.
#>
[CmdletBinding()]
param(
    [ValidateSet('Help', 'Baseline', 'Audit', 'Compare', 'Harden', 'Hunt', 'Watch', 'Load')]
    [string]$Mode = 'Help',
    [string]$OutRoot = 'C:\CF',
    [int]$Interval = 10,
    [int]$Minutes = 60
)

# Our own deception + monitoring - never "clean these up"
$script:Canaries = @('svc_backup_old')
$script:OwnTasks = @{
    '\System Health Relay'   = 'cfrelay\\relay\.ps1'
    '\System Health Check'   = 'cfrelay\\relay\.ps1'
    '\System Health Archive' = 'cfrelay\\relay\.ps1'
    '\CF YARA Scan'          = 'yara\\yara-scan\.ps1'
}
# Assume Breach box (the HMI runs Ignition): this script will make NO changes there
$script:IsAssumeBreach = (Test-Path 'C:\Program Files\Inductive Automation') -or
                         [bool](Get-Service -Name 'Ignition*' -ErrorAction SilentlyContinue) -or
                         ($env:COMPUTERNAME -eq 'IP-0A000F8E')
if ($script:IsAssumeBreach) {
    Write-Host '*** ASSUME BREACH BOX (HMI) detected: read-only. Every change/action is refused - write findings down for the report. ***' -ForegroundColor Magenta
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$script:CFHost = $env:COMPUTERNAME
$script:CFDir = Join-Path $OutRoot $script:CFHost
$script:CFLog = Join-Path $script:CFDir 'changes.log'
$script:CFQuar = Join-Path $script:CFDir 'quarantine'
$script:CFBaseline = Join-Path $script:CFDir 'baseline.json'
$script:CFProtected = Join-Path $OutRoot 'protected_ips.txt'
$script:CFScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:Findings = New-Object System.Collections.ArrayList

foreach ($d in @($script:CFDir, $script:CFQuar)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$script:IsDC = ($cs -and $cs.DomainRole -ge 4)
$script:IsServer = ($os -and $os.ProductType -ne 1)
$script:HasAD = [bool](Get-Module -ListAvailable -Name ActiveDirectory)

# Things red team tends to use in persistence / command lines
$script:SusPattern = '(?i)(powershell|pwsh|cmd(\.exe)?\s+/c|\s-e(nc|ncodedcommand)?\s|frombase64|iex[\s(]|invoke-expression|downloadstring|downloadfile|invoke-webrequest|net\.webclient|bitsadmin|certutil|mshta|rundll32|regsvr32|wscript|cscript|\\temp\\|\\appdata\\|\\users\\public\\|\\perflogs\\|\\programdata\\[^\\]+\.(exe|dll|ps1|bat|vbs)|\.ps1|\.vbs|\.hta|\.bat\b|\.js\b)'

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Test-CFAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-CFLog {
    param([string]$Action, [string]$Undo = '(none)')
    $line = '{0} | {1} | {2} | UNDO: {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:USERNAME, $Action, $Undo
    Add-Content -Path $script:CFLog -Value $line
    Write-Host "    [logged] $Action" -ForegroundColor DarkGray
}

function Add-CFFinding {
    param([ValidateSet('HIGH', 'MED', 'INFO')][string]$Level, [string]$Area, [string]$Msg)
    $null = $script:Findings.Add([pscustomobject]@{ Level = $Level; Area = $Area; Finding = $Msg })
    $color = @{ HIGH = 'Red'; MED = 'Yellow'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0,-4}] {1,-14} {2}" -f $Level, $Area, $Msg) -ForegroundColor $color
}

function Write-CFHeader {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Get-CFReg {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Set-CFReg {
    param(
        [string]$Path, [string]$Name, $Value,
        [ValidateSet('DWord', 'String', 'ExpandString', 'MultiString', 'QWord')][string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $old = Get-CFReg $Path $Name
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    if ($null -eq $old) {
        $undo = "Remove-ItemProperty -Path '$Path' -Name '$Name'"
    }
    else {
        $undo = "Set-ItemProperty -Path '$Path' -Name '$Name' -Value '$($old -join ',')'"
    }
    Write-CFLog "Set $Path\$Name = $Value (was: $($old -join ','))" $undo
}

function Confirm-CF {
    param([string]$Question)
    if ($script:IsAssumeBreach) {
        Write-Host "$Question -> NO (Assume Breach box: no changes. Note it for the report.)" -ForegroundColor Magenta
        return $false
    }
    $a = Read-Host "$Question [y/N]"
    return ($a -match '^(y|yes)$')
}

function Get-CFGroupMembers {
    param([string]$Group)
    try {
        Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object { "$($_.Name)|$($_.ObjectClass)" }
    }
    catch {
        # Get-LocalGroupMember breaks on orphaned SIDs; fall back to net.exe
        $raw = net localgroup "$Group" 2>$null
        if ($raw) {
            $raw | Select-Object -Skip 6 |
                Where-Object { $_ -and $_ -notmatch 'command completed' -and $_ -notmatch '^-+$' } |
                ForEach-Object { "$($_.Trim())|net" }
        }
    }
}

function Get-CFProcMap {
    $map = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $map[[int]$_.Id] = $_.ProcessName }
    return $map
}

function Get-CFRunKeys {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    # every loaded user hive, not just the current user
    Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
            $keys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            $keys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            [pscustomobject]@{ Key = $k; Name = $p.Name; Value = [string]$p.Value }
        }
    }
}

function Get-CFTasks {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $acts = ($_.Actions | ForEach-Object {
                if ($_.Execute) { ("$($_.Execute) $($_.Arguments)").Trim() } else { "COM:$($_.ClassId)" }
            }) -join ' ; '
        [pscustomobject]@{
            Task    = "$($_.TaskPath)$($_.TaskName)"
            State   = [string]$_.State
            Author  = $_.Author
            RunAs   = $_.Principal.UserId
            Actions = $acts
        }
    }
}

function Get-CFWmiPersistence {
    $ns = 'root\subscription'
    Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Type = 'Filter'; Name = $_.Name; Detail = $_.Query }
    }
    Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Type = 'CmdLineConsumer'; Name = $_.Name; Detail = "$($_.ExecutablePath) $($_.CommandLineTemplate)" }
    }
    Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Type = 'ScriptConsumer'; Name = $_.Name; Detail = "$($_.ScriptFileName) $($_.ScriptText)" }
    }
    Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Type = 'Binding'; Name = "$($_.Filter.Name) -> $($_.Consumer.Name)"; Detail = '' }
    }
}

function Get-CFListeners {
    $pm = Get-CFProcMap
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Proto = 'TCP'; Local = "$($_.LocalAddress):$($_.LocalPort)"; Port = $_.LocalPort; PID = $_.OwningProcess; Proc = $pm[[int]$_.OwningProcess] }
    }
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Proto = 'UDP'; Local = "$($_.LocalAddress):$($_.LocalPort)"; Port = $_.LocalPort; PID = $_.OwningProcess; Proc = $pm[[int]$_.OwningProcess] }
    }
}

function Get-CFUsers {
    if ($script:IsDC -and $script:HasAD) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Get-ADUser -Filter * -Properties Enabled, whenCreated, PasswordLastSet, LastLogonDate -ErrorAction SilentlyContinue |
            Select-Object @{n = 'Name'; e = { $_.SamAccountName } }, Enabled, whenCreated, PasswordLastSet, LastLogonDate
    }
    else {
        Get-LocalUser -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, @{n = 'SID'; e = { $_.SID.Value } }, LastLogon, PasswordLastSet, PasswordExpires
    }
}

function Get-CFPrivMembers {
    $out = @()
    if ($script:IsDC -and $script:HasAD) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $groups = 'Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins', 'Backup Operators',
        'Account Operators', 'Server Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Remote Desktop Users'
        foreach ($g in $groups) {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue |
                ForEach-Object { $out += "$g|$($_.SamAccountName)" }
        }
    }
    else {
        foreach ($g in 'Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators') {
            Get-CFGroupMembers $g | ForEach-Object { $out += "$g|$_" }
        }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Event log helper (also used interactively after -Mode Load)
# ---------------------------------------------------------------------------
function Get-CFEvents {
    <#
      Get-CFEvents Security 4625 -Minutes 30 | group IpAddress | sort Count -Desc
      Every EventData field becomes a column (TargetUserName, IpAddress, LogonType, ServiceName, ...).
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$LogName,
        [Parameter(Mandatory = $true, Position = 1)][int[]]$Id,
        [int]$Minutes = 60,
        [int]$Max = 5000
    )
    $filter = @{ LogName = $LogName; Id = $Id; StartTime = (Get-Date).AddMinutes(-$Minutes) }
    Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction SilentlyContinue | ForEach-Object {
        $o = [ordered]@{ TimeCreated = $_.TimeCreated; Id = $_.Id }
        try {
            $x = [xml]$_.ToXml()
            foreach ($d in $x.Event.EventData.Data) {
                if ($d.Name) { $o[$d.Name] = $d.'#text' }
            }
            if ($x.Event.UserData) { $o['UserData'] = $x.Event.UserData.InnerText }
        }
        catch { }
        [pscustomobject]$o
    }
}

# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------
function Block-CFIP {
    <# Block-CFIP 10.0.0.66   - blocks ONE address inbound AND outbound.
       2026 CyberForce rules: single IPs may be blocked; subnets/ranges and allow-lists are NOT allowed,
       and any blocked IP might be used for scoring (point loss if scoring breaks). #>
    param([Parameter(Mandatory = $true)][string[]]$IP)
    if ($script:IsAssumeBreach) { Write-Host 'Assume Breach box: no changes allowed here. Note it for the report.' -ForegroundColor Magenta; return }
    Write-Host '2026 rules: single IPs only, never a subnet or allow-list. Blocked IPs may be used for scoring - watch your service checks after.' -ForegroundColor Yellow
    $protected = @()
    if (Test-Path $script:CFProtected) { $protected = Get-Content $script:CFProtected | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
    foreach ($a in $IP) {
        $parsed = $null
        if ($a -match '[/\-*]' -or -not [System.Net.IPAddress]::TryParse($a, [ref]$parsed)) {
            Write-Host "REFUSED: '$a' is not a single IP address (subnets/ranges are prohibited by the 2026 rules)." -ForegroundColor Red
            continue
        }
        if ($protected -contains $a) {
            Write-Host "REFUSED: $a is in $($script:CFProtected) (scoring engine / protected)." -ForegroundColor Red
            continue
        }
        $name = "CF Block $a"
        New-NetFirewallRule -DisplayName "$name IN" -Direction Inbound -RemoteAddress $a -Action Block -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "$name OUT" -Direction Outbound -RemoteAddress $a -Action Block -Profile Any | Out-Null
        # firewall rules don't cut connections that are already open - show them so you can kill the process
        $live = Get-NetTCPConnection -RemoteAddress $a -ErrorAction SilentlyContinue
        if ($live) {
            Write-Host "  Live connections to/from $a (owning PIDs): $(($live.OwningProcess | Sort-Object -Unique) -join ', ')" -ForegroundColor Yellow
        }
        Write-CFLog "Blocked IP $a (in+out)" "Remove-NetFirewallRule -DisplayName '$name IN','$name OUT'"
        Write-Host "Blocked $a" -ForegroundColor Green
    }
}

function Stop-CFProc {
    <# Stop-CFProc 1234 [-Quarantine]   - kills the process and its children, logs the details #>
    param([Parameter(Mandatory = $true)][int]$Id, [switch]$Quarantine)
    if ($script:IsAssumeBreach) { Write-Host 'Assume Breach box: no changes allowed here. Note it for the report.' -ForegroundColor Magenta; return }
    $all = Get-CimInstance Win32_Process
    $target = $all | Where-Object { $_.ProcessId -eq $Id }
    if (-not $target) { Write-Host "No process $Id" -ForegroundColor Yellow; return }
    $kill = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($Id)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($kill -contains $cur) { continue }
        $null = $kill.Add($cur)
        $all | Where-Object { $_.ParentProcessId -eq $cur -and $_.ProcessId -ne $cur } | ForEach-Object { $queue.Enqueue([int]$_.ProcessId) }
    }
    $path = $target.ExecutablePath
    Write-CFLog "Killing PID $Id ($($target.Name)) path=$path cmd=$($target.CommandLine) parent=$($target.ParentProcessId) tree=$($kill -join ',')" '(restart the program if it was legitimate)'
    $kill.Reverse()
    foreach ($p in $kill) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
    Write-Host "Killed: $($kill -join ', ')" -ForegroundColor Green
    if ($Quarantine -and $path) { Start-Sleep -Milliseconds 500; Move-CFQuarantine $path }
}

function Move-CFQuarantine {
    <# Move-CFQuarantine C:\path\evil.exe   - hashes it, moves it to C:\CF\<host>\quarantine #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($script:IsAssumeBreach) { Write-Host 'Assume Breach box: no changes allowed here. Note it for the report.' -ForegroundColor Magenta; return }
    if (-not (Test-Path -LiteralPath $Path)) { Write-Host "Not found: $Path" -ForegroundColor Yellow; return }
    $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $name = Split-Path $Path -Leaf
    $dest = Join-Path $script:CFQuar ("{0}_{1}.quarantined" -f $h.Substring(0, 12), $name)
    try {
        Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        Add-Content -Path (Join-Path $script:CFQuar 'quarantine_index.txt') -Value ("{0} | {1} | {2} | {3}" -f (Get-Date -Format s), $h, $Path, $dest)
        Write-CFLog "Quarantined $Path (SHA256 $h)" "Move-Item '$dest' '$Path'"
        Write-Host "Quarantined -> $dest" -ForegroundColor Green
    }
    catch {
        Write-Host "Could not move $Path ($($_.Exception.Message)). Kill the process using it first, or take ownership:" -ForegroundColor Yellow
        Write-Host "  takeown /f `"$Path`"; icacls `"$Path`" /grant administrators:F" -ForegroundColor Yellow
    }
}

function Remove-CFWmiPersistence {
    <# Remove-CFWmiPersistence -Name 'EvilFilter'  - removes filter/consumer/binding objects whose name matches #>
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:IsAssumeBreach) { Write-Host 'Assume Breach box: no changes allowed here. Note it for the report.' -ForegroundColor Magenta; return }
    $ns = 'root\subscription'
    Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Where-Object { $_.Filter.Name -eq $Name -or $_.Consumer.Name -eq $Name } | Remove-CimInstance
    foreach ($cls in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
        Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $Name } | Remove-CimInstance
    }
    Write-CFLog "Removed WMI persistence objects named $Name" '(re-create only if it was legitimate)'
}

# ---------------------------------------------------------------------------
# Snapshot / state
# ---------------------------------------------------------------------------
function Get-CFState {
    # Compact, comparable view of everything red team likes to change.
    $s = [ordered]@{}
    $s.Users = @(Get-CFUsers | ForEach-Object { "$($_.Name)|enabled=$($_.Enabled)" })
    $s.PrivGroups = @(Get-CFPrivMembers)
    $s.Services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.StartMode)|$($_.StartName)|$($_.PathName)" })
    $s.Tasks = @(Get-CFTasks | ForEach-Object { "$($_.Task)|$($_.RunAs)|$($_.Actions)" })
    $s.RunKeys = @(Get-CFRunKeys | ForEach-Object { "$($_.Key)|$($_.Name)|$($_.Value)" })
    $startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
    @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    $s.StartupFiles = @(Get-ChildItem $startup -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { $_.FullName })
    $s.WMI = @(Get-CFWmiPersistence | ForEach-Object { "$($_.Type)|$($_.Name)|$($_.Detail)" })
    $s.Listeners = @(Get-CFListeners | ForEach-Object { "$($_.Proto)|$($_.Local)|$($_.Proc)" } | Sort-Object -Unique)
    $s.Shares = @(Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Path)" })
    $s.FirewallAllowIn = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName } | Sort-Object -Unique)
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    $ex = @()
    if ($mp) {
        $ex += @($mp.ExclusionPath | Where-Object { $_ } | ForEach-Object { "Path|$_" })
        $ex += @($mp.ExclusionProcess | Where-Object { $_ } | ForEach-Object { "Process|$_" })
        $ex += @($mp.ExclusionExtension | Where-Object { $_ } | ForEach-Object { "Ext|$_" })
        $ex += @($mp.ExclusionIpAddress | Where-Object { $_ } | ForEach-Object { "IP|$_" })
    }
    $s.DefenderExclusions = $ex
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $s.IFEO = @(Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = Get-CFReg $_.PSPath 'Debugger'
            if ($dbg) { "$($_.PSChildName)|$dbg" }
        })
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $s.Winlogon = @("Userinit|$(Get-CFReg $wl 'Userinit')", "Shell|$(Get-CFReg $wl 'Shell')")
    $s.Accessibility = @('sethc', 'utilman', 'osk', 'Magnify', 'Narrator', 'DisplaySwitch', 'AtBroker') | ForEach-Object {
        $f = "$env:windir\System32\$_.exe"
        if (Test-Path $f) { "$_|$((Get-FileHash $f -Algorithm SHA256).Hash)" }
    }
    $keyFiles = @('C:\ProgramData\ssh\administrators_authorized_keys') +
    @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' })
    $s.SSHKeys = @($keyFiles | Where-Object { Test-Path $_ } | ForEach-Object { $f = $_; Get-Content $f | Where-Object { $_.Trim() } | ForEach-Object { "$f|$_" } })
    return $s
}

function Save-CFSnapshot {
    param([string]$Label = 'snap')
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dir = Join-Path $script:CFDir "${Label}_$stamp"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-Host "Saving snapshot to $dir ..." -ForegroundColor Cyan

    $save = {
        param($name, [scriptblock]$sb, [switch]$Text)
        try {
            $data = & $sb
            $p = Join-Path $dir $name
            if ($Text) { $data | Out-File -FilePath $p -Width 400 -Encoding utf8 }
            else { $data | Export-Csv -Path $p -NoTypeInformation -Encoding utf8 }
        }
        catch { Write-Host "  (skipped $name : $($_.Exception.Message))" -ForegroundColor DarkGray }
    }

    & $save 'system.txt' { "Host: $env:COMPUTERNAME"; "DC: $script:IsDC  Server: $script:IsServer"; ($os | Format-List Caption, Version, BuildNumber, LastBootUpTime, InstallDate | Out-String); ipconfig /all } -Text
    & $save 'users.csv' { Get-CFUsers }
    & $save 'priv_groups.txt' { Get-CFPrivMembers } -Text
    & $save 'sessions.txt' { '== quser'; quser 2>&1; '== qwinsta'; qwinsta 2>&1; '== SMB sessions'; Get-SmbSession | Format-Table -AutoSize | Out-String } -Text
    & $save 'listeners.csv' { Get-CFListeners }
    & $save 'established.csv' {
        $pm = Get-CFProcMap
        Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{n = 'Proc'; e = { $pm[[int]$_.OwningProcess] } }
    }
    & $save 'processes.csv' { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate }
    & $save 'services.csv' { Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName }
    & $save 'tasks.csv' { Get-CFTasks }
    & $save 'runkeys.csv' { Get-CFRunKeys }
    & $save 'wmi_persistence.csv' { Get-CFWmiPersistence }
    & $save 'shares.csv' { Get-SmbShare | Select-Object Name, Path, Description }
    & $save 'firewall_profiles.csv' { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogFileName }
    & $save 'firewall_inbound_allow.csv' { Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Select-Object DisplayName, Profile, Group, Description }
    & $save 'defender.txt' { Get-MpComputerStatus | Format-List | Out-String; Get-MpPreference | Format-List Exclusion*, DisableRealtimeMonitoring, EnableNetworkProtection, AttackSurfaceReductionRules_* | Out-String } -Text
    & $save 'hotfixes.csv' { Get-HotFix | Select-Object HotFixID, InstalledOn, Description }
    & $save 'software.csv' {
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
            ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } | Where-Object DisplayName |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    & $save 'auditpol.txt' { auditpol /get /category:* } -Text
    & $save 'smb.txt' { Get-SmbServerConfiguration | Format-List EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature | Out-String } -Text
    & $save 'dnscache.csv' { Get-DnsClientCache | Select-Object Entry, Data }
    & $save 'hosts.txt' { Get-Content "$env:windir\System32\drivers\etc\hosts" } -Text
    & $save 'arp.csv' { Get-NetNeighbor -State Reachable, Stale | Select-Object IPAddress, LinkLayerAddress, State }
    try { secedit /export /cfg (Join-Path $dir 'secpol.inf') /quiet | Out-Null } catch { }
    if ($script:IsDC -and $script:HasAD) {
        & $save 'gpos.csv' { Import-Module GroupPolicy -ErrorAction SilentlyContinue; Get-GPO -All | Select-Object DisplayName, Id, ModificationTime, Owner }
    }

    $state = Get-CFState
    $statePath = Join-Path $dir 'state.json'
    $state | ConvertTo-Json -Depth 4 | Out-File -FilePath $statePath -Encoding utf8
    Write-Host "Snapshot done." -ForegroundColor Green
    return @{ Dir = $dir; State = $state; StatePath = $statePath }
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
function Invoke-CFBaseline {
    Write-CFHeader "BASELINE - $script:CFHost  (DC=$script:IsDC)"
    $r = Save-CFSnapshot -Label 'baseline'
    Copy-Item $r.StatePath $script:CFBaseline -Force
    Write-CFLog "Baseline saved ($($r.Dir))" '(n/a)'
    Write-Host ''
    Write-Host "Baseline saved to $script:CFBaseline" -ForegroundColor Green
    Write-Host 'Counts:' -ForegroundColor Cyan
    foreach ($k in $r.State.Keys) { Write-Host ("  {0,-20} {1}" -f $k, @($r.State[$k]).Count) }
    Write-Host ''
    Write-Host 'Next: .\CF-WinDefense.ps1 -Mode Audit' -ForegroundColor Cyan
}

function Invoke-CFAudit {
    Write-CFHeader "AUDIT - $script:CFHost  (DC=$script:IsDC, Server=$script:IsServer)"
    $script:Findings.Clear()

    # --- Defender ---
    $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $st) { Add-CFFinding HIGH 'Defender' 'Defender status unavailable (removed, disabled, or another AV in use)' }
    else {
        if (-not $st.AMServiceEnabled) { Add-CFFinding HIGH 'Defender' 'Antimalware service disabled' }
        if (-not $st.RealTimeProtectionEnabled) { Add-CFFinding HIGH 'Defender' 'Real-time protection OFF' }
        if (-not $st.BehaviorMonitorEnabled) { Add-CFFinding MED 'Defender' 'Behavior monitoring OFF' }
        if (-not $st.IsTamperProtected) { Add-CFFinding INFO 'Defender' 'Tamper protection not on (red team can change Defender settings)' }
    }
    if ($mp) {
        foreach ($e in @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) + @($mp.ExclusionIpAddress)) {
            if ($e) { Add-CFFinding HIGH 'Defender' "Exclusion present: $e  (Harden 1 removes)" }
        }
    }

    # --- Credentials / LSA ---
    if ((Get-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1) {
        Add-CFFinding HIGH 'Creds' 'WDigest UseLogonCredential=1 (plaintext passwords in LSASS)'
    }
    if ((Get-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -ne 1) { Add-CFFinding MED 'Creds' 'LSA protection (RunAsPPL) off' }
    if ((Get-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy') -eq 1) {
        Add-CFFinding MED 'Creds' 'LocalAccountTokenFilterPolicy=1 (remote local-admin / pass-the-hash allowed)'
    }
    if ((Get-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 0) { Add-CFFinding HIGH 'UAC' 'UAC disabled (EnableLUA=0)' }
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ((Get-CFReg $lsa 'RestrictAnonymous') -ne 1) { Add-CFFinding MED 'Anon' 'RestrictAnonymous not set' }
    if ((Get-CFReg $lsa 'EveryoneIncludesAnonymous') -eq 1) { Add-CFFinding HIGH 'Anon' 'EveryoneIncludesAnonymous=1' }
    $pkgs = @(Get-CFReg $lsa 'Security Packages') + @(Get-CFReg $lsa 'Authentication Packages') + @(Get-CFReg $lsa 'Notification Packages')
    $knownPkgs = 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'scecli', 'rassfm', '""', ''
    foreach ($p in $pkgs) { if ($p -and ($knownPkgs -notcontains $p.ToLower())) { Add-CFFinding MED 'LSA' "Unusual LSA package: $p (check it - password filter/SSP backdoor?)" } }

    # --- Accounts ---
    $users = @(Get-CFUsers)
    $guest = $users | Where-Object { $_.Name -eq 'Guest' }
    if ($guest -and $guest.Enabled) { Add-CFFinding HIGH 'Accounts' 'Guest account enabled' }
    Add-CFFinding INFO 'Accounts' ("{0} users ({1} enabled)" -f $users.Count, @($users | Where-Object Enabled).Count)
    foreach ($m in Get-CFPrivMembers) { Add-CFFinding INFO 'PrivGroup' $m }
    if (-not $script:IsDC) {
        $pne = @($users | Where-Object { $_.Enabled -and -not $_.PasswordExpires -and $_.Name -notin 'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount' })
        if ($pne.Count) { Add-CFFinding INFO 'Accounts' "$($pne.Count) enabled accounts with passwords that never expire (full list in users.csv)" }
        $users | Where-Object { $_.Enabled -and $_.Name -match '(?i)^(old|temp|tmp|test|vendor|contractor)[._-]|\$$' } |
            ForEach-Object { Add-CFFinding MED 'Accounts' "Stale/odd account still enabled: $($_.Name)" }
    }
    elseif ($script:HasAD) {
        Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName -ErrorAction SilentlyContinue |
            Where-Object { $_.SamAccountName -ne 'krbtgt' } |
            ForEach-Object {
                if ($script:Canaries -contains $_.SamAccountName) { Add-CFFinding INFO 'Kerberos' "$($_.SamAccountName) = OUR CANARY (fake SPN on purpose) - leave it" }
                else { Add-CFFinding MED 'Kerberos' "Kerberoastable account: $($_.SamAccountName) ($($_.ServicePrincipalName -join ', '))" }
            }
        Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -ErrorAction SilentlyContinue |
            ForEach-Object { Add-CFFinding HIGH 'Kerberos' "AS-REP roastable (no pre-auth): $($_.SamAccountName)" }
        Get-ADUser -Filter * -Properties whenCreated -ErrorAction SilentlyContinue | Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-1) -and $script:Canaries -notcontains $_.SamAccountName } |
            ForEach-Object { Add-CFFinding MED 'Accounts' "Created in last 24h: $($_.SamAccountName) at $($_.whenCreated)" }
    }

    # --- Network services ---
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smb) {
        if ($smb.EnableSMB1Protocol) { Add-CFFinding HIGH 'SMB' 'SMBv1 enabled' }
        if (-not $smb.RequireSecuritySignature) { Add-CFFinding MED 'SMB' 'SMB signing not required (relay attacks)' }
    }
    if ((Get-CFReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -ne 0) { Add-CFFinding MED 'Network' 'LLMNR enabled (Responder poisoning)' }
    $nbt = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction SilentlyContinue | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
    if ($nbt) { Add-CFFinding MED 'Network' 'NetBIOS over TCP/IP enabled on at least one adapter' }
    $rdpOff = Get-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($rdpOff -eq 0) {
        Add-CFFinding INFO 'RDP' 'RDP enabled'
        if ((Get-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -ne 1) { Add-CFFinding MED 'RDP' 'RDP without NLA' }
    }
    if ((Get-Service WinRM -ErrorAction SilentlyContinue).Status -eq 'Running') { Add-CFFinding INFO 'WinRM' 'WinRM running (lateral movement path - disable if not needed)' }
    $sp = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($sp -and $sp.Status -eq 'Running') {
        if ($script:IsDC) { Add-CFFinding HIGH 'Spooler' 'Print Spooler running on a DC (PrintNightmare / coercion)' } else { Add-CFFinding INFO 'Spooler' 'Print Spooler running' }
    }
    $proxy = (netsh winhttp show proxy) -join ' '
    if ($proxy -notmatch 'Direct access') { Add-CFFinding MED 'Network' "WinHTTP proxy set: $proxy" }
    $hosts = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' }
    foreach ($h in $hosts) { Add-CFFinding MED 'Network' "hosts file entry: $h" }

    # --- Firewall ---
    foreach ($p in Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        if (-not $p.Enabled) { Add-CFFinding HIGH 'Firewall' "$($p.Name) profile DISABLED" }
        if ($p.DefaultInboundAction -eq 'Allow') { Add-CFFinding MED 'Firewall' "$($p.Name) default inbound = Allow" }
    }
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Group -and $_.DisplayName -notlike 'CF *' } |
        ForEach-Object { Add-CFFinding INFO 'Firewall' "Custom inbound allow rule: $($_.DisplayName)" }

    # --- Listening ports ---
    foreach ($l in Get-CFListeners | Where-Object { $_.Proto -eq 'TCP' } | Sort-Object Port -Unique) {
        Add-CFFinding INFO 'Listening' ("TCP {0,-6} {1} (PID {2})" -f $l.Port, $l.Proc, $l.PID)
    }

    # --- Logging ---
    if ((Get-CFReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -ne 1) { Add-CFFinding MED 'Logging' 'PowerShell script block logging off (Harden 6)' }
    if ((Get-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -ne 1) { Add-CFFinding MED 'Logging' 'Command line not recorded in 4688 (Harden 5)' }
    $pc = (auditpol /get /subcategory:"Process Creation") -join ' '
    if ($pc -match 'No Auditing') { Add-CFFinding MED 'Logging' 'Process Creation auditing off (Harden 4)' }
    if (-not (Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue)) { Add-CFFinding INFO 'Logging' 'Sysmon not installed (Harden 21)' }
    try {
        if ($script:IsServer) {
            $v2 = Get-WindowsFeature PowerShell-V2 -ErrorAction Stop
            if ($v2.Installed) { Add-CFFinding MED 'PowerShell' 'PowerShell v2 installed (logging bypass) - Harden 8' }
        }
        else {
            $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
            if ($v2.State -eq 'Enabled') { Add-CFFinding MED 'PowerShell' 'PowerShell v2 enabled (logging bypass) - Harden 8' }
        }
    }
    catch { }

    # --- Persistence ---
    $cmdHash = (Get-FileHash "$env:windir\System32\cmd.exe").Hash
    $psHash = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -ErrorAction SilentlyContinue).Hash
    foreach ($b in 'sethc', 'utilman', 'osk', 'Magnify', 'Narrator', 'DisplaySwitch', 'AtBroker') {
        $f = "$env:windir\System32\$b.exe"
        if (-not (Test-Path $f)) { continue }
        $hash = (Get-FileHash $f).Hash
        $sig = Get-AuthenticodeSignature $f
        if ($hash -eq $cmdHash -or $hash -eq $psHash) { Add-CFFinding HIGH 'Backdoor' "$b.exe is a copy of cmd/powershell (sticky-keys backdoor)" }
        elseif ($sig.Status -ne 'Valid') { Add-CFFinding HIGH 'Backdoor' "$b.exe signature not valid ($($sig.Status))" }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = Get-CFReg $_.PSPath 'Debugger'
        if ($dbg) { Add-CFFinding HIGH 'IFEO' "Debugger set for $($_.PSChildName): $dbg" }
        $gf = Get-CFReg $_.PSPath 'GlobalFlag'
        if ($gf -eq 512) { Add-CFFinding HIGH 'IFEO' "SilentProcessExit monitor on $($_.PSChildName)" }
    }
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $ui = Get-CFReg $wl 'Userinit'; $sh = Get-CFReg $wl 'Shell'
    if ($ui -and $ui.TrimEnd(',').ToLower() -ne 'c:\windows\system32\userinit.exe') { Add-CFFinding HIGH 'Winlogon' "Userinit modified: $ui" }
    if ($sh -and $sh.ToLower() -ne 'explorer.exe') { Add-CFFinding HIGH 'Winlogon' "Shell modified: $sh" }
    $appinit = Get-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs'
    if ($appinit) { Add-CFFinding HIGH 'AppInit' "AppInit_DLLs set: $appinit" }
    foreach ($w in Get-CFWmiPersistence) {
        if ($w.Type -eq 'Filter' -and $w.Name -in 'SCM Event Log Filter', 'BVTFilter') { continue }
        if ($w.Type -eq 'Binding' -and $w.Name -match 'SCM Event Log|BVT') { continue }
        $lvl = if ($w.Type -match 'Consumer') { 'HIGH' } else { 'MED' }
        Add-CFFinding $lvl 'WMI' "$($w.Type): $($w.Name) $($w.Detail)"
    }
    foreach ($r in Get-CFRunKeys) {
        $lvl = if ($r.Value -match $script:SusPattern) { 'HIGH' } else { 'INFO' }
        Add-CFFinding $lvl 'RunKey' "$($r.Name) = $($r.Value)  [$($r.Key)]"
    }
    foreach ($t in Get-CFTasks | Where-Object { $_.Task -notlike '\Microsoft\*' }) {
        if ($script:OwnTasks.ContainsKey($t.Task) -and $t.Actions -match $script:OwnTasks[$t.Task]) {
            Add-CFFinding INFO 'Task' "$($t.Task) = OUR monitoring task [$($t.State)] - leave it"
            continue
        }
        $lvl = if ($t.Actions -match $script:SusPattern) { 'HIGH' } else { 'MED' }
        Add-CFFinding $lvl 'Task' "$($t.Task) [$($t.State)] runas=$($t.RunAs) -> $($t.Actions)"
    }
    foreach ($t in Get-CFTasks | Where-Object { $_.Task -like '\Microsoft\*' -and $_.Actions -match '(?i)(powershell|cmd\.exe|mshta|\\temp\\|\\appdata\\|\\users\\public)' -and $_.Actions -notmatch '(?i)(silcollector\.cmd|dsregcmd\.exe)' }) {
        Add-CFFinding HIGH 'Task' "Odd action hiding in a Microsoft task path: $($t.Task) -> $($t.Actions)"
    }
    foreach ($s in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        $pn = [string]$s.PathName
        if ($pn -match $script:SusPattern -and $pn -notmatch '(?i)^"?c:\\windows\\system32\\svchost\.exe') {
            Add-CFFinding HIGH 'Service' "$($s.Name) [$($s.StartMode)/$($s.State)] -> $pn"
        }
        elseif ($pn -and $pn -notmatch '^"' -and $pn -match '^[^"]*\s[^"]*\.exe' -and $pn -notmatch '(?i)^c:\\windows\\') {
            Add-CFFinding MED 'Service' "Unquoted path with spaces: $($s.Name) -> $pn"
        }
    }
    $startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
    @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    $wsh = New-Object -ComObject WScript.Shell
    Get-ChildItem $startup -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } |
        ForEach-Object {
            $tgt = ''
            if ($_.Extension -eq '.lnk') { $l = $wsh.CreateShortcut($_.FullName); $tgt = "$($l.TargetPath) $($l.Arguments)".Trim() }
            elseif ($_.Extension -in '.cmd', '.bat', '.ps1', '.vbs', '.txt') {
                $tgt = ((Get-Content $_.FullName -TotalCount 5 -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*(@?echo off|rem\b|::)' }) -join ' | ')
                if ($tgt.Length -gt 160) { $tgt = $tgt.Substring(0, 160) + '...' }
            }
            # AWS EC2Launch sets the desktop wallpaper this way on every AMI - normal
            if ($tgt -match '(?i)EC2Launch\.exe"?\s+wallpaper') { return }
            Add-CFFinding HIGH 'Startup' "$($_.FullName) -> $tgt"
        }
    foreach ($kf in @('C:\ProgramData\ssh\administrators_authorized_keys') + @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' })) {
        if (Test-Path $kf) { Add-CFFinding MED 'SSH' "authorized_keys present: $kf ($(@(Get-Content $kf | Where-Object { $_.Trim() }).Count) keys)" }
    }
    Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { Add-CFFinding MED 'BITS' "BITS job: $($_.DisplayName) owner=$($_.OwnerAccount)" }

    # --- Save ---
    $fpath = Join-Path $script:CFDir ("findings_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $script:Findings | Export-Csv $fpath -NoTypeInformation -Encoding utf8
    $hi = @($script:Findings | Where-Object Level -eq 'HIGH').Count
    $md = @($script:Findings | Where-Object Level -eq 'MED').Count
    Write-Host ''
    Write-Host "HIGH: $hi   MED: $md   -> $fpath" -ForegroundColor $(if ($hi) { 'Red' } else { 'Green' })
    Write-Host 'Next: fix HIGH items, then .\CF-WinDefense.ps1 -Mode Harden' -ForegroundColor Cyan
}

function Invoke-CFCompare {
    Write-CFHeader "COMPARE vs BASELINE - $script:CFHost"
    if (-not (Test-Path $script:CFBaseline)) { Write-Host 'No baseline yet. Run -Mode Baseline first.' -ForegroundColor Yellow; return }
    $base = Get-Content $script:CFBaseline -Raw | ConvertFrom-Json
    $cur = Get-CFState
    $changes = 0
    $hot = 'Users', 'PrivGroups', 'Services', 'Tasks', 'RunKeys', 'StartupFiles', 'WMI', 'IFEO', 'Winlogon', 'Accessibility', 'SSHKeys', 'DefenderExclusions'
    foreach ($k in $cur.Keys) {
        $old = @($base.$k | Where-Object { $_ -ne $null })
        $new = @($cur[$k] | Where-Object { $_ -ne $null })
        $oldSet = @{}; foreach ($i in $old) { $oldSet[[string]$i] = $true }
        $newSet = @{}; foreach ($i in $new) { $newSet[[string]$i] = $true }
        $added = @($new | Where-Object { -not $oldSet.ContainsKey([string]$_) })
        $removed = @($old | Where-Object { -not $newSet.ContainsKey([string]$_) })
        if ($added.Count -or $removed.Count) {
            Write-Host ''
            Write-Host "[$k]" -ForegroundColor Cyan
            foreach ($a in $added) { Write-Host "  + NEW   $a" -ForegroundColor $(if ($hot -contains $k) { 'Red' } else { 'Yellow' }); $changes++ }
            foreach ($r in $removed) { Write-Host "  - GONE  $r" -ForegroundColor DarkYellow; $changes++ }
        }
    }
    Write-Host ''
    if ($changes -eq 0) { Write-Host 'No changes since baseline.' -ForegroundColor Green }
    else {
        Write-Host "$changes change(s). Red = persistence/account areas: investigate first." -ForegroundColor Yellow
        if (Confirm-CF 'Accept the current state as the new baseline (only if every change above is yours)?') {
            $cur | ConvertTo-Json -Depth 4 | Out-File $script:CFBaseline -Encoding utf8
            Write-CFLog 'Baseline updated from Compare' '(older baseline snapshots remain in baseline_* folders)'
        }
    }
}

function Invoke-CFHunt {
    param([int]$Min = 60)
    Write-CFHeader "HUNT - last $Min minutes - $script:CFHost"
    $script:Findings.Clear()

    # Failed logons
    $f = @(Get-CFEvents Security 4625 -Minutes $Min)
    if ($f.Count) {
        $f | Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 10 |
            ForEach-Object { Add-CFFinding $(if ($_.Count -ge 10) { 'HIGH' } else { 'MED' }) 'FailedLogon' ("{0} failures from {1} (users: {2})" -f $_.Count, $_.Name, (($_.Group.TargetUserName | Sort-Object -Unique) -join ',')) }
    }
    # Network / RDP logons
    Get-CFEvents Security 4624 -Minutes $Min |
        Where-Object { $_.LogonType -in '3', '10' -and $_.TargetUserName -notmatch '\$$' -and $_.TargetUserName -ne 'ANONYMOUS LOGON' } |
        Group-Object TargetUserName, IpAddress, LogonType | ForEach-Object {
            $e = $_.Group[0]
            $t = if ($e.LogonType -eq '10') { 'RDP' } else { 'Network' }
            Add-CFFinding INFO 'Logon' ("{0} logon(s): {1}\{2} from {3} ({4})" -f $_.Count, $e.TargetDomainName, $e.TargetUserName, $e.IpAddress, $t)
        }
    # Explicit credential use
    Get-CFEvents Security 4648 -Minutes $Min | Where-Object { $_.SubjectUserName -notmatch '\$$' } | Select-Object -First 20 |
        ForEach-Object { Add-CFFinding MED 'ExplicitCred' ("{0} {1} used creds of {2} -> {3} ({4})" -f $_.TimeCreated, $_.SubjectUserName, $_.TargetUserName, $_.TargetServerName, $_.ProcessName) }
    # Account changes
    $acctNames = @{ 4720 = 'user created'; 4722 = 'user enabled'; 4724 = 'password reset'; 4726 = 'user deleted'; 4728 = 'added to global group'; 4732 = 'added to local group'; 4738 = 'user changed'; 4740 = 'locked out'; 4756 = 'added to universal group' }
    Get-CFEvents Security 4720, 4722, 4724, 4726, 4728, 4732, 4738, 4740, 4756 -Minutes $Min | ForEach-Object {
        $who = if ($_.MemberName) { $_.MemberName } else { $_.TargetUserName }
        $lvl = if ($_.Id -in 4720, 4728, 4732, 4756) { 'HIGH' } else { 'MED' }
        Add-CFFinding $lvl 'Account' ("{0} {1}: {2} (group/target {3}) by {4}" -f $_.TimeCreated, $acctNames[[int]$_.Id], $who, $_.TargetUserName, $_.SubjectUserName)
    }
    # Services / tasks
    Get-CFEvents System 7045 -Minutes $Min | ForEach-Object { Add-CFFinding HIGH 'NewService' ("{0} {1} -> {2} as {3}" -f $_.TimeCreated, $_.ServiceName, $_.ImagePath, $_.AccountName) }
    Get-CFEvents Security 4697 -Minutes $Min | ForEach-Object { Add-CFFinding HIGH 'NewService' ("{0} {1} -> {2} by {3}" -f $_.TimeCreated, $_.ServiceName, $_.ServiceFileName, $_.SubjectUserName) }
    Get-CFEvents Security 4698, 4702 -Minutes $Min | ForEach-Object { Add-CFFinding HIGH 'Task' ("{0} task {1} {2} by {3}" -f $_.TimeCreated, $_.TaskName, $(if ($_.Id -eq 4698) { 'created' } else { 'updated' }), $_.SubjectUserName) }
    # Log clearing
    Get-CFEvents Security 1102 -Minutes $Min | ForEach-Object { Add-CFFinding HIGH 'LogCleared' "$($_.TimeCreated) Security log cleared ($($_.UserData))" }
    Get-CFEvents System 104 -Minutes $Min | ForEach-Object { Add-CFFinding HIGH 'LogCleared' "$($_.TimeCreated) a System-channel log was cleared" }
    # Defender
    Get-CFEvents 'Microsoft-Windows-Windows Defender/Operational' 1116, 1117, 5001, 5007, 1121 -Minutes $Min | ForEach-Object {
        $what = switch ([int]$_.Id) { 1116 { 'MALWARE DETECTED' } 1117 { 'action taken' } 5001 { 'REAL-TIME PROTECTION DISABLED' } 5007 { 'config changed' } 1121 { 'ASR block' } }
        $detail = (@($_.'Threat Name', $_.Path, $_.'New Value', $_.'Old Value') | Where-Object { $_ }) -join ' | '
        Add-CFFinding $(if ($_.Id -in 1116, 5001) { 'HIGH' } else { 'MED' }) 'Defender' "$($_.TimeCreated) $what $detail"
    }
    # PowerShell script blocks
    # Generic suspicious-PowerShell markers only. Named attack tools (credential dumpers, AMSI tampering) are left to
    # Defender itself: they show up as Defender 1116/1117 detections above, and naming them here makes AMSI block this script.
    $psBad = '(?i)(iex[\s(]|invoke-expression|downloadstring|downloadfile|frombase64string|net\.webclient|-nop\b|-w(indowstyle)?\s+hidden|add-mppreference|set-mppreference|reflection\.)'
    Get-CFEvents 'Microsoft-Windows-PowerShell/Operational' 4104 -Minutes $Min | Where-Object { $_.ScriptBlockText -match $psBad } |
        Select-Object -First 25 | ForEach-Object {
            $txt = ([string]$_.ScriptBlockText) -replace '\s+', ' '
            if ($txt.Length -gt 180) { $txt = $txt.Substring(0, 180) + '...' }
            Add-CFFinding HIGH 'PowerShell' "$($_.TimeCreated) $txt"
        }
    # DC-only: Kerberoasting and DCSync
    if ($script:IsDC) {
        Get-CFEvents Security 4769 -Minutes $Min | Where-Object { $_.TicketEncryptionType -eq '0x17' -and $_.ServiceName -notmatch '\$$' -and $_.ServiceName -ne 'krbtgt' } |
            ForEach-Object { Add-CFFinding HIGH 'Kerberoast' ("{0} RC4 ticket for {1} requested by {2} from {3}" -f $_.TimeCreated, $_.ServiceName, $_.TargetUserName, $_.IpAddress) }
        Get-CFEvents Security 4662 -Minutes $Min | Where-Object { $_.Properties -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' -and $_.SubjectUserName -notmatch '\$$' } |
            ForEach-Object { Add-CFFinding HIGH 'DCSync' ("{0} replication rights used by {1}" -f $_.TimeCreated, $_.SubjectUserName) }
    }
    # Sysmon: LSASS access
    if (Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue) {
        Get-CFEvents 'Microsoft-Windows-Sysmon/Operational' 10 -Minutes $Min |
            Where-Object { $_.TargetImage -match '(?i)lsass\.exe$' -and $_.SourceImage -notmatch '(?i)(MsMpEng|wininit|csrss|svchost|lsm|wmiprvse|MsSense|SenseIR|vmtoolsd)\.exe$' } |
            Group-Object SourceImage | ForEach-Object { Add-CFFinding HIGH 'LSASS' "$($_.Count) access(es) to lsass by $($_.Name)" }
    }

    # Live processes
    $procs = @(Get-CimInstance Win32_Process)
    $byId = @{}; foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
    $webParents = 'w3wp.exe', 'sqlservr.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe', 'java.exe', 'tomcat9.exe', 'tomcat7.exe', 'node.exe', 'hfs.exe', 'mailservice.exe', 'syncbrs.exe'
    $shells = 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'certutil.exe', 'rundll32.exe', 'mshta.exe', 'bitsadmin.exe', 'wmic.exe', 'nltest.exe', 'systeminfo.exe'
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine; $path = [string]$p.ExecutablePath
        $parent = $byId[[int]$p.ParentProcessId]
        $tag = "PID $($p.ProcessId) $($p.Name)"
        if ($parent -and ($webParents -contains $parent.Name.ToLower()) -and ($shells -contains $p.Name.ToLower())) {
            Add-CFFinding HIGH 'WebShell?' "$tag spawned by $($parent.Name): $cmd"
        }
        if ($cmd -match '(?i)\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}') { Add-CFFinding HIGH 'EncodedPS' "$tag $cmd" }
        elseif ($cmd -match '(?i)(downloadstring|downloadfile|frombase64string|iex\s*\(|invoke-webrequest|net\.webclient)') { Add-CFFinding HIGH 'Download' "$tag $cmd" }
        if ($cmd -match '(?i)(certutil.*(-urlcache|-decode)|mshta\s+(http|javascript|vbscript)|regsvr32.*/i:http|rundll32.*javascript|bitsadmin.*/transfer)') { Add-CFFinding HIGH 'LOLBin' "$tag $cmd" }
        if ($path -match '(?i)\\(temp|tmp|appdata|users\\public|perflogs|\$recycle\.bin)\\' ) { Add-CFFinding MED 'OddPath' "$tag $path" }
        if ($p.Name -match '(?i)^(svchost|lsass|csrss|services|winlogon|smss|wininit)\.exe$' -and $path -and $path -notmatch '(?i)^c:\\windows\\system32\\') {
            Add-CFFinding HIGH 'Masquerade' "$tag running from $path"
        }
    }
    # Unsigned executables currently running outside C:\Windows
    $paths = $procs | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -notmatch '(?i)^c:\\windows\\' } | Select-Object -ExpandProperty ExecutablePath -Unique
    foreach ($ep in $paths) {
        $sig = Get-AuthenticodeSignature -FilePath $ep -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne 'Valid') { Add-CFFinding MED 'Unsigned' "$ep ($($sig.Status))" }
    }
    # Connections owned by suspicious processes
    $pm = Get-CFProcMap
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
        ForEach-Object {
            $n = $pm[[int]$_.OwningProcess]
            if ($n -match '(?i)^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|notepad)$') {
                Add-CFFinding HIGH 'C2?' ("{0} (PID {1}) connected to {2}:{3}" -f $n, $_.OwningProcess, $_.RemoteAddress, $_.RemotePort)
            }
        }
    # Recently written executables / scripts
    $since = (Get-Date).AddMinutes(-[Math]::Max($Min, 360))
    $exts = '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr', '.aspx', '.ashx', '.php', '.jsp'
    foreach ($root in 'C:\Users', 'C:\ProgramData', 'C:\Windows\Temp', 'C:\PerfLogs', 'C:\inetpub') {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $exts -contains $_.Extension.ToLower() -and $_.LastWriteTime -gt $since -and $_.FullName -notmatch '(?i)\\(Microsoft\\Windows Defender|Packages|WindowsApps|Microsoft\\Edge)' } |
            Select-Object -First 40 |
            ForEach-Object { Add-CFFinding MED 'NewFile' ("{0}  {1}" -f $_.LastWriteTime, $_.FullName) }
    }

    $fpath = Join-Path $script:CFDir ("hunt_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $script:Findings | Export-Csv $fpath -NoTypeInformation -Encoding utf8
    $hi = @($script:Findings | Where-Object Level -eq 'HIGH').Count
    Write-Host ''
    Write-Host "HIGH: $hi   total: $($script:Findings.Count)   -> $fpath" -ForegroundColor $(if ($hi) { 'Red' } else { 'Green' })
    if (-not (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue)) { Write-Host 'Could not read the Security log - are you Administrator?' -ForegroundColor Yellow }
}

function Invoke-CFWatch {
    param([int]$Every = 10)
    Write-CFHeader "WATCH - every $Every s - Ctrl+C to stop - $script:CFHost"
    $wlog = Join-Path $script:CFDir 'watch.log'
    $noise = 'conhost.exe', 'WmiPrvSE.exe', 'backgroundTaskHost.exe', 'RuntimeBroker.exe', 'dllhost.exe', 'SearchProtocolHost.exe',
    'SearchFilterHost.exe', 'smartscreen.exe', 'taskhostw.exe', 'audiodg.exe', 'MpCmdRun.exe', 'sppsvc.exe', 'TiWorker.exe',
    'TrustedInstaller.exe', 'wermgr.exe', 'CompatTelRunner.exe', 'WUDFHost.exe', 'svchost.exe', 'ctfmon.exe', 'SppExtComObj.Exe', 'MoUsoCoreWorker.exe', 'NisSrv.exe'
    $say = {
        param($lvl, $msg)
        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $lvl, $msg
        $color = switch ($lvl) { 'ALERT' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
        Write-Host $line -ForegroundColor $color
        Add-Content -Path $wlog -Value $line
        if ($lvl -eq 'ALERT') { try { [console]::Beep(1000, 200) } catch { } }
    }
    $snap = {
        $pm = Get-CFProcMap
        $procTable = @{}
        foreach ($cp in Get-CimInstance Win32_Process) { $procTable[[int]$cp.ProcessId] = $cp }
        @{
            Procs     = $procTable
            Listen    = @(Get-CFListeners | ForEach-Object { "$($_.Proto) $($_.Local) $($_.Proc)" } | Sort-Object -Unique)
            Conns     = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) <- $($pm[[int]$_.OwningProcess]) (PID $($_.OwningProcess))" } | Sort-Object -Unique)
            Users     = @(Get-CFUsers | ForEach-Object { "$($_.Name) enabled=$($_.Enabled)" })
            Priv      = @(Get-CFPrivMembers)
            Services  = @(Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name) -> $($_.PathName)" })
            Tasks     = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
            Sessions  = @(quser 2>$null | Select-Object -Skip 1 | ForEach-Object { ($_ -replace '\s{2,}', ' ').Trim() } | ForEach-Object { ($_ -split ' ')[0] })
            Defender  = [string](Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
        }
    }
    $prev = & $snap
    & $say 'INFO' 'Watching. Baseline taken for this session.'
    while ($true) {
        Start-Sleep -Seconds $Every
        $now = & $snap
        foreach ($id in $now.Procs.Keys) {
            if (-not $prev.Procs.ContainsKey($id)) {
                $p = $now.Procs[$id]
                if ($noise -contains $p.Name) { continue }
                $par = $now.Procs[[int]$p.ParentProcessId]
                $parName = if ($par) { $par.Name } else { "PID $($p.ParentProcessId)" }
                $lvl = if ([string]$p.CommandLine -match $script:SusPattern) { 'ALERT' } else { 'INFO' }
                & $say $lvl ("NEW PROC  {0} (PID {1}) parent={2}  {3}" -f $p.Name, $id, $parName, $p.CommandLine)
            }
        }
        foreach ($pair in @(
                @{ K = 'Listen'; L = 'ALERT'; T = 'NEW LISTENER' },
                @{ K = 'Conns'; L = 'WARN'; T = 'NEW CONN' },
                @{ K = 'Users'; L = 'ALERT'; T = 'USER CHANGE' },
                @{ K = 'Priv'; L = 'ALERT'; T = 'PRIV GROUP' },
                @{ K = 'Services'; L = 'ALERT'; T = 'NEW SERVICE' },
                @{ K = 'Tasks'; L = 'ALERT'; T = 'NEW TASK' },
                @{ K = 'Sessions'; L = 'ALERT'; T = 'NEW SESSION' })) {
            $old = @($prev[$pair.K]); $new = @($now[$pair.K])
            foreach ($item in $new) { if ($old -notcontains $item) { & $say $pair.L "$($pair.T)  $item" } }
            if ($pair.K -in 'Users', 'Priv', 'Services', 'Tasks') {
                foreach ($item in $old) { if ($new -notcontains $item) { & $say 'WARN' "REMOVED $($pair.K)  $item" } }
            }
        }
        if ($prev.Defender -eq 'True' -and $now.Defender -ne 'True') { & $say 'ALERT' 'DEFENDER REAL-TIME PROTECTION TURNED OFF' }
        $prev = $now
    }
}

function Invoke-CFHarden {
    Write-CFHeader "HARDEN - $script:CFHost  (every change goes to $script:CFLog)"
    Write-Host '  2026 RULE CHECKS:' -ForegroundColor Yellow
    Write-Host '   - Hardenable Windows VMs: Mail/File Server (Win 2019) and Active Directory (Win 2022).' -ForegroundColor Yellow
    Write-Host '   - Do NOT harden the Assume Breach HMI (Win Server 2019). Investigate + report there.' -ForegroundColor Yellow
    Write-Host '   - Scored: LDAP 389 + SNMP 161 (AD), SMTP 25 + HFS 1080 (Mail/File). Keep them up on those ports.' -ForegroundColor Yellow
    Write-Host '   - Never modify SCORE1, SCORE2, or PATCH. No IP/hostname changes. Snapshot first (2 reverts/VM/hour).' -ForegroundColor Yellow
    if (-not (Confirm-CF '  Is this a traditional (non-Assume-Breach) box and do you have a snapshot?')) { return }
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $items = @{
        1  = @{ N = 'Defender on + remove exclusions'; R = 'Low'; S = {
                $mp = Get-MpPreference
                Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled -ErrorAction Continue
                Write-CFLog 'Defender real-time/behavior/IOAV/script scanning on, MAPS Advanced, PUA on' 'Set-MpPreference -DisableRealtimeMonitoring $true  (do not!)'
                foreach ($e in $mp.ExclusionPath) { if ($e -match '(?i)SmarterMail') { Write-Host "    Kept SmarterMail exclusion: $e" -ForegroundColor DarkGray; continue }; if ($e) { Remove-MpPreference -ExclusionPath $e; Write-CFLog "Removed Defender path exclusion $e" "Add-MpPreference -ExclusionPath '$e'" } }
                foreach ($e in $mp.ExclusionProcess) { if ($e) { Remove-MpPreference -ExclusionProcess $e; Write-CFLog "Removed Defender process exclusion $e" "Add-MpPreference -ExclusionProcess '$e'" } }
                foreach ($e in $mp.ExclusionExtension) { if ($e) { Remove-MpPreference -ExclusionExtension $e; Write-CFLog "Removed Defender extension exclusion $e" "Add-MpPreference -ExclusionExtension '$e'" } }
                foreach ($e in $mp.ExclusionIpAddress) { if ($e) { Remove-MpPreference -ExclusionIpAddress $e; Write-CFLog "Removed Defender IP exclusion $e" "Add-MpPreference -ExclusionIpAddress '$e'" } }
                try { Update-MpSignature -ErrorAction Stop } catch { Write-Host '    (signature update failed - offline?)' -ForegroundColor DarkGray }
                $st = Get-MpComputerStatus
                Write-Host "    RealTime=$($st.RealTimeProtectionEnabled) Tamper=$($st.IsTamperProtected)" -ForegroundColor Green
            }
        }
        2  = @{ N = 'Defender network protection'; R = 'Low'; S = {
                Set-MpPreference -EnableNetworkProtection Enabled
                Write-CFLog 'Defender network protection Enabled' 'Set-MpPreference -EnableNetworkProtection Disabled'
            }
        }
        3  = @{ N = 'ASR rules (asks Audit or Block)'; R = 'Medium'; S = {
                $rules = [ordered]@{
                    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
                    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
                    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block potentially obfuscated scripts'
                    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBS launching downloaded executables'
                    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
                    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps creating child processes'
                    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced ransomware protection'
                    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creation from PSExec/WMI (ALWAYS audit only here)'
                }
                $mode = Read-Host '    A = AuditMode (safe, logs 1121/1122), B = Block (Enabled)  [A/B]'
                $action = if ($mode -match '^[bB]') { 'Enabled' } else { 'AuditMode' }
                foreach ($g in $rules.Keys) {
                    $act = if ($g -eq 'd1e49aac-8f56-4280-b9ba-993a6d77406c') { 'AuditMode' } else { $action }
                    try { Add-MpPreference -AttackSurfaceReductionRules_Ids $g -AttackSurfaceReductionRules_Actions $act -ErrorAction Stop }
                    catch { Write-Host "    ASR $g failed: $($_.Exception.Message)" -ForegroundColor Yellow; continue }
                    Write-CFLog "ASR $act : $($rules[$g])" "Remove-MpPreference -AttackSurfaceReductionRules_Ids $g"
                }
            }
        }
        4  = @{ N = 'Audit policy (logons, process creation, accounts, tasks, services, Kerberos)'; R = 'None'; S = {
                $bk = Join-Path $script:CFDir ("auditpol_backup_{0}.csv" -f (Get-Date -Format 'HHmmss'))
                auditpol /backup /file:"$bk" | Out-Null
                $subs = 'Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations',
                'Computer Account Management', 'Security Group Management', 'User Account Management', 'Other Account Management Events',
                'Process Creation', 'Logon', 'Logoff', 'Special Logon', 'Account Lockout', 'Other Logon/Logoff Events',
                'Other Object Access Events', 'File Share', 'Audit Policy Change', 'Authentication Policy Change',
                'Security System Extension', 'System Integrity', 'Security State Change', 'Directory Service Changes', 'Directory Service Access'
                foreach ($s in $subs) { auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }
                # make sure advanced audit policy wins over legacy categories
                Set-CFReg $lsa 'SCENoApplyLegacyAuditPolicy' 1
                Write-CFLog "Audit policy enabled for $($subs.Count) subcategories" "auditpol /restore /file:`"$bk`""
            }
        }
        5  = @{ N = 'Command line in process-creation events (4688)'; R = 'None'; S = {
                Set-CFReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
            }
        }
        6  = @{ N = 'PowerShell logging (script block, module, transcripts)'; R = 'None'; S = {
                $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
                Set-CFReg "$base\ScriptBlockLogging" 'EnableScriptBlockLogging' 1
                Set-CFReg "$base\ModuleLogging" 'EnableModuleLogging' 1
                Set-CFReg "$base\ModuleLogging\ModuleNames" '*' '*' 'String'
                $tdir = Join-Path $OutRoot 'Transcripts'
                if (-not (Test-Path $tdir)) { New-Item -ItemType Directory -Path $tdir -Force | Out-Null }
                Set-CFReg "$base\Transcription" 'EnableTranscripting' 1
                Set-CFReg "$base\Transcription" 'EnableInvocationHeader' 1
                Set-CFReg "$base\Transcription" 'OutputDirectory' $tdir 'String'
            }
        }
        7  = @{ N = 'Bigger event logs (Security 1 GB, others 256 MB)'; R = 'None'; S = {
                $sizes = [ordered]@{ 'Security' = 1073741824; 'System' = 268435456; 'Application' = 268435456; 'Microsoft-Windows-PowerShell/Operational' = 268435456; 'Windows PowerShell' = 268435456; 'Microsoft-Windows-Sysmon/Operational' = 268435456 }
                foreach ($l in $sizes.Keys) {
                    $cfg = wevtutil gl "$l" 2>$null
                    if (-not $cfg) { continue }
                    $old = (($cfg | Select-String 'maxSize:') -replace '.*maxSize:\s*', '').Trim()
                    wevtutil sl "$l" /ms:$($sizes[$l]) | Out-Null
                    Write-CFLog "Log $l max size -> $($sizes[$l]) (was $old)" "wevtutil sl `"$l`" /ms:$old"
                }
            }
        }
        8  = @{ N = 'Disable PowerShell v2 (logging bypass)'; R = 'Low'; S = {
                if ($script:IsServer) {
                    Uninstall-WindowsFeature PowerShell-V2 -ErrorAction Continue | Out-Null
                    Write-CFLog 'Removed PowerShell-V2 feature' 'Install-WindowsFeature PowerShell-V2'
                }
                else {
                    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Continue | Out-Null
                    Write-CFLog 'Disabled PowerShell v2 optional feature' 'Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'
                }
            }
        }
        9  = @{ N = 'WDigest off (no plaintext creds in memory)'; R = 'None'; S = {
                Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
            }
        }
        10 = @{ N = 'LSA protection RunAsPPL (needs reboot)'; R = 'Low'; S = {
                Set-CFReg $lsa 'RunAsPPL' 1
                Write-Host '    Takes effect after reboot. Only reboot if the rules allow and services auto-start.' -ForegroundColor Yellow
            }
        }
        11 = @{ N = 'SMBv1 off + SMB signing required'; R = 'Low-Med'; S = {
                $c = Get-SmbServerConfiguration
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
                Write-CFLog "SMB1 off (was $($c.EnableSMB1Protocol)), signing required (was $($c.RequireSecuritySignature))" "Set-SmbServerConfiguration -EnableSMB1Protocol `$$($c.EnableSMB1Protocol) -RequireSecuritySignature `$$($c.RequireSecuritySignature) -Force"
            }
        }
        12 = @{ N = 'LLMNR + NetBIOS-over-TCP off'; R = 'Low'; S = {
                Set-CFReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
                Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | ForEach-Object {
                    $old = $_.TcpipNetbiosOptions
                    $null = Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
                    Write-CFLog "NetBIOS off on adapter index $($_.Index) ($($_.Description)), was $old" "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'Index=$($_.Index)' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]$old}"
                }
            }
        }
        13 = @{ N = 'Restrict anonymous access'; R = 'Low'; S = {
                Set-CFReg $lsa 'RestrictAnonymous' 1
                Set-CFReg $lsa 'RestrictAnonymousSAM' 1
                Set-CFReg $lsa 'EveryoneIncludesAnonymous' 0
            }
        }
        14 = @{ N = 'UAC on + block remote local-admin tokens (breaks remote admin w/ local accts)'; R = 'Medium'; S = {
                $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                Set-CFReg $sys 'EnableLUA' 1
                Set-CFReg $sys 'ConsentPromptBehaviorAdmin' 2
                Set-CFReg $sys 'LocalAccountTokenFilterPolicy' 0
                Write-Host '    LocalAccountTokenFilterPolicy=0 stops pass-the-hash with LOCAL admin accounts over the network. Domain accounts unaffected.' -ForegroundColor DarkGray
            }
        }
        15 = @{ N = 'RDP requires NLA'; R = 'Low'; S = {
                Set-CFReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1
            }
        }
        16 = @{ N = 'Guest account off'; R = 'None'; S = {
                if ($script:IsDC -and $script:HasAD) { Disable-ADAccount -Identity Guest; Write-CFLog 'Disabled domain Guest' 'Enable-ADAccount -Identity Guest' }
                else { Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue; Write-CFLog 'Disabled local Guest' 'Enable-LocalUser -Name Guest' }
            }
        }
        17 = @{ N = 'Firewall on (all profiles) + log drops'; R = 'Low'; S = {
                $before = (Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ','
                Set-NetFirewallProfile -All -Enabled True -LogBlocked True -LogMaxSizeKilobytes 16384
                Write-CFLog "Firewall enabled on all profiles, drop logging on (was $before)" 'Set-NetFirewallProfile -All -Enabled False  (do not!)'
            }
        }
        18 = @{ N = 'Default-deny inbound + PORT allow rules (no IP allow-lists - 2026 rule)'; R = 'Medium'; S = {
                Write-Host '    Currently listening TCP ports:' -ForegroundColor Cyan
                Get-CFListeners | Where-Object Proto -eq 'TCP' | Sort-Object Port -Unique | ForEach-Object { Write-Host ("      {0,-6} {1}" -f $_.Port, $_.Proc) }
                Write-Host '    2026 scored Windows services: AD (Win 2022) = LDAP 389, SNMP 161/udp; Mail/File (Win 2019) = SMTP 25, HFS 1080.' -ForegroundColor Yellow
                Write-Host '    A DC also needs 53, 88, 135, 445, 464, 636, 3268, 49152-65535 (RPC) for domain clients.' -ForegroundColor Yellow
                $tcp = Read-Host '    TCP ports to allow (comma list; ranges like 49152-65535 OK)'
                $udp = Read-Host '    UDP ports to allow (e.g. 53,88,123,161,389) or blank'
                foreach ($p in ($tcp -split '[,\s]+' | Where-Object { $_ -match '^\d+(-\d+)?$' })) {
                    New-NetFirewallRule -DisplayName "CF Allow TCP $p" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any | Out-Null
                    Write-CFLog "Allow inbound TCP $p" "Remove-NetFirewallRule -DisplayName 'CF Allow TCP $p'"
                }
                foreach ($p in ($udp -split '[,\s]+' | Where-Object { $_ -match '^\d+(-\d+)?$' })) {
                    New-NetFirewallRule -DisplayName "CF Allow UDP $p" -Direction Inbound -Protocol UDP -LocalPort $p -Action Allow -Profile Any | Out-Null
                    Write-CFLog "Allow inbound UDP $p" "Remove-NetFirewallRule -DisplayName 'CF Allow UDP $p'"
                }
                if (Confirm-CF '    Now set default inbound = Block on all profiles?') {
                    Set-NetFirewallProfile -All -DefaultInboundAction Block
                    Write-CFLog 'Default inbound action = Block (all profiles)' 'Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured'
                }
                Write-Host '    Existing enabled allow rules still apply. Review custom ones (Audit lists them) and disable any red team added:' -ForegroundColor Yellow
                Write-Host "      Disable-NetFirewallRule -DisplayName '<name>'" -ForegroundColor Yellow
            }
        }
        19 = @{ N = 'Print Spooler off'; R = 'Only if printing scored'; S = {
                $old = (Get-Service Spooler).StartType
                Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
                Write-CFLog "Spooler stopped/disabled (was $old)" "Set-Service Spooler -StartupType $old; Start-Service Spooler"
            }
        }
        20 = @{ N = 'WinRM off (not scored in 2026 - check your team does not use it)'; R = 'Medium'; S = {
                $old = (Get-Service WinRM).StartType
                Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled
                Write-CFLog "WinRM stopped/disabled (was $old)" "Set-Service WinRM -StartupType $old; Start-Service WinRM"
            }
        }
        21 = @{ N = 'Install/update Sysmon (Sysmon64.exe + sysmonconfig*.xml next to script)'; R = 'None'; S = {
                $exe = Join-Path $script:CFScriptDir 'Sysmon64.exe'
                $cfg = Get-ChildItem $script:CFScriptDir -Filter 'sysmonconfig*.xml' -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not (Test-Path $exe) -or -not $cfg) { Write-Host "    Need Sysmon64.exe and sysmonconfig*.xml in $script:CFScriptDir" -ForegroundColor Yellow; return }
                if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
                    Write-Host '    Sysmon is already installed. Current config:' -ForegroundColor Yellow
                    & $exe -c 2>$null | Select-String 'Config file|Config hash' | ForEach-Object { Write-Host "      $($_.Line.Trim())" }
                    if (-not (Confirm-CF "    REPLACE the team's current Sysmon config with $($cfg.Name)?")) { return }
                    & $exe -accepteula -c $cfg.FullName | Out-Null
                    Write-CFLog "Sysmon config updated ($($cfg.Name))" "& '$exe' -c  (re-apply previous config)"
                }
                else {
                    & $exe -accepteula -i $cfg.FullName | Out-Null
                    Write-CFLog "Sysmon installed ($($cfg.Name))" "& '$exe' -u"
                }
            }
        }
        22 = @{ N = 'Block OUTBOUND for download tools (certutil, mshta, regsvr32, bitsadmin, hh, wscript, cscript)'; R = 'Low'; S = {
                $tools = 'certutil.exe','mshta.exe','regsvr32.exe','bitsadmin.exe','hh.exe','wscript.exe','cscript.exe'
                foreach ($dir in "$env:windir\System32", "$env:windir\SysWOW64") {
                    foreach ($tool in $tools) {
                        $path = Join-Path $dir $tool
                        if (-not (Test-Path $path)) { continue }
                        $name = "CF Block Out $tool ($(Split-Path $dir -Leaf))"
                        if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { continue }
                        New-NetFirewallRule -DisplayName $name -Direction Outbound -Program $path -Action Block -Profile Any | Out-Null
                        Write-CFLog "Blocked outbound: $path" "Remove-NetFirewallRule -DisplayName '$name'"
                    }
                }
                Write-Host '    Program-based outbound blocks (not IP rules - allowed by the 2026 rules). Needs firewall ON (item 17).' -ForegroundColor Green
            }
        }
    }
    $safe = 1, 2, 4, 5, 6, 7, 8, 9, 12, 13, 15, 16, 17, 22

    while ($true) {
        Write-Host ''
        foreach ($k in ($items.Keys | Sort-Object)) { Write-Host ("  {0,2}. {1,-62} risk: {2}" -f $k, $items[$k].N, $items[$k].R) }
        Write-Host ''
        Write-Host "  safe = $($safe -join ',')   (None/Low risk, no reboot)" -ForegroundColor DarkGray
        $choice = Read-Host 'Pick numbers (e.g. 1,4,5,6), "safe", or q to quit'
        if ($choice -match '^(q|quit|exit)$') { break }
        $nums = if ($choice -eq 'safe') { $safe } else { @($choice -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }) }
        foreach ($n in $nums) {
            if (-not $items.ContainsKey($n)) { Write-Host "  No item $n" -ForegroundColor Yellow; continue }
            if (-not (Confirm-CF ("  Run {0}. {1} (risk {2})?" -f $n, $items[$n].N, $items[$n].R))) { continue }
            try { & $items[$n].S; Write-Host "  Done: $n" -ForegroundColor Green }
            catch { Write-Host "  FAILED $n : $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
    Write-Host "Changes logged in $script:CFLog" -ForegroundColor Cyan
}

function Show-CFHelp {
    Write-Host @'

CF-WinDefense.ps1 - CyberForce Windows live defense
---------------------------------------------------
  -Mode Baseline   snapshot everything + save baseline           (first 2 minutes)
  -Mode Audit      flag risky settings and suspicious persistence (right after Baseline)
  -Mode Harden     numbered menu; asks before each change; logs undo commands
  -Mode Compare    what changed since the baseline                (every 15-20 min)
  -Mode Hunt       event-log + process hunt  [-Minutes 60]        (every 30 min)
  -Mode Watch      live alerts for new procs/conns/users/services/tasks  [-Interval 10]
  . .\CF-WinDefense.ps1 -Mode Load    load response helpers into this window:
        Block-CFIP <ip>   (single IPs only; no subnets/allow-lists)
        Stop-CFProc <pid> [-Quarantine]
        Move-CFQuarantine <path>      Get-CFEvents <log> <ids> [-Minutes N]
        Remove-CFWmiPersistence -Name <name>

Output: C:\CF\<HOST>\   changes.log = every change + its undo
Scoring engine IP(s): put them in C:\CF\protected_ips.txt so Block-CFIP will refuse them.
'@ -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if ($Mode -eq 'Load') {
    Write-Host 'Loaded: Block-CFIP, Stop-CFProc, Move-CFQuarantine, Get-CFEvents, Remove-CFWmiPersistence, Invoke-CFAudit, Invoke-CFHunt, Invoke-CFCompare' -ForegroundColor Green
    return
}
if ($Mode -eq 'Help') { Show-CFHelp; return }
if (-not (Test-CFAdmin)) { Write-Host 'Run this from an ELEVATED PowerShell (Run as Administrator).' -ForegroundColor Red; return }

switch ($Mode) {
    'Baseline' { Invoke-CFBaseline }
    'Audit' { Invoke-CFAudit }
    'Compare' { Invoke-CFCompare }
    'Harden' { Invoke-CFHarden }
    'Hunt' { Invoke-CFHunt -Min $Minutes }
    'Watch' { Invoke-CFWatch -Every $Interval }
}
