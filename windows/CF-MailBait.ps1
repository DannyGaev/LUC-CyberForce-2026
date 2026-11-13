<#
  CF-MailBait.ps1  -  turn the Mail canary into a bait-password trap (Mail box ONLY, not AD)

  What it does:
    1. Gives the local canary account svc_backup_old a "bait" password.
    2. Denies that account EVERY kind of logon (console, RDP, network/SMB, batch, service).
    3. Writes the bait password into C:\Shares\IT_passwords_old.txt (the file HFS serves).
  Result: anyone who reads the file and tries the password gets "logon type not granted"
  (status 0xC000015B) - no access at all - and CF-WinRelay posts a LOOK NOW alert.

  Run in an admin PowerShell on Mail:   .\CF-MailBait.ps1 -BaitPass '<bait password from the Credentials sheet>'
  (the bait password is NOT stored in this repo - if red team can read the repo, the trap would be useless)
  Test afterwards:  runas /user:$env:COMPUTERNAME\svc_backup_old cmd   (type the bait password)
                    -> expect error 1385 "the user has not been granted the requested logon type"
#>
param([Parameter(Mandatory = $true)][string]$BaitPass)   # used NOWHERE else - this account can never log in
$Account  = 'svc_backup_old'
$BaitFile = 'C:\Shares\IT_passwords_old.txt'
$Rights   = @('SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyNetworkLogonRight',
              'SeDenyBatchLogonRight','SeDenyServiceLogonRight')

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this in an ADMIN PowerShell.' -ForegroundColor Red; return
}
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    Write-Host 'This is a domain controller. Do NOT run this on AD - the AD canary keeps its random password.' -ForegroundColor Red; return
}
$user = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
if (-not $user) { Write-Host "Local account $Account not found. Create the canary first." -ForegroundColor Red; return }
$sid = $user.SID.Value

# 1. deny every logon type (local security policy)
$tmp = Join-Path $env:TEMP 'cfbait'
New-Item -ItemType Directory -Force $tmp | Out-Null
$inf = Join-Path $tmp 'rights.inf'; $db = Join-Path $tmp 'rights.sdb'
& secedit.exe /export /cfg $inf /areas USER_RIGHTS | Out-Null
$lines = [System.Collections.Generic.List[string]](Get-Content $inf)
foreach ($r in $Rights) {
    $i = -1
    for ($n = 0; $n -lt $lines.Count; $n++) { if ($lines[$n] -match "^$r\s*=") { $i = $n; break } }
    if ($i -ge 0) {
        if ($lines[$i] -notmatch [regex]::Escape("*$sid")) { $lines[$i] = $lines[$i].TrimEnd() + ",*$sid" }
    } else {
        $p = $lines.IndexOf('[Privilege Rights]')
        $lines.Insert($p + 1, "$r = *$sid")
    }
}
Set-Content -Path $inf -Value $lines -Encoding Unicode
& secedit.exe /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
& gpupdate.exe /target:computer /force | Out-Null
Remove-Item $tmp -Recurse -Force

# 2. set the bait password (only after the deny rights are in place)
Set-LocalUser -Name $Account -Password (ConvertTo-SecureString $BaitPass -AsPlainText -Force)

# 3. put the bait in the file (keeps the file's read-auditing)
$content = @(
    'IT - legacy service accounts (migrate to vault before Q4)',
    '',
    'backup01 nightly job    svc_backup_old / ' + $BaitPass,
    'old print server        moved to vault',
    'scanner smtp relay      moved to vault'
)
Set-Content -Path $BaitFile -Value $content

# show the result
& secedit.exe /export /cfg (Join-Path $env:TEMP 'cfcheck.inf') /areas USER_RIGHTS | Out-Null
$check = Get-Content (Join-Path $env:TEMP 'cfcheck.inf') | Where-Object { $_ -match '^SeDeny' }
Remove-Item (Join-Path $env:TEMP 'cfcheck.inf') -Force
Write-Host "Deny rights now include $Account ($sid):" -ForegroundColor Green
$check | ForEach-Object { Write-Host "  $_" }
Write-Host "Bait file updated: $BaitFile" -ForegroundColor Green
Write-Host "Test: runas /user:$env:COMPUTERNAME\$Account cmd   then type the bait password  -> expect error 1385" -ForegroundColor Cyan
