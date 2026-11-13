# yara-scan.ps1 - scans the folders attackers usually drop files in, logs one line per hit.
# Scheduled task "CF YARA Scan" runs it every 10 min as SYSTEM.
# HMI uses -p 1 (one CPU thread) instead of -p 2 to stay light on the Assume Breach box.
$yara  = 'C:\Tools\yara\yara64.exe'
$rules = 'C:\Tools\yara\core.yarc'
$log   = 'C:\CF\yara\hits.log'

# Where attackers usually drop things
$dirs = @('C:\Windows\Temp','C:\Users\Public','C:\Scripts','C:\inetpub','C:\Shares',
          'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')
foreach ($u in Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue) {
    foreach ($s in 'Desktop','Downloads','Documents','AppData\Local\Temp',
                   'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') {
        $dirs += Join-Path $u.FullName $s
    }
}

New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null
foreach ($d in $dirs) {
    if (Test-Path $d) {
        # -C = precompiled rules, -z = skip files over 20 MB
        & $yara -C -r -f -w -p 2 -z 20000000 $rules $d 2>$null | ForEach-Object {
            $t = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            "$t UTC | $env:COMPUTERNAME | $_" | Out-File $log -Append -Encoding utf8
        }
    }
}
