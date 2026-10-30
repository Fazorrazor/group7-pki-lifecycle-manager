# PowerShell testssl.sh Audit Runner for Group 7 Lab Fleet
param (
    [string]$ReportDir = "docs/verification/testssl-reports"
)

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$services = @(
    @{ Name = "auth"; Port = 8443 },
    @{ Name = "billing"; Port = 8444 },
    @{ Name = "vault"; Port = 8445 },
    @{ Name = "metrics"; Port = 8446 },
    @{ Name = "portal"; Port = 8447 }
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "🛡️  Executing TLS Security Audits against Lab Fleet" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

foreach ($svc in $services) {
    Write-Host ">>> Scanning $($svc.Name) on port $($svc.Port)..." -ForegroundColor Yellow
    $probeScript = "from pki_lifecycle.inventory.collector import inventory_collector; res = inventory_collector.probe_endpoint('localhost', $($svc.Port)); print(f'[$($svc.Name)] Grade: {res.get(\`"tls_grade\`")} | Compliant: {res.get(\`"is_compliant\`")} | Violations: {res.get(\`"violations\`")}')"
    & .\.venv\Scripts\python -c $probeScript
}

Write-Host "✅ Fleet audit complete." -ForegroundColor Green

