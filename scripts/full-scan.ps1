# Ares Tool Security — Full Scan Script (PowerShell)
# Runs all 4 modules in sequence against a single target.
# Generates 4 separate .md reports in reports/
#
# Usage: .\scripts\full-scan.ps1 https://example.com

param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║    Ares Tool Security — Full Scan       ║" -ForegroundColor Cyan
Write-Host "  ║    Target: $Target" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$modules = @("web-audit", "brute-force", "ddos-audit", "vuln-scan")
$root = Split-Path -Parent $PSScriptRoot

foreach ($module in $modules) {
    $modulePath = Join-Path $root "modules" "$module.py"
    if (Test-Path $modulePath) {
        Write-Host ""
        Write-Host "  ── Running: $module ──" -ForegroundColor Yellow
        python3 $modulePath $Target 2>&1
        Write-Host ""
        Write-Host "  ── Done: $module ──" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "  ⚠️  Module not found: $module.py — skipping" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║    Full scan complete                    ║" -ForegroundColor Cyan
$reportsDir = Join-Path $root "reports"
Write-Host "  ║    Reports in: $reportsDir" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
