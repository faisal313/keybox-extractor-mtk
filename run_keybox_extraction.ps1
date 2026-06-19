# Full MTK keybox extraction pipeline (root method)
param(
    [string]$OutputXml = "",
    [string]$DeviceLabel = "",
    [string[]]$Partitions = @(),
    [switch]$AllCandidates
)
$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot
$Scripts = Join-Path $Root "scripts"
$Dumps = Join-Path $Root "dumps"

if ($DeviceLabel -eq "") {
    $brand = (adb shell getprop ro.product.brand 2>&1).Trim()
    $device = (adb shell getprop ro.product.device 2>&1).Trim()
    if ($device) {
        $DeviceLabel = "${brand}_${device}" -replace '[^\w\-]', '_'
    } else {
        $DeviceLabel = "device"
    }
    Write-Host "Device label: $DeviceLabel"
}

if ($OutputXml -eq "") {
    $OutputXml = Join-Path $Dumps "${DeviceLabel}_Pvt_kb.xml"
}

Write-Host "=== MTK keybox extraction pipeline ===" -ForegroundColor Cyan
Write-Host ""

$dumpArgs = @{ OutputDir = $Dumps }
if ($Partitions.Count -gt 0) { $dumpArgs.Partitions = $Partitions }
if ($AllCandidates) { $dumpArgs.AllCandidates = $true }

& (Join-Path $Scripts "dump_partitions.ps1") @dumpArgs
if ($LASTEXITCODE -ne 0 -and -not (Get-ChildItem $Dumps -Filter "*.bin" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: No partition dumps created."
    exit 1
}

Write-Host ""
Write-Host "=== Analyze ==="
python (Join-Path $Scripts "analyze_keybox.py")

Write-Host ""
Write-Host "=== Extract XML ==="
python (Join-Path $Scripts "extract_keybox_xml.py") -o $OutputXml
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host ""
Write-Host "=== Check keybox validity ==="
$ValidityJson = Join-Path $Dumps "${DeviceLabel}_validity.json"
python (Join-Path $Scripts "check_keybox_validity.py") -i $OutputXml -o $ValidityJson
$validExit = $LASTEXITCODE

Write-Host ""
Write-Host "Done."
Write-Host "  Snippets: $Dumps\*_keybox_snippet.txt"
Write-Host "  Keybox:   $OutputXml"
Write-Host "  Validity: $ValidityJson"
if ($validExit -eq 0) {
    Write-Host "  Status:   VALID (all certificates in date)" -ForegroundColor Green
} elseif ($validExit -eq 1) {
    Write-Host "  Status:   INVALID or expired certificate(s)" -ForegroundColor Yellow
} else {
    Write-Host "  Status:   Could not verify (install: pip install cryptography)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "WARNING: Do not commit dumps/ or *_Pvt_kb.xml to a public repo."
