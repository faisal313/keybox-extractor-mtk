# Dump MTK keybox-related partitions via root (ADB + Magisk)
param(
    [string]$OutputDir = "",
    [string[]]$Partitions = @(),
    [switch]$AllCandidates,
    [switch]$SkipScan
)
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
if ($OutputDir -eq "") { $OutputDir = Join-Path $Root "dumps" }
$Scripts = Join-Path $Root "scripts"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Common MTK partitions where attestation / DRM keyboxes may live
$DefaultCandidates = @(
    "persist", "protect1", "protect2", "proinfo", "nvram", "nvdata",
    "frp", "metadata", "md5", "seccfg", "sec1", "tee1", "tee2",
    "oppo_custom", "custom", "para", "misc"
)

$SkipPartitions = @(
    "boot", "boot_a", "boot_b", "recovery", "recovery_a", "recovery_b",
    "system", "system_a", "system_b", "vendor", "vendor_a", "vendor_b",
    "userdata", "cache", "super", "vbmeta", "vbmeta_a", "vbmeta_b",
    "dtbo", "logo", "lk", "lk_a", "lk_b", "scp", "scp_a", "scp_b",
    "spmfw", "sspm", "mcupm", "gz", "gz_a", "gz_b", "preloader",
    "preloader_a", "preloader_b", "odm", "odm_a", "odm_b", "product"
)

function Get-DevicePartitions {
    $paths = @(
        "/dev/block/by-name",
        "/dev/block/platform/bootdevice/by-name"
    )
    foreach ($base in $paths) {
        $listing = adb shell "su -c 'ls $base 2>/dev/null'" 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $listing.Trim()) {
            return @{
                Base = $base
                Names = ($listing -split "\s+" | Where-Object { $_ -and $_ -notmatch "^\s*$" } | Sort-Object -Unique)
            }
        }
    }
    return $null
}

function Resolve-PartitionBlock {
    param([string]$Name, [string]$Base)
    return "$Base/$Name"
}

Write-Host "=== MTK keybox partition dump (root / ADB) ===" -ForegroundColor Cyan
Write-Host "Output: $OutputDir"
Write-Host "Requirements: USB debugging, Magisk root, grant su to shell/adb"
Write-Host ""

$adb = adb devices 2>&1 | Out-String
if ($adb -notmatch "`tdevice") {
    Write-Host "ERROR: No ADB device."
    exit 1
}

$model = (adb shell getprop ro.product.model 2>&1).Trim()
$device = (adb shell getprop ro.product.device 2>&1).Trim()
$chipset = (adb shell getprop ro.board.platform 2>&1).Trim()
Write-Host "Device: $model ($device)  platform=$chipset"

$rootCheck = adb shell "su -c id" 2>&1 | Out-String
if ($rootCheck -notmatch "uid=0") {
    Write-Host "ERROR: Root not available (Magisk must grant shell/adb)."
    exit 1
}
Write-Host "Root OK"
Write-Host ""

$discovered = Get-DevicePartitions
if (-not $discovered) {
    Write-Host "WARN: Could not list by-name partitions; using default candidate list."
    $discovered = @{ Base = "/dev/block/by-name"; Names = $DefaultCandidates }
}

$available = @($discovered.Names)
Write-Host "Found $($available.Count) partition(s) on device."

if ($Partitions.Count -gt 0) {
    $toDump = @($Partitions)
} elseif ($AllCandidates) {
    $toDump = @($available | Where-Object { $_ -notin $SkipPartitions })
} else {
    $toDump = @($DefaultCandidates | Where-Object { $_ -in $available })
    $extra = @($available | Where-Object {
        $_ -notin $SkipPartitions -and
        $_ -notin $toDump -and
        $_ -match '(?i)(custom|key|drm|widevine|attest|tee|sec|protect|persist|proinfo|nvram|nvdata|frp|metadata|para|misc)'
    })
    $toDump = @($toDump + $extra | Select-Object -Unique)
}

if ($toDump.Count -eq 0) {
    if ($available -contains "persist") {
        $toDump = @("persist")
    } else {
        Write-Host "ERROR: No keybox candidate partitions found on device."
        exit 1
    }
}

Write-Host "Dumping: $($toDump -join ', ')"
Write-Host ""

foreach ($name in $toDump) {
    $block = Resolve-PartitionBlock -Name $name -Base $discovered.Base
    $remote = "/sdcard/_kb_dump_$name.bin"
    $local = Join-Path $OutputDir "$name.bin"
    Write-Host "Dumping $name.bin ..."
    adb shell "su -c 'dd if=$block of=$remote bs=4096'" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        adb shell "su -c 'dd if=/dev/block/platform/bootdevice/by-name/$name of=$remote bs=4096'" 2>&1 | Out-Null
    }
    if ($LASTEXITCODE -ne 0) {
        adb shell "su -c 'dd if=/dev/block/by-name/$name of=$remote bs=4096'" 2>&1 | Out-Null
    }
    adb pull $remote $local 2>&1 | Out-Null
    adb shell "rm -f $remote" 2>&1 | Out-Null
    if (Test-Path $local) {
        Write-Host ("  OK: {0} ({1} bytes)" -f $local, (Get-Item $local).Length)
    } else {
        Write-Host "  SKIP: $name (not present or dump failed)"
    }
}

if (-not $SkipScan) {
    Write-Host ""
    Write-Host "=== Scanning for keybox markers ==="
    python (Join-Path $Scripts "scan_keybox_markers.py")
}

Write-Host ""
Write-Host "Next: extract clean XML with extract_keybox_xml.py (auto-picks best partition dump)"
