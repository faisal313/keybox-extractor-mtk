# MTK Android Keybox Extraction

Toolkit for dumping and extracting **Android Attestation Keybox** data from **MediaTek (MTK) Android devices** after **bootloader unlock + root** (Magisk or equivalent).

Works with any MTK phone that stores attestation keys in standard partition layouts. The scripts auto-discover partitions on the device and pick the best dump for extraction.

---

## What you get

| Output | Description |
|--------|-------------|
| `dumps/*.bin` | Partition backups (persist, protect1/2, etc.) |
| `dumps/*_keybox_snippet.txt` | Raw bytes around keybox search hits |
| `dumps/<device>_Pvt_kb.xml` | Clean `<AndroidAttestation>` keybox (XML + PEM) |

On many MTK devices, the attestation keybox lives in **persist** as **plaintext XML with PEM keys**. Some vendors use **protect1** / **protect2** or vendor partitions instead. Runtime use still goes through TEE/TrustZone.

---

## Requirements

### Phone

| Requirement | Details |
|-------------|---------|
| SoC | MediaTek (MT67xx, MT68xx, Dimensity, etc.) |
| Bootloader | Unlocked |
| Root | Magisk (or equivalent) with **Shell/adb** granted superuser |
| USB debugging | Enabled in Developer options |
| State | Booted to Android (not recovery/download mode for ADB dump) |

Verify root before running:

```powershell
adb devices
adb shell su -c id
```

Expected: `uid=0(root) gid=0(root)`

### PC

| Requirement | Details |
|-------------|---------|
| OS | **Windows 10/11** (scripts are PowerShell; Linux/macOS can run Python scripts manually) |
| USB | Working data cable and port (prefer USB 2.0 if ADB is flaky) |
| Disk space | ~500 MB free (partition dumps vary; `persist` is often 32–64 MB) |
| Internet | Only needed to install dependencies (not required during extraction) |

### Software

| Tool | Version | Required | Install |
|------|---------|----------|---------|
| [ADB](https://developer.android.com/studio/releases/platform-tools) | Latest platform-tools | **Yes** | Extract zip, add folder to `PATH` |
| [Python](https://www.python.org/downloads/) | **3.8+** | **Yes** | Check **Add Python to PATH** during setup |
| PowerShell | 5.1+ (built into Windows) | **Yes** | Already on Windows |
| `cryptography` (pip) | Latest | Optional | `pip install cryptography` |

Quick install check:

```powershell
adb version
python --version
pip --version
```

For certificate validity / inspection:

```powershell
pip install cryptography
```

### USB drivers

Install OEM or generic USB drivers if `adb devices` shows no device or `unauthorized`:

- MediaTek preloader/VCOM drivers (for BROM/mtkclient path)
- Your phone brand’s USB driver (Oppo, Xiaomi, Realme, etc.)
- [Google USB Driver](https://developer.android.com/studio/run/win-usb) (via Android Studio SDK Manager)

### Root setup (not included here)

This repo covers **keybox extraction only**. You need root separately:

1. Unlock bootloader (mtkclient BROM, vendor fastboot, etc.)
2. Patch `boot.img` with Magisk (or flash a rooted ROM)
3. Flash patched boot
4. Confirm root: `adb shell su -c id` → `uid=0(root)`

---

## Quick start (one command)

**Start here:** phone booted to Android, **USB debugging ON**, USB cable connected, Magisk root granted to Shell/adb (see step 1 below).

```powershell
cd keybox-extraction
.\run_keybox_extraction.ps1
```

The script auto-detects device name from `ro.product.brand` + `ro.product.device` and writes:

- `dumps/<brand>_<device>_Pvt_kb.xml`

Optional custom label:

```powershell
.\run_keybox_extraction.ps1 -DeviceLabel "MyPhone"
```

Dump only specific partitions:

```powershell
.\run_keybox_extraction.ps1 -Partitions persist,protect1,protect2
```

Dump all non-system partitions (slower, thorough):

```powershell
.\run_keybox_extraction.ps1 -AllCandidates
```

---

## Step-by-step (manual)

### 1. Prepare phone (start here — ADB + root)

Required before dumping. Skip this if you already have `dumps/*.bin` (e.g. from mtkclient/BROM).

1. Boot phone to **Android** (not recovery / download mode).
2. **Settings → About phone** → tap Build number 7× → back → **Developer options**.
3. Enable **USB debugging**.
4. Connect USB cable → tap **Allow** on the phone when prompted.
5. Confirm PC sees the device and root works:

```powershell
adb devices
adb shell su -c id
```

Expected: device shows as `device` (not `unauthorized`), and `uid=0(root)`.

In Magisk: grant **Superuser** to **Shell** / **adb shell**.

### 2. Dump partitions (root + ADB)

```powershell
cd keybox-extraction\scripts
.\dump_partitions.ps1
```

Auto-discovers `/dev/block/by-name/` on the device and dumps keybox-relevant partitions via `dd` + `adb pull`.

| Partition | Typical keybox relevance |
|-----------|-------------------------|
| **persist** | **Primary** on most MTK devices |
| protect1 / protect2 | DRM / attestation on some MTK builds |
| proinfo | Device manufacturing info |
| nvram / nvdata | Modem NVRAM (rare for keybox) |
| tee1 / tee2 | TEE storage (some vendors) |
| *custom* / *oppo_custom* / *para* | Vendor-specific storage |

Manual partition list:

```powershell
.\dump_partitions.ps1 -Partitions persist,protect1,proinfo
```

### 3. Scan for markers

```powershell
python scripts\scan_keybox_markers.py
```

Writes `dumps/<partition>_keybox_snippet.txt` when patterns like `AndroidAttestation`, `Widevine`, `Keybox` are found.

### 4. Analyze format

```powershell
python scripts\analyze_keybox.py
```

Scans **all** dumps, reports PEM/XML vs encrypted blobs, and suggests the best extraction candidate.

### 5. Extract clean XML

Auto-pick best partition dump:

```powershell
python scripts\extract_keybox_xml.py -o dumps\my_keybox.xml
```

Or specify input:

```powershell
python scripts\extract_keybox_xml.py -i dumps\persist.bin -o dumps\my_keybox.xml
python scripts\extract_keybox_xml.py -i dumps\protect1.bin -o dumps\my_keybox.xml
```

### 6. Check keybox validity

```powershell
pip install cryptography
python scripts\check_keybox_validity.py
python scripts\check_keybox_validity.py -i dumps\my_keybox.xml -o dumps\my_keybox_validity.json
```

Exit codes: `0` = all certs valid, `1` = expired/invalid, `2` = error (missing file or cryptography).

### 7. Inspect certificate details (optional)

```powershell
python scripts\inspect_certs.py
python scripts\inspect_certs.py -i dumps\my_keybox.xml
```

---

## Repository layout

```
keybox-extraction/
├── README.md
├── .gitignore
├── run_keybox_extraction.ps1   # Full pipeline
├── scripts/
│   ├── dump_partitions.ps1     # Auto-discover + dump MTK partitions
│   ├── scan_keybox_markers.py
│   ├── analyze_keybox.py
│   ├── extract_keybox_xml.py
│   ├── check_keybox_validity.py
│   └── inspect_certs.py
├── dumps/                      # Generated (gitignored)
│   └── README.md
└── example/
    └── keybox_structure.example.xml
```

---

## Alternative: BROM / mtkclient (no root)

If the phone is not rooted but is in download mode with auth bypass:

```powershell
cd path\to\mtkclient
python mtk.py r persist C:\path\to\dumps\persist.bin --serialport COM3 --preloader path\to\preloader.bin
```

Repeat for `protect1`, `protect2`, etc. if needed. Then run steps 3–5 from this folder on the resulting `.bin` files (no USB debugging needed for those steps).

---

## Security warning

**Never commit to a public GitHub repo:**

- `dumps/*.bin`
- `dumps/*_Pvt_kb.xml`
- `dumps/*_keybox_snippet.txt`

These contain **device-unique private keys**. The included `.gitignore` blocks them by default.

Only publish scripts, documentation, and `example/keybox_structure.example.xml` (redacted).

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `No ADB device` | Enable USB debugging, tap Allow, try another cable/port |
| `Root not available` | Grant root to Shell/adb in Magisk |
| `No keybox markers` | Try `-AllCandidates` or dump `protect1` / `protect2` manually |
| `No AndroidAttestation block` | Keybox may be encrypted or in TEE-only storage on this vendor |
| Wrong partition | Run `analyze_keybox.py` and use `-i` with the suggested candidate |

---

## Device notes

| Vendor / class | Common keybox location | At-rest format |
|----------------|------------------------|----------------|
| Most MTK (Oppo, Realme, Vivo, etc.) | `persist` | Plaintext XML + PEM |
| Some MTK + custom TEE | `protect1` / `protect2` | Varies |
| Encrypted vendor builds | TEE only | Not extractable from partition dump |

---

## License

Scripts: use at your own risk. You are responsible for complying with device terms of service and local law. Do not distribute extracted keyboxes.
