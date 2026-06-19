# Output directory

Partition dumps and extracted keybox XML are written here when you run the scripts.

**Do not commit files from this folder to a public Git repository.** They contain device-unique private keys.

Expected outputs after a successful run:

| File | Description |
|------|-------------|
| `persist.bin` | Full persist partition (keybox on most MTK devices) |
| `protect1.bin`, `protect2.bin`, ... | Other MTK partitions scanned for keybox data |
| `*_keybox_snippet.txt` | Raw regions around keybox markers |
| `<device>_Pvt_kb.xml` | Clean Android Attestation keybox export |
