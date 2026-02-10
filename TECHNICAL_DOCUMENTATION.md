# TECHNICAL DOCUMENTATION
## Forensic Timeline Extraction & Analysis System v2.0

---

## 📑 Document Overview

This document provides complete technical specifications for the three-component forensic timeline analysis system.

**Components:**
- **Extractor.py** - Timeline extraction from disk images
- **Analyser.py** - Detection and reporting with user-selectable views
- **Main.py** - Workflow orchestration

**Target Audience:** Forensic analysts, developers, security researchers

---

## 🏗️ SYSTEM ARCHITECTURE

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER ENTRY POINT                            │
│                        (Main.py)                                 │
│                                                                  │
│  Orchestrates: Extractor → Analyser → HTML Output               │
└────────────────────────┬────────────────────────────────────────┘
                         │
         ┌───────────────┴────────────────┐
         ↓                                ↓
┌─────────────────────┐         ┌─────────────────────┐
│   EXTRACTOR         │         │    ANALYSER         │
│   (Extractor.py)    │→ CSV →  │   (Analyser.py)     │
│                     │         │                     │
│  • Open image       │         │  • Load CSV         │
│  • Walk filesystem  │         │  • Collapse events  │
│  • Extract metadata │         │  • Detect anomalies │
│  • Generate CSV     │         │  • Generate HTML    │
└─────────────────────┘         └─────────────────────┘
         ↓                                ↓
   timeline.csv                  forensic_report.html
```

### Data Flow Pipeline

```
DISK IMAGE (.dd, .E01, .raw)
        ↓
    Extractor.py
        ↓ (pytsk3 filesystem traversal)
    Extract 4 timestamp types per file
        ↓ (CRTIME, MTIME, ATIME, CTIME)
    Create event records
        ↓ (one event per timestamp)
    Sort chronologically
        ↓
    timeline.csv
        ↓
    Analyser.py
        ↓ (group by file path)
    Collapse event-based → file-based
        ↓ (pivot timestamps to columns)
    File table with all timestamps
        ↓ (apply detection rules)
    Flag suspicious patterns
        ↓ (user selects view: 1, 2, or 3)
    Generate HTML report
        ↓
    forensic_report.html
```

---

## 📦 COMPONENT 1: Extractor.py

### Purpose
Extracts filesystem metadata and timestamps from disk images using The Sleuth Kit (pytsk3).

### Dependencies
```python
import pytsk3        # The Sleuth Kit Python bindings
import csv           # CSV file writing
from datetime import datetime, timezone  # Timestamp conversion
```

### Configuration Constants

```python
SCAN_LIMIT = 10000      # Maximum files to scan
OUTPUT_CSV = "timeline.csv"  # Output filename
```

**SCAN_LIMIT Rationale:**
- Prevents memory exhaustion on large images
- Default 10,000 balances performance vs completeness
- Adjustable based on system resources

**Memory Usage Estimates:**
```
SCAN_LIMIT    RAM Used    Approx Time
─────────────────────────────────────
1,000         ~50 MB      30 sec
10,000        ~500 MB     2 min
50,000        ~2.5 GB     10 min
100,000       ~5 GB       20 min
```

### Function Reference

#### `to_utc(ts: int) -> str | None`

**Purpose:** Convert Unix timestamp to ISO 8601 UTC string

**Parameters:**
- `ts` (int): Unix timestamp (seconds since epoch)

**Returns:**
- `str`: ISO 8601 formatted UTC timestamp
- `None`: If timestamp is null, zero, or invalid

**Implementation:**
```python
def to_utc(ts):
    try:
        if ts is None or ts == 0:
            return None
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None
```

**Error Handling:**
- Null/zero timestamps → `None`
- Conversion errors → `None`
- Ensures UTC timezone

**Example:**
```python
to_utc(1705756800) → "2024-01-20T10:00:00+00:00"
to_utc(0)          → None
to_utc(None)       → None
```

---

#### `open_image(image_path: str) -> tuple[FS_Info, str]`

**Purpose:** Open disk image and locate filesystem

**Parameters:**
- `image_path` (str): Path to disk image file

**Returns:**
- Tuple: `(filesystem_object, partition_description)`

**Algorithm:**
```
1. Create Img_Info object from image path
2. Create Volume_Info to enumerate partitions
3. For each partition:
   a. Check if length > 0 (not empty)
   b. Check if not "Unallocated" space
   c. Try to open FS_Info at partition offset
   d. If successful, return (fs, description)
4. If no valid partition found:
   a. Attempt direct FS_Info (unpartitioned image)
   b. Return (fs, "No Partition")
```

**Offset Calculation:**
```python
offset = part.start * 512
# part.start = partition start sector
# 512 = bytes per sector (standard)
```

**Supported Image Formats:**
- Raw: .dd, .raw, .img
- Expert Witness: .E01, .Ex01
- Advanced Forensic: .aff, .afd
- Virtual disk: .vmdk, .vdi (raw mode)

**Example:**
```python
fs, desc = open_image("evidence.dd")
# fs = <pytsk3.FS_Info object>
# desc = "NTFS (0x07)" or "No Partition"
```

---

#### `walk_directory(directory, parent_path="/", counter=[0]) -> Generator`

**Purpose:** Recursively traverse filesystem directory tree

**Parameters:**
- `directory`: pytsk3 directory object
- `parent_path` (str): Current path (default "/")
- `counter` (list): Mutable counter for scan limit

**Yields:**
- Tuples: `(entry, full_path)`

**Generator Pattern:**
```python
for entry, path in walk_directory(root):
    # Process one file at a time
    # Memory efficient - doesn't load all files
```

**Recursion Logic:**
```
/
├── dir1/
│   ├── file1.txt      ← Yield (entry, "/dir1/file1.txt")
│   └── subdir/        ← Recurse into
│       └── file2.txt  ← Yield (entry, "/dir1/subdir/file2.txt")
└── dir2/
    └── file3.txt      ← Yield (entry, "/dir2/file3.txt")
```

**Scan Limit Enforcement:**
```python
if counter[0] >= SCAN_LIMIT:
    return  # Stop recursion
```

**Why List for Counter?**
- Lists are mutable in Python
- Changes persist across recursion
- Simple global state management

**Skipped Entries:**
- `.` (current directory)
- `..` (parent directory)
- Entries without metadata
- Corrupted/unreadable entries

---

#### `extract_timeline(fs, partition_desc: str) -> list[dict]`

**Purpose:** Extract all timestamp events from filesystem

**Parameters:**
- `fs`: pytsk3 filesystem object
- `partition_desc` (str): Partition description

**Returns:**
- List of event dictionaries

**Event Structure:**
```python
{
    "time": "2024-01-20T10:00:00+00:00",  # ISO 8601 UTC
    "type": "CRTIME",                      # Timestamp type
    "path": "/home/user/file.txt",         # Full path
    "partition": "NTFS (0x07)",            # Partition
    "inode": 12345,                        # Inode number
    "size": 4096,                          # File size (bytes)
    "deleted": False                       # Deletion status
}
```

**Timestamp Types:**
```python
timestamps = {
    "ATIME": meta.atime,   # Access time
    "MTIME": meta.mtime,   # Modification time
    "CTIME": meta.ctime,   # Change time (metadata)
    "CRTIME": meta.crtime  # Creation time (birth)
}
```

**Deleted File Detection:**
```python
deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
```
- Bitwise AND checks unalloc flag
- Works for recently deleted files
- Doesn't detect secure deletion

**Processing Steps:**
```
1. Open root directory
2. Walk all entries via walk_directory()
3. For each file:
   a. Extract metadata (inode, size, flags)
   b. Get all 4 timestamps
   c. Convert each to UTC
   d. Create event record for each valid timestamp
4. Sort events chronologically
5. Return event list
```

---

#### `write_csv(timeline: list[dict]) -> None`

**Purpose:** Write timeline events to CSV file

**Parameters:**
- `timeline`: List of event dictionaries

**CSV Structure:**
```csv
time,type,path,partition,inode,size,deleted
2024-01-20T10:00:00+00:00,CRTIME,/file.txt,NTFS,123,1024,False
2024-01-20T11:00:00+00:00,MTIME,/file.txt,NTFS,123,1024,False
```

**Field Descriptions:**
- `time`: ISO 8601 UTC timestamp
- `type`: CRTIME/MTIME/ATIME/CTIME
- `path`: Full file path
- `partition`: Partition description
- `inode`: File inode number
- `size`: File size in bytes
- `deleted`: Boolean (True/False)

---

### Main Execution Flow

```python
def main():
    # 1. Get image path from user
    image_path = input("Enter disk image path: ").strip().strip('"')
    
    # 2. Open image and get filesystem
    fs, part_desc = open_image(image_path)
    
    # 3. Extract timeline events
    timeline = extract_timeline(fs, part_desc)
    
    # 4. Write to CSV
    write_csv(timeline)
    
    # 5. Report statistics
    print(f"[+] Extracted {len(timeline)} events")
    print(f"[+] Scan limit used: {SCAN_LIMIT}")
    print(f"[+] CSV saved as: {OUTPUT_CSV}")
```

---

## 📦 COMPONENT 2: Analyser.py

### Purpose
Analyzes timeline CSV, detects suspicious patterns, and generates HTML reports with three viewing options.

### Dependencies
```python
import pandas as pd         # Data analysis
from datetime import timedelta  # Time calculations
import os                   # File operations
import sys                  # System exit
```

### Configuration Constants

```python
CSV_FILE = "timeline.csv"           # Input from Extractor
OUTPUT_HTML = "forensic_report.html"  # Output filename
```

### Function Reference

#### `load_csv() -> DataFrame`

**Purpose:** Load and validate timeline CSV

**Returns:**
- pandas DataFrame with parsed data

**Validation Steps:**
```
1. Check file existence
2. Validate required columns
3. Parse timestamps to datetime
4. Convert deleted to boolean
5. Sort chronologically
```

**Required Columns:**
```python
required = ["time", "type", "path", "partition", "inode", "size", "deleted"]
```

**Data Transformations:**
```python
# Timestamp parsing
df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")

# Boolean conversion
df["deleted"] = df["deleted"].astype(str).str.lower().isin(["true","1","yes"])

# Chronological sort
df = df.sort_values("time")
```

**Error Handling:**
- File not found → Exit with error
- Missing columns → Exit with error
- Invalid timestamps → Convert to NaT
- Invalid boolean → Convert to False

---

#### `build_file_table(df: DataFrame) -> DataFrame`

**Purpose:** Transform event-based timeline to file-based view

**Input:** Event-based DataFrame (multiple rows per file)
**Output:** File-based DataFrame (one row per file)

**Transformation Logic:**
```python
# Group all events by file path
grouped = df.groupby("path", dropna=False)

# For each file
for path, group in grouped:
    # Take first occurrence for static fields
    record = {
        "path": path,
        "partition": group["partition"].iloc[0],
        "inode": group["inode"].iloc[0],
        "size": group["size"].iloc[0],
        "deleted": group["deleted"].iloc[0]
    }
    
    # Pivot timestamp types into columns
    for _, row in group.iterrows():
        ttype = row["type"].upper()  # CRTIME, MTIME, etc.
        if pd.notna(row["time"]):
            record[ttype] = row["time"]
```

**Transformation Example:**

**Before (Event-based):**
```
time                 | type   | path
─────────────────────┼────────┼──────────
2024-01-20 10:00:00 | CRTIME | /file.txt
2024-01-20 11:00:00 | MTIME  | /file.txt
2024-01-20 12:00:00 | ATIME  | /file.txt
```

**After (File-based):**
```
path      | CRTIME           | MTIME            | ATIME
──────────┼──────────────────┼──────────────────┼──────────────────
/file.txt | 2024-01-20 10:00 | 2024-01-20 11:00 | 2024-01-20 12:00
```

---

#### `detect(df: DataFrame) -> DataFrame`

**Purpose:** Apply detection rules and flag suspicious patterns

**Input:** File-based DataFrame
**Output:** DataFrame with `flags` and `suspicious` columns

**Detection Rules:**

##### Rule 1: Access Before Creation

```python
if pd.notna(c) and pd.notna(a) and a < c:
    flags.append("Access before creation")
```

**Logic:**
- ATIME < CRTIME is physically impossible
- File must exist before it can be accessed
- Indicates timestamp stomping

**Example:**
```
CRTIME: 2024-01-20 15:00:00
ATIME:  2024-01-20 14:00:00  ← 1 hour earlier!
Flag: "Access before creation"
```

##### Rule 2: Modified Before Creation

```python
if pd.notna(c) and pd.notna(m) and m < c:
    flags.append("Modified before creation")
```

**Logic:**
- MTIME < CRTIME is impossible
- File must exist before it can be modified
- Another timestamp stomping indicator

##### Rule 3: Rapid Timestamp Activity

```python
times = [x for x in [c,a,m,t] if pd.notna(x)]
if len(times) >= 3:
    if max(times) - min(times) < timedelta(seconds=2):
        flags.append("Rapid timestamp activity (<2s)")
```

**Logic:**
- Collects all valid timestamps
- Calculates time span: max - min
- Flags if span < 2 seconds
- Indicates automated/scripted activity

**Mathematical Example:**
```
CRTIME: 10:00:00.000
MTIME:  10:00:00.500
ATIME:  10:00:01.000
CTIME:  10:00:01.200

max() = 10:00:01.200
min() = 10:00:00.000
span = 1.2 seconds < 2 seconds → FLAGGED
```

**Why 2 Seconds?**
- Human operations: typically 5+ seconds
- Automated scripts: typically <1 second
- 2 seconds balances false positives vs detection

##### Rule 4: Deleted File Accessed

```python
if r.get("deleted") and pd.notna(a):
    flags.append("Deleted file accessed")
```

**Logic:**
- Deleted files shouldn't have recent access
- Combination is suspicious
- Possible data exfiltration before deletion

**Flag Storage:**
```python
df["flags"] = flags_all  # List of flag lists
df["suspicious"] = df["flags"].apply(lambda x: len(x) > 0)
```

---

#### `generate_html(choice: int, df_events: DataFrame, df_files: DataFrame) -> None`

**Purpose:** Generate HTML report based on user's view selection

**Parameters:**
- `choice` (int): View option (1, 2, or 3)
- `df_events`: Event-based DataFrame
- `df_files`: File-based DataFrame with detections

**View Options:**

##### Option 1: Suspicious Files Only

**Shows:**
- Only files flagged by detection rules
- Path and flags

**Use Case:**
- Initial triage
- Quick assessment
- Finding obvious anomalies

**HTML Structure:**
```html
<h1>Suspicious Files</h1>
<table>
  <tr><th>Path</th><th>Flags</th></tr>
  <tr>
    <td>/malware.exe</td>
    <td class="bad">Access before creation, Rapid activity</td>
  </tr>
</table>
```

##### Option 2: Full File Timeline

**Shows:**
- All files on disk
- All four timestamp types
- Deletion status
- Flags (if any)

**Use Case:**
- Comprehensive analysis
- Timeline reconstruction
- Context for suspicious files

**HTML Structure:**
```html
<h1>Full File Timeline</h1>
<table>
  <tr>
    <th>Path</th>
    <th>CRTIME</th>
    <th>MTIME</th>
    <th>ATIME</th>
    <th>CTIME</th>
    <th>Deleted</th>
    <th>Flags</th>
  </tr>
  <!-- One row per file -->
</table>
```

##### Option 3: Raw Timeline Events

**Shows:**
- Individual timestamp events
- Chronological order
- Event type
- Deletion status

**Use Case:**
- Detailed forensic examination
- Correlation with other logs
- Exact sequence of events

**HTML Structure:**
```html
<h1>Raw Timeline Events</h1>
<table>
  <tr>
    <th>Time</th>
    <th>Type</th>
    <th>Path</th>
    <th>Partition</th>
    <th>Deleted</th>
  </tr>
  <!-- One row per event -->
</table>
```

**CSS Styling:**
```css
body {
  font-family: Arial;
  background: #f5f6f7;
  padding: 30px;
}

.section {
  background: white;
  padding: 20px;
  margin-bottom: 25px;
  border-radius: 8px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

th {
  background: #111;  /* Black header */
  color: white;
  padding: 8px;
}

td {
  padding: 6px;
  border-bottom: 1px solid #ddd;
}

.bad {
  color: red;
  font-weight: bold;
}
```

---

### Main Execution Flow

```python
def main():
    # 1. Display menu
    print("1 → Suspicious Files")
    print("2 → Full File Timeline")
    print("3 → Raw Timeline Events")
    
    # 2. Get user choice
    choice = int(input("Select option: "))
    
    # 3. Validate choice
    if choice not in [1, 2, 3]:
        print("Invalid choice")
        return
    
    # 4. Load timeline CSV
    df_events = load_csv()
    
    # 5. Transform to file view
    df_files = build_file_table(df_events)
    
    # 6. Apply detection rules
    df_files = detect(df_files)
    
    # 7. Generate HTML based on choice
    generate_html(choice, df_events, df_files)
```

---

## 📦 COMPONENT 3: Main.py

### Purpose
Orchestrate complete workflow from extraction to analysis

### Implementation

```python
import Extractor
import Analyser

def main():
    # Step 1: Extract timeline from disk image
    print("[1] Extracting timeline...")
    Extractor.main()
    
    # Step 2: Analyze timeline and generate report
    print("[2] Generating HTML report...")
    Analyser.main()
    
    # Step 3: Complete
    print("[✓] Done")

if __name__ == "__main__":
    main()
```

**Execution Flow:**
```
User runs: python Main.py
    ↓
Main.py calls Extractor.main()
    ↓
User enters disk image path
    ↓
Extractor creates timeline.csv
    ↓
Main.py calls Analyser.main()
    ↓
User selects view option (1, 2, or 3)
    ↓
Analyser creates forensic_report.html
    ↓
Done!
```

**Error Propagation:**
- If Extractor fails → Main.py stops
- If Analyser fails → Main.py stops
- Errors are printed to console

---

## 🔍 DETECTION ALGORITHM ANALYSIS

### False Positive Scenarios

#### Legitimate Rapid Activity

**Scenario:** Software installer
```
CRTIME: 10:00:00
MTIME:  10:00:00
ATIME:  10:00:01
CTIME:  10:00:01
```

**Why Flagged:** All within 1 second
**Is It Malicious?** No - normal installer behavior

**Mitigation:**
- Review file path (is it in Program Files?)
- Check file signature
- Correlate with installation logs

#### Time Zone Confusion

**Scenario:** File copied across time zones
```
CRTIME: 2024-01-20 10:00:00 PST
ATIME:  2024-01-20 09:00:00 PST (copied from EST)
```

**Why Flagged:** Access before creation
**Is It Malicious?** No - timezone artifact

**Mitigation:**
- All timestamps converted to UTC
- Reduces but doesn't eliminate this issue
- Manual review required

### False Negative Scenarios

#### Sophisticated Timestamp Stomping

**Scenario:** Attacker sets all timestamps consistently
```
CRTIME: 2023-01-01 10:00:00
MTIME:  2023-01-01 10:30:00
ATIME:  2023-01-01 11:00:00
CTIME:  2023-01-01 11:30:00
```

**Why Not Flagged:** All timestamps consistent
**Is It Malicious?** Possibly - but undetectable by temporal logic

**Mitigation:**
- Hash file against known malware
- Check file location (suspicious directories?)
- Correlate with other artifacts

#### Delayed Malware Execution

**Scenario:** Dropper with delayed payload
```
CRTIME: 2024-01-20 10:00:00
ATIME:  2024-01-20 16:00:00  ← 6 hours later
```

**Why Not Flagged:** Timespan > 2 seconds
**Is It Malicious?** Possibly - evades rapid activity detection

**Mitigation:**
- Look for patterns across multiple files
- Check network logs for C2 communication
- Analyze file content

---

## ⚙️ PERFORMANCE OPTIMIZATION

### Memory Management

**Current Approach:** Generator pattern in walk_directory()
```python
# Good: Yields one file at a time
for entry, path in walk_directory(root):
    process(entry)

# Bad: Would load all files into memory
all_files = list(walk_directory(root))  # Don't do this!
```

**Benefits:**
- Constant memory usage
- Works on large images
- Early termination possible

### Scan Limit Tuning

**Guidelines:**
```python
# For RAM-constrained systems (4GB)
SCAN_LIMIT = 5000

# Standard workstation (8GB)
SCAN_LIMIT = 10000  # Default

# Forensic workstation (16GB+)
SCAN_LIMIT = 50000

# Server (32GB+)
SCAN_LIMIT = 100000
```

### Disk I/O Optimization

**Recommendations:**
1. Use SSD for disk images
2. Enable OS read-ahead caching
3. Avoid network-mounted images

**Linux Optimization:**
```bash
# Increase read-ahead buffer
echo 8192 > /sys/block/sda/queue/read_ahead_kb
```

---

## 🚨 ERROR HANDLING

### Extractor.py Error Cases

| Error | Cause | Handling |
|-------|-------|----------|
| File not found | Invalid image path | Raise exception |
| Permission denied | Insufficient permissions | Raise exception |
| Corrupted image | Damaged disk image | Skip corrupted entries |
| Unsupported FS | Exotic filesystem | Raise exception |
| Out of memory | Scan limit too high | Graceful degradation |

### Analyser.py Error Cases

| Error | Cause | Handling |
|-------|-------|----------|
| CSV not found | Extractor not run | Exit with message |
| Missing columns | Corrupted CSV | Exit with message |
| Invalid choice | User input error | Print error, return |
| Invalid timestamp | Malformed data | Convert to NaT |

---

## 📊 DATA STRUCTURES

### Event Record (timeline.csv row)

```python
{
    "time": str,        # ISO 8601 UTC timestamp
    "type": str,        # "CRTIME" | "MTIME" | "ATIME" | "CTIME"
    "path": str,        # Full file path
    "partition": str,   # Partition description
    "inode": int,       # Inode number
    "size": int,        # File size in bytes
    "deleted": bool     # Deletion status
}
```

### File Record (after build_file_table)

```python
{
    "path": str,        # Full file path
    "partition": str,   # Partition description
    "inode": int,       # Inode number
    "size": int,        # File size in bytes
    "deleted": bool,    # Deletion status
    "CRTIME": Timestamp | None,  # Creation time
    "MTIME": Timestamp | None,   # Modification time
    "ATIME": Timestamp | None,   # Access time
    "CTIME": Timestamp | None,   # Change time
    "flags": list[str], # List of detection flags
    "suspicious": bool  # True if flags non-empty
}
```

---

## 🔬 FORENSIC CONSIDERATIONS

### Timestamp Precision

**Filesystem Differences:**
```
FAT32:     2-second granularity (MTIME, CTIME)
NTFS:      100-nanosecond granularity (all)
ext4:      Nanosecond granularity (all)
HFS+:      1-second granularity (all)
```

**Impact on Detection:**
- FAT32 may show more "rapid activity" flags
- Adjust thresholds for FAT32 analysis
- Document filesystem type in report

### Deleted File Artifacts

**What We Can Detect:**
- Recently deleted files (inode present)
- Unallocated files (TSK_FS_META_FLAG_UNALLOC)
- Files in $Recycle.Bin or Trash

**What We Cannot Detect:**
- Secure deletion (wiped inodes)
- Overwritten files (data destroyed)
- Files deleted long ago (inode recycled)

### Chain of Custody

**Evidence Integrity:**
1. Hash original evidence
2. Work on forensic copy
3. Document all steps
4. Preserve all outputs
5. Verify hash after analysis

---

## 📚 APPENDIX

### Sample timeline.csv

```csv
time,type,path,partition,inode,size,deleted
2024-01-20T10:00:00+00:00,CRTIME,/file1.txt,NTFS,12345,1024,False
2024-01-20T10:30:00+00:00,MTIME,/file1.txt,NTFS,12345,1024,False
2024-01-20T11:00:00+00:00,ATIME,/file1.txt,NTFS,12345,1024,False
2024-01-20T15:00:00+00:00,CRTIME,/malware.exe,NTFS,67890,524288,True
2024-01-20T14:30:00+00:00,ATIME,/malware.exe,NTFS,67890,524288,True
```

### Sample Detection Output

```
File: /malware.exe
Flags:
  - Access before creation
  - Deleted file accessed

Forensic Interpretation:
  1. ATIME (14:30) < CRTIME (15:00) = impossible
  2. File is deleted but has access timestamp
  3. High confidence timestamp manipulation
  4. Recommend immediate investigation
```

---

**End of Technical Documentation**

**Version:** 2.0  
**Last Updated:** 2024  
**Components:** Extractor.py, Analyser.py, Main.py
