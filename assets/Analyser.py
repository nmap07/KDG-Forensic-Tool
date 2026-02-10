#!/usr/bin/env python3
import pandas as pd
from datetime import timedelta
import os
import sys

CSV_FILE = "timeline.csv"
OUTPUT_HTML = "forensic_report.html"

# ---------- LOAD CSV ----------
def load_csv():
    if not os.path.exists(CSV_FILE):
        print("❌ timeline.csv not found")
        sys.exit(1)

    df = pd.read_csv(CSV_FILE)

    required = ["time","type","path","partition","inode","size","deleted"]
    for col in required:
        if col not in df.columns:
            print(f"❌ Missing column: {col}")
            sys.exit(1)

    df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
    df["deleted"] = df["deleted"].astype(str).str.lower().isin(["true","1","yes"])
    df = df.sort_values("time")

    print(f"[+] Loaded {len(df)} events")
    return df

# ---------- COLLAPSE ----------
def build_file_table(df):
    grouped = df.groupby("path", dropna=False)
    rows = []

    for path, g in grouped:
        record = {
            "path": path,
            "partition": g["partition"].iloc[0],
            "inode": g["inode"].iloc[0],
            "size": g["size"].iloc[0],
            "deleted": g["deleted"].iloc[0]
        }

        for _, row in g.iterrows():
            ttype = str(row["type"]).upper()
            if pd.notna(row["time"]):
                record[ttype] = row["time"]

        rows.append(record)

    return pd.DataFrame(rows)

# ---------- DETECTION ----------
def detect(df):
    flags_all = []

    for _, r in df.iterrows():
        flags = []

        c = r.get("CRTIME")
        a = r.get("ATIME")
        m = r.get("MTIME")
        t = r.get("CTIME")

        if pd.notna(c) and pd.notna(a) and a < c:
            flags.append("Access before creation")

        if pd.notna(c) and pd.notna(m) and m < c:
            flags.append("Modified before creation")

        times = [x for x in [c,a,m,t] if pd.notna(x)]
        if len(times) >= 3:
            if max(times) - min(times) < timedelta(seconds=2):
                flags.append("Rapid timestamp activity (<2s)")

        if r.get("deleted") and pd.notna(a):
            flags.append("Deleted file accessed")

        flags_all.append(flags)

    df["flags"] = flags_all
    df["suspicious"] = df["flags"].apply(lambda x: len(x) > 0)
    return df

# ---------- HTML GENERATOR ----------
def generate_html(choice, df_events, df_files):

    html = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Forensic View</title>
<style>
body {font-family: Arial;background:#f5f6f7;padding:30px}
h1 {text-align:center}
.section {background:white;padding:20px;margin-bottom:25px;border-radius:8px}
table {width:100%;border-collapse:collapse;font-size:13px}
th {background:#111;color:white;padding:8px}
td {padding:6px;border-bottom:1px solid #ddd}
.bad {color:red;font-weight:bold}
</style>
</head>
<body>
"""

    # --------- OPTION 1: SUSPICIOUS ---------
    if choice == 1:
        html += "<h1>Suspicious Files</h1>"
        suspicious_df = df_files[df_files["suspicious"]]

        html += """
<div class="section">
<table>
<tr><th>Path</th><th>Flags</th></tr>
"""
        for _, r in suspicious_df.iterrows():
            html += f"<tr><td>{r['path']}</td><td class='bad'>{', '.join(r['flags'])}</td></tr>"

        html += "</table></div>"

    # --------- OPTION 2: FULL FILE TIMELINE ---------
    elif choice == 2:
        html += "<h1>Full File Timeline</h1>"

        html += """
<div class="section">
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
"""
        for _, r in df_files.iterrows():
            html += f"""
<tr>
<td>{r['path']}</td>
<td>{r.get('CRTIME','')}</td>
<td>{r.get('MTIME','')}</td>
<td>{r.get('ATIME','')}</td>
<td>{r.get('CTIME','')}</td>
<td>{r['deleted']}</td>
<td>{', '.join(r['flags'])}</td>
</tr>
"""
        html += "</table></div>"

    # --------- OPTION 3: RAW EVENTS ---------
    elif choice == 3:
        html += "<h1>Raw Timeline Events</h1>"

        html += """
<div class="section">
<table>
<tr>
<th>Time</th>
<th>Type</th>
<th>Path</th>
<th>Partition</th>
<th>Deleted</th>
</tr>
"""
        for _, r in df_events.iterrows():
            html += f"""
<tr>
<td>{r['time']}</td>
<td>{r['type']}</td>
<td>{r['path']}</td>
<td>{r['partition']}</td>
<td>{r['deleted']}</td>
</tr>
"""
        html += "</table></div>"

    html += "</body></html>"

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Open → {OUTPUT_HTML}")

# ---------- MAIN ----------
def main():
    print("\n=== FORENSIC VIEWER ===\n")
    print("1 → Suspicious Files")
    print("2 → Full File Timeline")
    print("3 → Raw Timeline Events")

    try:
        choice = int(input("Select option: "))
    except:
        print("Invalid input")
        return

    if choice not in [1,2,3]:
        print("Invalid choice")
        return

    df_events = load_csv()
    df_files = build_file_table(df_events)
    df_files = detect(df_files)

    generate_html(choice, df_events, df_files)

if __name__ == "__main__":
    main()