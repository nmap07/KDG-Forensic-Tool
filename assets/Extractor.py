#!/usr/bin/env python3
import pytsk3
import csv
from datetime import datetime, timezone

# ---------- SETTINGS ----------
SCAN_LIMIT = 10000
OUTPUT_CSV = "timeline.csv"

# ---------- Time conversion ----------
def to_utc(ts):
    try:
        if ts is None or ts == 0:
            return None
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None

# ---------- Open image ----------
def open_image(image_path):
    img = pytsk3.Img_Info(image_path)
    vol = pytsk3.Volume_Info(img)

    for part in vol:
        if part.len > 0 and "Unallocated" not in str(part.desc):
            try:
                fs = pytsk3.FS_Info(img, offset=part.start * 512)
                desc = str(part.desc)
                return fs, desc
            except Exception:
                continue

    fs = pytsk3.FS_Info(img)
    return fs, "No Partition"

# ---------- Walk filesystem ----------
def walk_directory(directory, parent_path="/", counter=[0]):
    for entry in directory:

        if counter[0] >= SCAN_LIMIT:
            return

        try:
            if not entry.info.name:
                continue

            name = entry.info.name.name.decode(errors="ignore")
            if name in [".", ".."]:
                continue

            full_path = parent_path + name
            counter[0] += 1

            yield entry, full_path

            if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    subdir = entry.as_directory()
                    yield from walk_directory(subdir, full_path + "/", counter)
                except Exception:
                    pass
        except Exception:
            continue

# ---------- Extract timeline ----------
def extract_timeline(fs, partition_desc):
    timeline = []

    root = fs.open_dir(path="/")

    for entry, path in walk_directory(root):
        try:
            meta = entry.info.meta
            if not meta:
                continue

            inode = meta.addr
            size = meta.size if meta.size else 0

            deleted = False
            try:
                deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            except:
                pass

            timestamps = {
                "ATIME": getattr(meta, "atime", 0),
                "MTIME": getattr(meta, "mtime", 0),
                "CTIME": getattr(meta, "ctime", 0),
                "CRTIME": getattr(meta, "crtime", 0),
            }

            for t_type, t_val in timestamps.items():
                t_conv = to_utc(t_val)
                if t_conv:
                    timeline.append({
                        "time": t_conv,
                        "type": t_type,
                        "path": path,
                        "partition": partition_desc,
                        "inode": inode,
                        "size": size,
                        "deleted": deleted
                    })

        except Exception:
            continue

    timeline.sort(key=lambda x: x["time"])
    return timeline

# ---------- Write CSV ----------
def write_csv(timeline):
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "time",
                "type",
                "path",
                "partition",
                "inode",
                "size",
                "deleted"
            ]
        )
        writer.writeheader()
        writer.writerows(timeline)

# ---------- MAIN ----------
def main():
    image_path = input("Enter disk image path: ").strip().strip('"')

    fs, part_desc = open_image(image_path)

    timeline = extract_timeline(fs, part_desc)
    write_csv(timeline)

    print(f"[+] Extracted {len(timeline)} events")
    print(f"[+] Scan limit used: {SCAN_LIMIT}")
    print(f"[+] CSV saved as: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()