"""Move obsolete bin artifacts to a sibling archive, preserving current outputs.

Dry-run by default. Active VMware fixture files are always retained. This moves
files without deleting historical evidence or freeing disk space.
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
KEEP = {
    "verification", "microsoft-ad-lab", "nfsclient-windows-amd64.exe",
    "nfsclient-linux-amd64", "nfs-viewer-as-helper", "THIRD-PARTY-LICENSES.txt",
    "ARCHIVE_LOCATION.json",
}


def inventory(path):
    files, size = 0, 0
    pending = [path]
    while pending:
        current = pending.pop()
        info = current.lstat()
        # Never traverse or relocate a symlink, junction or mounted directory.
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError("refusing reparse point: " + str(current))
        if current.is_dir():
            pending.extend(current.iterdir())
        else:
            files += 1
            size += info.st_size
    return {"files": files, "bytes": size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Move inventoried entries after validation")
    args = parser.parse_args()
    root = ROOT.resolve(strict=True)
    bin_dir = root / "bin"
    if not bin_dir.is_dir() or bin_dir.is_symlink() or getattr(bin_dir.lstat(), "st_file_attributes", 0) & 0x400 or bin_dir.resolve(strict=True).parent != root:
        parser.error("bin must be a normal directory within this project")
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    archive_parent = root.parent / (root.name + "-artifacts")
    destination = archive_parent / (stamp + "-audit-fixes")
    if archive_parent.exists() and (archive_parent.is_symlink() or getattr(archive_parent.lstat(), "st_file_attributes", 0) & 0x400 or archive_parent.resolve() != archive_parent):
        parser.error("archive parent must be a normal sibling directory")
    if destination.parent.parent != root.parent:
        parser.error("archive destination must be a fresh directory in the sibling archive")
    entries = []
    for entry in sorted(bin_dir.iterdir()):
        if entry.name in KEEP:
            continue
        if entry.resolve(strict=True).parent != bin_dir.resolve(strict=True):
            parser.error("artifact escapes bin: " + str(entry))
        entries.append({"name": entry.name, **inventory(entry)})
    result = {"project": str(root), "archive": str(destination), "applied": args.apply and bool(entries),
              "entries": entries, "retained": sorted(KEEP),
              "files": sum(e["files"] for e in entries),
              "bytes": sum(e["bytes"] for e in entries)}
    print(json.dumps(result, indent=2))
    if not args.apply or not entries:
        return
    if destination.exists():
        parser.error("archive destination must be a fresh directory in the sibling archive")
    destination.mkdir(parents=True, exist_ok=False)
    runtime = destination / "runtime-bin"
    runtime.mkdir()
    manifest = destination / "manifest.json"
    result["moved"] = []
    manifest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for record in entries:
        source, target = bin_dir / record["name"], runtime / record["name"]
        if source.resolve(strict=True).parent != bin_dir.resolve(strict=True) or target.parent.resolve() != runtime.resolve() or target.exists():
            raise ValueError("artifact paths changed after validation")
        # Rename stays on this volume and retains the entire original artifact.
        os.rename(source, target)
        result["moved"].append(record["name"])
        manifest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (bin_dir / "ARCHIVE_LOCATION.json").write_text(json.dumps({
        "archive": str(destination), "manifest": str(manifest),
        "note": "Historical bin paths now live under archive/runtime-bin; active microsoft-ad-lab retained."
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
