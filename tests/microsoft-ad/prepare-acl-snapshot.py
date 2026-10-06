"""Prepare acl from the existing authenticated Ubuntu snapshot, offline."""
import json
import pathlib
import shutil
import subprocess
import runpy

BASE = pathlib.Path("/base")
BUNDLE = pathlib.Path("/bundle")
SCRIPT = "/scripts/verify-linux-bundle.py"

if not pathlib.Path("/.dockerenv").is_file() or (BUNDLE / "verified.json").exists():
    raise SystemExit("Requires an isolated preparation container and unfinished bundle")
subprocess.run(["python3", SCRIPT, "check", str(BASE)], check=True)
verifier = runpy.run_path(SCRIPT)
proof = json.loads((BASE / "provenance.json").read_text())
chosen = None
for record in proof["indexes"]:
    index = subprocess.check_output(["/usr/lib/apt/apt-helper", "cat-file", str(BASE / record["index"])]).decode()
    for package in verifier["paragraphs"](index):
        if package.get("Package") != "acl" or package.get("Architecture") != "amd64":
            continue
        if chosen and subprocess.run(["dpkg", "--compare-versions", package["Version"], "le", chosen["Version"]]).returncode == 0:
            continue
        authenticated = verifier["authenticate_index"](BASE, record, {package["SHA256"]})
        chosen = authenticated[package["SHA256"]]
if chosen is None:
    raise SystemExit("Authenticated snapshot contains no amd64 acl package")
for directory in ("debs", "provenance"):
    shutil.copytree(BASE / directory, BUNDLE / directory, dirs_exist_ok=True)
proof["requested"] = ["acl"]
proof["snapshot_reuse"] = "Authenticated existing nfs-ad bundle; added acl from the same signed indexes"
(BUNDLE / "provenance.json").write_text(json.dumps(proof, indent=2) + "\n")
pool = pathlib.PurePosixPath(chosen["Filename"])
if pool.parent != pathlib.PurePosixPath("pool/main/a/acl") or not pool.name.startswith("acl_"):
    raise SystemExit("Unexpected signed acl pool path")
plan = {"source": "https://archive.ubuntu.com/ubuntu/" + str(pool), "filename": pool.name,
        "bytes": int(chosen["Size"]), "sha256": chosen["SHA256"], "version": chosen["Version"]}
(BUNDLE / "acl-download-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
print(json.dumps(plan))
