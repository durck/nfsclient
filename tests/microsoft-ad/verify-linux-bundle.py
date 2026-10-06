#!/usr/bin/python3
"""Authenticate offline debs through Ubuntu InRelease -> Packages -> SHA256."""
import hashlib
import argparse
import json
import pathlib
import shutil
import subprocess
import sys

TARGETS = ["nfs-kernel-server", "sssd-ad", "sssd-tools", "adcli", "krb5-user"]


def run(*args):
    return subprocess.check_output(args)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def paragraphs(text):
    for paragraph in text.strip().split("\n\n"):
        fields = {}
        key = None
        for line in paragraph.splitlines():
            if line.startswith(" ") and key:
                fields[key] += "\n" + line
            elif ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
            elif line.endswith(":"):
                key = line[:-1]
                fields[key] = ""
        yield fields


def safe_child(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or path.is_symlink():
        raise ValueError("Unsafe bundle path")
    return path


def authenticate_index(root, record, wanted):
    release = safe_child(root, record["release"])
    signature = run("gpgv", "--status-fd", "1", "--keyring",
                    "/usr/share/keyrings/ubuntu-archive-keyring.gpg", str(release)).decode()
    if "[GNUPG:] VALIDSIG " not in signature:
        raise ValueError("Missing authenticated Ubuntu signature")
    text = release.read_text().split("\n\n", 1)[1].split("-----BEGIN PGP SIGNATURE-----", 1)[0]
    fields = next(paragraphs(text))
    if fields.get("Origin") != "Ubuntu" or fields.get("Codename") != "noble":
        raise ValueError("Unexpected signed release")
    index = run("/usr/lib/apt/apt-helper", "cat-file", str(safe_child(root, record["index"])))
    expected = [line.split() for line in fields["SHA256"].splitlines() if line.strip()]
    if [sha(index), str(len(index)), record["metakey"]] not in expected:
        raise ValueError("Package index does not match signed Ubuntu Release")
    return {item["SHA256"]: item for item in paragraphs(index.decode()) if item.get("SHA256") in wanted}


def prepare(root):
    records = []
    for target in paragraphs(run("apt-get", "indextargets").decode()):
        if target.get("Identifier") != "Packages":
            continue
        filename = pathlib.Path(target["Filename"])
        # APT's filename before the component directory identifies InRelease.
        component = target["Component"]
        release = pathlib.Path(str(filename).split("_" + component + "_binary-amd64_Packages", 1)[0] + "_InRelease")
        if not release.exists():
            raise ValueError("Could not locate authenticated Release")
        index_dest = root / "provenance" / filename.name
        release_dest = root / "provenance" / release.name
        shutil.copyfile(filename, index_dest)
        shutil.copyfile(release, release_dest)
        records.append({"index": str(index_dest.relative_to(root)), "release": str(release_dest.relative_to(root)),
                        "metakey": target["MetaKey"], "uri": target["URI"]})
    proof = {"suite": "noble", "architecture": "amd64", "requested": TARGETS, "indexes": records}
    (root / "provenance.json").write_text(json.dumps(proof, indent=2) + "\n")


def verify(root):
    proof = json.loads((root / "provenance.json").read_text())
    if proof["requested"] != TARGETS or proof["architecture"] != "amd64" or proof["suite"] != "noble":
        raise ValueError("Unexpected package target")
    debs = {deb: sha(deb.read_bytes()) for deb in sorted((root / "debs").glob("*.deb"))}
    wanted = set(debs.values())
    signed_packages = {}
    for record in proof["indexes"]:
        signed_packages.update(authenticate_index(root, record, wanted))
    packages = []
    for deb, digest in debs.items():
        package = signed_packages.get(digest)
        if package is None or str(deb.stat().st_size) != package["Size"]:
            raise ValueError("Unauthenticated deb: " + deb.name)
        if package["Architecture"] not in ("amd64", "all"):
            raise ValueError("Unexpected architecture")
        packages.append({"package": package["Package"], "version": package["Version"],
                         "architecture": package["Architecture"], "filename": "debs/" + deb.name,
                         "sha256": digest, "ubuntu_pool_path": package["Filename"], "bytes": deb.stat().st_size})
    if not set(TARGETS).issubset({item["package"] for item in packages}):
        raise ValueError("A requested package is missing")
    local_index = list(paragraphs((root / "Packages").read_text()))
    authenticated = {item["filename"]: item for item in packages}
    if len(local_index) != len(authenticated):
        raise ValueError("Local repository must contain exactly the authenticated debs")
    for item in local_index:
        original = authenticated.get(item["Filename"])
        if original is None or any(item[key] != original[field] for key, field in
                                   (("Package", "package"), ("Version", "version"),
                                    ("Architecture", "architecture"), ("SHA256", "sha256"))):
            raise ValueError("Local repository differs from authenticated debs")
    result = {"requested": TARGETS, "package_count": len(packages), "packages": packages,
              "authentication": "Ubuntu archive keyring verifies InRelease, which authenticates Packages and deb SHA256",
              "dependency_installation_verified": False}
    # Guest verification is read-only because the source is an ISO.
    if sys.argv[1] == "verify":
        temporary = root / "verified.json.partial"
        temporary.write_text(json.dumps(result, indent=2) + "\n")
        temporary.replace(root / "verified.json")
    print(json.dumps({"authenticated_debs": len(packages), "requested": TARGETS}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("prepare", "verify", "check"))
    parser.add_argument("bundle")
    parser.add_argument("--profile", choices=("nfs-ad", "posix-acl", "kernel-gss", "kernel-gssproxy"), default="nfs-ad")
    args = parser.parse_args()
    if args.profile == "posix-acl":
        TARGETS = ["acl"]
    elif args.profile in ("kernel-gss", "kernel-gssproxy"):
        TARGETS = ["krb5-kdc", "krb5-admin-server", "acl", "nfs-kernel-server", "krb5-user"]
        if args.profile == "kernel-gssproxy":
            TARGETS.append("gssproxy")
    operation = args.operation
    root = pathlib.Path(args.bundle)
    if operation == "prepare":
        prepare(root)
    elif operation in ("verify", "check"):
        verify(root)
    else:
        raise SystemExit("Unknown operation")
