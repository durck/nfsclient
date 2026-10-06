"""Compare guest-native SHA256 results to the public test's payload oracle."""
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
seen = set()
for line in (root / "native-published-sha256.txt").read_text().splitlines():
    digest, path = line.split(maxsplit=1)
    parts = pathlib.PurePosixPath(path).parts
    if parts[2] in ("fat32", "exfat"):
        expected = b"ext4-open-export\n"
        seen.add(("local-linux", parts[2]))
    else:
        fs, policy = parts[2].split("-")
        platform = parts[-1].split("-")[0]
        expected = ("native-" + fs + "-" + policy + "\0").encode() * 257
        seen.add((platform, fs, policy))
    assert hashlib.sha256(expected).hexdigest() == digest, path
for platform in ("windows", "linux"):
    for fs in ("ext4", "xfs", "btrfs"):
        for policy in ("open", "restricted"):
            assert (platform, fs, policy) in seen, (platform, fs, policy)
assert ("local-linux", "fat32") in seen and ("local-linux", "exfat") in seen
print("Native bytes verified: Windows/Linux x three filesystems x two export policies; Linux FAT32/exFAT publication.")
