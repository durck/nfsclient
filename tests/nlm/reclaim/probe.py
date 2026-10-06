"""Independent guest-local POSIX contention observations for the owned fixture."""
import errno
import fcntl
import json
import pathlib
import re
import time

root = pathlib.Path("/evidence")
try:
    last = json.loads((root / "probe-result").read_text())["token"]
except FileNotFoundError:
    last = None
while True:
    try:
        request = json.loads((root / "probe-request").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        time.sleep(0.1)
        continue
    if request["token"] == last:
        time.sleep(0.1)
        continue
    assert re.fullmatch(r"reclaim-(windows|linux)-[23]-(ranges|resume|late)", request["name"])
    assert request["offset"] >= 0 and request["length"] >= 0
    with open(pathlib.Path("/data") / request["name"], "r+b") as file:
        try:
            fcntl.lockf(file, fcntl.LOCK_EX | fcntl.LOCK_NB, request["length"], request["offset"])
            fcntl.lockf(file, fcntl.LOCK_UN, request["length"], request["offset"])
            conflict = False
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EACCES):
                raise
            conflict = True
    result = dict(request, conflict=conflict)
    with (root / "posix-probes.jsonl").open("a") as out:
        out.write(json.dumps(result) + "\n")
    (root / "probe-result").write_text(json.dumps(result))
    last = request["token"]
