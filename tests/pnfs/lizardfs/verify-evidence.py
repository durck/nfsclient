"""Join the pnfs10 logs, unchanged-RPC observations, and native file oracle.

No fixture is contacted. A successful report requires the complete retained
matrix; timings describe these ordered runs, not a general speedup claim.
Elapsed durations and READ ordering use monotonic time; wall times are diagnostic.
"""

import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile


SIZE = (128 << 20) + 17
CHUNK_SIZE = 64 << 20
PLATFORMS = ("windows", "linux")
VERSIONS = ("4.1", "4.2")
API_PHASES = ("sequential", "parallel", "parallel-barrier-held-lock", "cut", "mds-no-read")
CLI_PHASES = ("cli-parallel-1", "cli-parallel-8", "cli-parallel-8-barrier", "mds-no-read")
NAME = r"pnfs-multi-(api|cli)-(windows|linux)-(4\.[12])-([0-9]+)"
SUCCESS = re.compile(
    r"PNFS_MULTI_(API|CLI) platform=(windows|linux) version=(4\.[12]) "
    r"remote=(\S+) bytes=([0-9]+) sha256=([0-9a-f]{64})(.*?) verified\s*$"
)
METRIC = re.compile(
    r"PNFS_MULTI_READ remote=(\S+) phase=([a-z0-9-]+) wire_bytes=([0-9]+) "
    r"seconds=([0-9]+\.[0-9]{6}) MiB_per_second=([0-9]+\.[0-9]{3}) requests=([0-9]+)\s*$"
)
BAD_LOG = re.compile(
    r"^\s*(?:--- (?:FAIL|SKIP):|FAIL\b|panic:|fatal error:)|WARNING: DATA RACE|no tests to run",
    re.MULTILINE,
)
TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})")


class InvalidEvidence(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, f"{label}: invalid integer {value!r}")
    return value


def timestamp(value, label, allow_zero=False):
    match = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    require(match is not None, f"{label}: invalid timestamp {value!r}")
    base, fraction, zone = match.groups()
    instant = dt.datetime.fromisoformat(base + ("+00:00" if zone == "Z" else zone))
    require(instant.year >= 2000 or (allow_zero and value == "0001-01-01T00:00:00Z"),
            f"{label}: missing/zero timestamp")
    elapsed = instant - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + int((fraction or "").ljust(9, "0"))


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(raw):
    def invalid_constant(value):
        raise InvalidEvidence(f"non-finite JSON value: {value}")

    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def pattern_hash():
    # Adding 251*256 to an offset changes both formula terms by multiples of
    # 256, so this period computes the expected hash without a 128 MiB buffer.
    period = bytes((offset * 31 + offset // 251) % 256 for offset in range(251 * 256))
    digest = hashlib.sha256()
    whole, tail = divmod(SIZE, len(period))
    for _ in range(whole):
        digest.update(period)
    digest.update(period[:tail])
    return digest.hexdigest()


def parse_log(text, platform, mode, expected_hash):
    require(not BAD_LOG.search(text), f"{platform}/{mode}: failed, skipped, or incomplete test")
    require(re.search(r"^PASS\s*$", text, re.MULTILINE), f"{platform}/{mode}: missing process PASS")
    tail = text.rstrip().splitlines()[-1].strip()
    require(tail == "PASS" or re.match(r"ok\s+nfs-viewer/internal/cli\b", tail),
            f"{platform}/{mode}: unexpected log ending {tail!r}")
    tests = ["TestLizardPNFSMultiDSCLI"]
    if mode == "api":
        tests.append("TestLizardPNFSMultiDS")
    for test in tests:
        for suffix in ("", "/4.1", "/4.2"):
            require(re.search(r"^\s*--- PASS: " + re.escape(test + suffix) + r" \(", text, re.MULTILINE),
                    f"{platform}/{mode}: missing PASS for {test + suffix}")
    profiles, metrics = {}, {}
    expected = {(kind, version) for kind in (["api", "cli"] if mode == "api" else ["cli"]) for version in VERSIONS}
    for line in text.splitlines():
        if "PNFS_MULTI_API" in line or "PNFS_MULTI_CLI" in line:
            match = SUCCESS.search(line)
            require(match is not None, f"{platform}/{mode}: malformed success marker")
            kind, observed_platform, version, name, size, digest, rest = match.groups()
            kind = kind.lower()
            require(observed_platform == platform, f"{name}: wrong log platform")
            name_parts = re.fullmatch(NAME, name)
            require(name_parts and name_parts.groups()[:3] == (kind, platform, version), f"{name}: name/profile mismatch")
            require(int(size) == SIZE and digest == expected_hash, f"{name}: incorrect size or deterministic payload hash")
            flags = rest.split()
            required = {"two_DS", "held_lock", "no_MDS_read", "reconnect"}
            if kind == "api":
                required |= {"sequential", "parallel", "barrier", "contention", "DS_cut", "no_replay"}
                require(not any(flag.startswith("binary=") for flag in flags), f"{name}: unexpected binary flag")
            else:
                binary_flags = [flag for flag in flags if flag.startswith("binary=")]
                require(binary_flags == ["binary=" + ("true" if mode == "release" else "false")], f"{name}: incorrect CLI mode")
            require(required <= set(flags), f"{name}: missing successful-check flags")
            key = (kind, version)
            require(key in expected and key not in profiles, f"{platform}/{mode}: duplicate or unexpected profile {key}")
            profiles[key] = {"name": name, "platform": platform, "version": version, "kind": kind,
                             "execution": "api" if kind == "api" else ("release-cli" if mode == "release" else "inprocess-cli"),
                             "size": SIZE, "sha256": digest}
        elif "PNFS_MULTI_READ" in line:
            match = METRIC.search(line)
            require(match is not None, f"{platform}/{mode}: malformed timing marker")
            name, phase, count, seconds, rate, requests = match.groups()
            key = (name, phase)
            require(key not in metrics, f"{name}/{phase}: duplicate timing marker")
            metrics[key] = {"wire_bytes": int(count), "seconds": float(seconds), "rate": float(rate), "requests": int(requests)}
    require(set(profiles) == expected, f"{platform}/{mode}: incomplete success profile matrix")
    return list(profiles.values()), metrics


def topology_servers(document):
    def endpoint(value, label):
        require(isinstance(value, str), f"{label}: missing endpoint")
        host, separator, port = value.rpartition(":")
        require(separator and port.isascii() and port.isdigit(), f"{label}: invalid endpoint")
        address = ipaddress.IPv4Address(host)
        require(str(address) == host and not address.is_unspecified and not address.is_multicast,
                f"{label}: invalid endpoint address")
        require(1 <= int(port) <= 65535 and str(int(port)) == port, f"{label}: invalid endpoint port")
        return host, int(port)

    require(isinstance(document, dict), "missing fixture topology")
    servers = document.get("servers")
    mds = document.get("mds")
    require(isinstance(servers, list) and len(servers) == 2 and isinstance(mds, dict),
            "topology must contain two DS records and one MDS record")
    result, containers, ips, advertised, windows_targets, linux_targets = {}, set(), set(), set(), set(), set()
    for server in servers:
        server_id = integer(server.get("server_id"), 0, 1, "topology server ID")
        require(server_id not in result, "topology contains a repeated server ID")
        container = server.get("container")
        require(isinstance(container, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", container)
                and container not in containers, "topology contains a missing or repeated DS container")
        ip = str(ipaddress.IPv4Address(server.get("chunkserver_ip")))
        require(ip == server["chunkserver_ip"] and ip not in ips, "topology must contain two distinct canonical chunkserver IPs")
        ad = endpoint(server.get("advertised"), f"DS{server_id} advertised")
        windows = endpoint(server.get("windows_target"), f"DS{server_id} Windows target")
        linux = endpoint(server.get("linux_target"), f"DS{server_id} Linux target")
        require(ad == (ip, 2049) and linux == ad and windows[0] == "127.0.0.1",
                f"DS{server_id}: endpoint/chunkserver IP or container-port mapping mismatch")
        require(ad not in advertised and windows not in windows_targets and linux not in linux_targets,
                "topology contains duplicate DS endpoints")
        result[server_id] = server
        containers.add(container)
        ips.add(ip)
        advertised.add(ad)
        windows_targets.add(windows)
        linux_targets.add(linux)
    container = mds.get("container")
    require(isinstance(container, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", container)
            and container not in containers, "MDS container is missing or aliases a DS container")
    ad = endpoint(mds.get("advertised"), "MDS advertised")
    windows = endpoint(mds.get("windows_target"), "MDS Windows target")
    require(ad[1] == 2049 and ad[0] not in ips and ad not in advertised
            and windows[0] == "127.0.0.1" and windows not in windows_targets,
            "MDS endpoint is invalid or aliases a DS endpoint")
    return result


def native_files(document, profiles, expected_hash):
    require(isinstance(document, dict) and document.get("ok") is True and document.get("operation") == "oracle",
            "native oracle did not report successful verification")
    files = document.get("files")
    require(isinstance(files, list) and len(files) == 12, "native oracle must contain exactly 12 files")
    result = {}
    for file in files:
        name = file.get("name")
        require(name in profiles and name not in result, f"unexpected/duplicate native file {name!r}")
        integer(file.get("size"), SIZE, SIZE, f"{name} native size")
        integer(file.get("uid"), 25001, 25001, f"{name} native UID")
        integer(file.get("gid"), 25000, 25000, f"{name} native GID")
        require(file.get("mode") == "0644" and file.get("goal") == "1" and file.get("pattern_verified") is True,
                f"{name}: native mode, goal, or byte pattern not verified")
        require(file.get("sha256") == profiles[name]["sha256"] == expected_hash, f"{name}: native/log payload hash mismatch")
        chunks = file.get("chunks")
        require(isinstance(chunks, list) and len(chunks) == 3, f"{name}: expected three native chunks")
        ips, indexes, ids, chunkserver_by_index = set(), set(), set(), {}
        for chunk in chunks:
            index = integer(chunk.get("index"), 0, 2, f"{name} chunk index")
            chunk_id = chunk.get("id")
            require(isinstance(chunk_id, str) and re.fullmatch(r"[1-9][0-9]*", chunk_id), f"{name}: invalid native chunk ID")
            require(index not in indexes and chunk_id not in ids, f"{name}: repeated chunk index or ID")
            indexes.add(index)
            ids.add(chunk_id)
            integer(chunk.get("version"), 1, 2**32 - 1, f"{name} chunk version")
            addresses = chunk.get("addresses")
            require(isinstance(addresses, list) and len(addresses) == 1, f"{name}: expected one replica per chunk")
            address = addresses[0]
            integer(address.get("part_type_id"), 0, 0, f"{name} chunk part type")
            integer(address.get("port"), 1, 65535, f"{name} chunk port")
            ip = str(ipaddress.IPv4Address(address.get("ip")))
            require(ip != "0.0.0.0", f"{name}: zero chunkserver IP")
            ips.add(ip)
            chunkserver_by_index[str(index)] = ip
        require(indexes == {0, 1, 2} and len(ips) >= 2, f"{name}: multi-server physical placement missing")
        integer(file.get("distinct_chunkserver_ips"), len(ips), len(ips), f"{name} distinct IP count")
        result[name] = {"chunkserver_ips": sorted(ips), "chunk_ids": sorted(ids),
                        "chunkserver_by_index": chunkserver_by_index}
    require(set(result) == set(profiles), "native/log filename sets differ")
    return result


def verify_snapshot(document, name, phase, metric, native_file, servers):
    label = f"{name}/{phase}"
    serial_baseline = phase in ("sequential", "cli-parallel-1")
    require(document.get("Remote") == name and document.get("Phase") == phase, f"{label}: snapshot identity mismatch")
    elapsed = integer(document.get("ElapsedNS"), 0 if phase == "mds-no-read" else 1, 30 * 60 * 10**9, f"{label} elapsed")
    snapshot = document.get("Snapshot")
    require(isinstance(snapshot, dict), f"{label}: missing snapshot")
    require({"Connections", "Reads", "Errors", "BarrierMatched", "BarrierTimedOut"} <= set(snapshot),
            f"{label}: incomplete observer snapshot")
    connections = snapshot.get("Connections")
    require(isinstance(connections, dict) and connections, f"{label}: observer saw no connection")
    for server, count in connections.items():
        require(server in ("-1", "0", "1"), f"{label}: unexpected observer server ID")
        integer(count, 1, 100, f"{label} connection count")
    reads = snapshot.get("Reads")
    errors = snapshot.get("Errors")
    require(reads is None or isinstance(reads, list), f"{label}: invalid READ list")
    require(errors is None or isinstance(errors, list), f"{label}: invalid observer errors")
    reads, errors = reads or [], errors or []
    require(all(isinstance(error, str) for error in errors), f"{label}: invalid observer error entries")
    matched, timed_out = snapshot.get("BarrierMatched"), snapshot.get("BarrierTimedOut")
    require(type(matched) is bool and type(timed_out) is bool, f"{label}: missing barrier result")
    if phase != "cut":
        require(not errors, f"{label}: observer errors: {errors}")
    if phase == "mds-no-read":
        require(set(connections) == {"-1"} and not reads and not matched and not timed_out and elapsed == 0,
                f"{label}: MDS READ fallback or invalid MDS evidence")
        received, barrier_pair = 0, None
    else:
        require(set(connections) <= {"0", "1"} and all(count == 1 for count in connections.values()),
                f"{label}: DS connection replay/unexpected connection")
        received, parsed, identities, offsets = 0, [], set(), set()
        for read in reads:
            require(isinstance(read, dict) and {"RequestedAt", "ForwardedAt", "RepliedAt"} <= set(read),
                    f"{label}: incomplete READ timing record")
            server = integer(read.get("ServerID"), 0, 1, f"{label} READ server")
            xid = integer(read.get("XID"), 0, 2**32 - 1, f"{label} READ XID")
            offset = integer(read.get("Offset"), 0, SIZE - 1, f"{label} READ offset")
            count = integer(read.get("Count"), 1, min(1 << 20, SIZE - offset), f"{label} READ count")
            chunk_index = offset // CHUNK_SIZE
            require(offset + count <= (chunk_index + 1) * CHUNK_SIZE, f"{label}: READ crosses a native chunk boundary")
            require(native_file["chunkserver_by_index"].get(str(chunk_index)) == servers[server]["chunkserver_ip"],
                    f"{label}: READ server {server} does not own native chunk {chunk_index}")
            returned = integer(read.get("ReturnedBytes"), 0, count, f"{label} returned bytes")
            status = integer(read.get("WireStatus"), 0, 2**32 - 1, f"{label} NFS status")
            require(str(server) in connections and (server, xid) not in identities and offset not in offsets,
                    f"{label}: unconnected server, repeated RPC XID, or repeated READ offset")
            identities.add((server, xid))
            offsets.add(offset)
            timing = []
            for event in ("Requested", "Forwarded", "Replied"):
                required = event == "Requested" or phase != "cut" or returned > 0
                captured = integer(read.get(event + "NS"), 1 if required else 0, 2**63 - 1,
                                   f"{label} {event.lower()} monotonic nanoseconds")
                wall_time = read.get(event + "At")
                timestamp(wall_time, label + " " + event.lower(), allow_zero=captured == 0)
                require(captured != 0 or wall_time == "0001-01-01T00:00:00Z",
                        f"{label}: {event.lower()} wall time has no monotonic capture")
                timing.append(captured)
            requested, forwarded, replied = timing
            require((not forwarded or requested <= forwarded) and
                    (not replied or (forwarded > 0 and forwarded <= replied)),
                    f"{label}: invalid monotonic READ event order")
            if phase != "cut":
                require(status == 0 and returned == count, f"{label}: invalid/short/failed READ")
                parsed.append((offset, count, server, requested, forwarded, replied))
            else:
                # A transport cut may leave a request or response unfinished.
                # Completed bytes still need a successful corresponding reply.
                if returned:
                    require(status == 0, f"{label}: cut bytes have no successful reply")
            received += returned
        barrier_pair = None
        if phase == "cut":
            require(0 < received < SIZE and not matched and not timed_out, f"{label}: cut did not leave a partial transfer")
        else:
            require(set(connections) == {"0", "1"}, f"{label}: two DS connections not demonstrated")
            offset, servers = 0, set()
            parsed.sort()
            for read in parsed:
                require(read[0] == offset, f"{label}: gap, overlap, or repeated READ at offset {offset}")
                offset += read[1]
                servers.add(read[2])
            require(offset == received == SIZE and servers == {0, 1}, f"{label}: incomplete two-DS wire coverage")
            if serial_baseline:
                for previous, current in zip(parsed, parsed[1:]):
                    require(current[3] >= previous[5],
                            f"{label}: sequential READ at offset {current[0]} started before the previous reply")
            if "barrier" in phase:
                require(matched and not timed_out, f"{label}: boundary gate did not prove overlap")
                for left, right in zip(parsed, parsed[1:]):
                    if (left[2] != right[2] and left[0] + left[1] == right[0]
                            and max(left[3], right[3]) <= min(left[4], right[4])
                            and max(left[3], right[3]) < min(left[5], right[5])):
                        barrier_pair = {"boundary": right[0], "server_ids": [left[2], right[2]],
                                        "both_requests_observed_before_either_forward_or_reply": True}
                        break
                require(barrier_pair is not None, f"{label}: no distinct-server boundary request pair supports overlap")
            else:
                require(not matched and not timed_out, f"{label}: unexpected barrier affected unimpeded timing")
    seconds = elapsed / 1e9
    rate = received / (1 << 20) / seconds if seconds else 0.0
    require(metric["wire_bytes"] == received and metric["requests"] == len(reads), f"{label}: log/snapshot byte or request count differs")
    require(abs(metric["seconds"] - seconds) <= 0.00000051 and abs(metric["rate"] - rate) <= 0.00051,
            f"{label}: log/snapshot timing differs")
    return {"elapsed_ns": elapsed, "seconds": seconds, "wire_bytes": received, "requests": len(reads),
            "MiB_per_second": rate, "connections": connections, "barrier_pair": barrier_pair,
            "observer_errors": errors, "serial_baseline_verified": serial_baseline}


def verify(artifact_dir):
    inventory = {}

    def read(path):
        raw = path.read_bytes()
        inventory[path.relative_to(artifact_dir).as_posix()] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        return raw

    expected_hash = pattern_hash()
    profiles, metrics = {}, {}
    for platform in PLATFORMS:
        for mode in ("api", "release"):
            path = artifact_dir / f"pnfs10-{platform}-{mode}.log"
            observed, timings = parse_log(read(path).decode("utf-8-sig"), platform, mode, expected_hash)
            for profile in observed:
                name = profile["name"]
                require(name not in profiles, f"duplicate filename across logs: {name}")
                profile["log"] = path.name
                profiles[name] = profile
            require(not set(metrics) & set(timings), "timing marker appears in more than one log")
            metrics.update(timings)
    require(len(profiles) == 12, "expected 4 API and 8 CLI profiles")
    expected_snapshots = {(name, phase) for name, profile in profiles.items()
                          for phase in (API_PHASES if profile["kind"] == "api" else CLI_PHASES)}
    require(len(expected_snapshots) == 52 and set(metrics) == expected_snapshots, "timing marker matrix must match all 52 snapshots exactly")
    evidence = artifact_dir / "pnfs10-evidence"
    actual = {path.name for path in evidence.glob("*.json")}
    expected_names = {f"{name}-{phase}.json" for name, phase in expected_snapshots}
    require(actual == expected_names, f"snapshot files differ: missing={sorted(expected_names - actual)}, extra={sorted(actual - expected_names)}")
    topology = load_json(read(artifact_dir / "pnfs10-topology.json"))
    servers = topology_servers(topology)
    native = native_files(load_json(read(artifact_dir / "pnfs10-independent.json")), profiles, expected_hash)
    for name, profile in profiles.items():
        phases = API_PHASES if profile["kind"] == "api" else CLI_PHASES
        profile["native"] = native[name]
        profile["phases"] = {phase: verify_snapshot(load_json(read(evidence / f"{name}-{phase}.json")), name, phase, metrics[name, phase], native[name], servers)
                             for phase in phases}
        sequential, parallel = phases[:2]
        sequential_seconds = profile["phases"][sequential]["seconds"]
        parallel_seconds = profile["phases"][parallel]["seconds"]
        profile["ordered_timing_comparison"] = {
            "sequential_seconds": sequential_seconds, "parallel_seconds": parallel_seconds,
            "parallel_to_sequential_elapsed_ratio": parallel_seconds / sequential_seconds,
            "scope": "GetPNFS only" if profile["kind"] == "api" else "CLI invocation including connect, locks, transfer, unlock, and reconnect",
        }
    return {
        "ok": True, "operation": "verify-pnfs10-evidence", "profiles_verified": 12,
        "snapshot_files_verified": 52, "native_files_verified": 12, "payload_size": SIZE,
        "expected_payload_sha256": expected_hash,
        "timing_limits": "Ordered sequential then parallel warm runs on this disposable fixture. Barrier runs are excluded from comparisons. These are observations, not a general benchmark or speedup claim.",
        "timing_clock": "ElapsedNS is a Go monotonic duration. READ causality, serial baselines, and barrier overlap use RequestedNS/ForwardedNS/RepliedNS from one monotonic process origin. RFC3339 wall timestamps are diagnostic only.",
        "placement_check": "Every observed DS READ stays within one 64 MiB native chunk and its observer ServerID maps through the retained topology to that chunk's single physical replica IP.",
        "topology": topology,
        "profiles": sorted(profiles.values(), key=lambda item: (item["platform"], item["execution"], item["version"])),
        "input_files": dict(sorted(inventory.items())),
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def atomic_report(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def selftest():
    """Synthetic evidence tests the validator only; never represents a lab run."""
    checks = 0

    def reject(operation):
        nonlocal checks
        try:
            operation()
        except (InvalidEvidence, OSError, ValueError, TypeError, KeyError, AttributeError):
            checks += 1
        else:
            raise AssertionError("validator accepted deliberately invalid evidence")

    def stamp(n):
        return f"2026-09-25T00:00:00.{n:09d}Z"

    require(timestamp(stamp(2), "test") - timestamp(stamp(1), "test") == 1, "lost nanosecond precision")
    checks += 1
    reject(lambda: load_json('{"ok":true,"ok":false}'))
    reject(lambda: load_json('{"value":NaN}'))
    digest = pattern_hash()
    records = []
    for index, offset in enumerate(range(0, SIZE, 1 << 20)):
        count = min(1 << 20, SIZE - offset)
        records.append({"ServerID": (offset // CHUNK_SIZE) % 2, "XID": index + 1, "Offset": offset,
                        "Count": count, "ReturnedBytes": count, "WireStatus": 0,
                        "RequestedAt": stamp(index * 10 + 1), "ForwardedAt": stamp(index * 10 + 2),
                        "RepliedAt": stamp(index * 10 + 3), "RequestedNS": index * 10 + 1,
                        "ForwardedNS": index * 10 + 2, "RepliedNS": index * 10 + 3})
    with tempfile.TemporaryDirectory(prefix="pnfs-evidence-verifier-selftest-") as temporary:
        root = Path(temporary).resolve()
        require(root.parent == Path(tempfile.gettempdir()).resolve(), "selftest temp directory escaped its owner")
        evidence = root / "pnfs10-evidence"
        evidence.mkdir()
        topology = {"servers": [{"server_id": i, "container": f"selftest-ds{i + 1}",
                                 "advertised": f"192.0.2.{i + 1}:2049", "linux_target": f"192.0.2.{i + 1}:2049",
                                 "windows_target": f"127.0.0.1:{13050 + i}", "chunkserver_ip": f"192.0.2.{i + 1}"}
                                for i in range(2)],
                    "mds": {"container": "selftest-mds", "advertised": "192.0.2.3:2049", "windows_target": "127.0.0.1:13049"}}
        topology_path = root / "pnfs10-topology.json"
        topology_path.write_text(json.dumps(topology), encoding="utf-8")
        native = {"ok": True, "operation": "oracle", "files": []}
        sample = None
        for platform in PLATFORMS:
            for mode in ("api", "release"):
                lines = []
                for kind in (["api", "cli"] if mode == "api" else ["cli"]):
                    for version in VERSIONS:
                        number = len(native["files"]) + 1
                        name = f"pnfs-multi-{kind}-{platform}-{version}-{number}"
                        phases = API_PHASES if kind == "api" else CLI_PHASES
                        for phase in phases:
                            snapshot = {"Connections": {"0": 1, "1": 1}, "Reads": copy.deepcopy(records),
                                        "Errors": None, "BarrierMatched": "barrier" in phase, "BarrierTimedOut": False}
                            elapsed = 1_000_000_000
                            if phase == "mds-no-read":
                                snapshot["Connections"], snapshot["Reads"], elapsed = {"-1": 3}, None, 0
                            elif phase == "cut":
                                snapshot["Connections"], snapshot["Reads"] = {"0": 1}, snapshot["Reads"][:2]
                            elif "barrier" in phase:
                                for index in (63, 64):
                                    snapshot["Reads"][index]["ForwardedAt"] = stamp(643)
                                    snapshot["Reads"][index]["RepliedAt"] = stamp(644)
                                    snapshot["Reads"][index]["ForwardedNS"] = 643
                                    snapshot["Reads"][index]["RepliedNS"] = 644
                            document = {"Remote": name, "Phase": phase, "ElapsedNS": elapsed, "Snapshot": snapshot}
                            path = evidence / f"{name}-{phase}.json"
                            path.write_text(json.dumps(document), encoding="utf-8")
                            received = sum(read["ReturnedBytes"] for read in (snapshot["Reads"] or []))
                            rate = received / (1 << 20) if elapsed else 0
                            lines.append(f"PNFS_MULTI_READ remote={name} phase={phase} wire_bytes={received} seconds={elapsed / 1e9:.6f} MiB_per_second={rate:.3f} requests={len(snapshot['Reads'] or [])}")
                            if sample is None and "barrier" in phase:
                                sample = (path, copy.deepcopy(document),
                                          {"wire_bytes": received, "requests": len(records), "seconds": 1.0, "rate": float(f"{rate:.3f}")})
                        flags = "two_DS held_lock no_MDS_read reconnect"
                        flags += " sequential parallel barrier contention DS_cut no_replay" if kind == "api" else " binary=" + ("true" if mode == "release" else "false")
                        lines.append(f"PNFS_MULTI_{kind.upper()} platform={platform} version={version} remote={name} bytes={SIZE} sha256={digest} {flags} verified")
                        native["files"].append({"name": name, "size": SIZE, "uid": 25001, "gid": 25000,
                                                "mode": "0644", "goal": "1", "sha256": digest, "pattern_verified": True,
                                                "distinct_chunkserver_ips": 2,
                                                "chunks": [{"index": i, "id": str(number * 3 + i), "version": 1,
                                                            "addresses": [{"ip": "192.0.2." + str(1 + i % 2), "port": 9422, "part_type_id": 0, "label": "selftest"}]} for i in range(3)]})
                    test = "TestLizardPNFSMultiDS" + ("CLI" if kind == "cli" else "")
                    lines.extend(f"--- PASS: {test}{suffix} (1.00s)" for suffix in ("", "/4.1", "/4.2"))
                lines.append("PASS")
                (root / f"pnfs10-{platform}-{mode}.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        native_path = root / "pnfs10-independent.json"
        native_path.write_text(json.dumps(native), encoding="utf-8")
        result = verify(root)
        require(result["ok"] and len(result["input_files"]) == 58, "complete synthetic evidence did not validate")
        checks += 1
        require(all(value["serial_baseline_verified"] is (phase in ("sequential", "cli-parallel-1"))
                    for profile in result["profiles"] for phase, value in profile["phases"].items()),
                "serial baseline result is missing or applied to another phase")
        checks += 1
        path, document, metric = sample
        native_file = next(profile["native"] for profile in result["profiles"] if profile["name"] == document["Remote"])
        servers = topology_servers(topology)
        for phase, kind in (("sequential", "api"), ("cli-parallel-1", "cli")):
            profile = next(profile for profile in result["profiles"] if profile["kind"] == kind)
            serial = load_json((evidence / f"{profile['name']}-{phase}.json").read_bytes())
            serial["Snapshot"]["Reads"][64]["RequestedNS"] = serial["Snapshot"]["Reads"][63]["RepliedNS"]
            require(verify_snapshot(serial, profile["name"], phase, metric, profile["native"], servers)["serial_baseline_verified"],
                    f"{phase}: serial READ beginning at the previous reply was rejected")
            checks += 1
            # Wall-clock adjustments do not change the monotonic event order.
            for read in serial["Snapshot"]["Reads"]:
                read.update(RequestedAt=stamp(3), ForwardedAt=stamp(2), RepliedAt=stamp(1))
            require(verify_snapshot(serial, profile["name"], phase, metric, profile["native"], servers)["serial_baseline_verified"],
                    f"{phase}: wall-clock backstep invalidated a monotonic serial baseline")
            checks += 1
            # Preserve valid byte coverage and each READ's monotonic order,
            # but start the next DS request before the previous reply arrives.
            serial["Snapshot"]["Reads"][64]["RequestedNS"] = serial["Snapshot"]["Reads"][63]["ForwardedNS"]
            reject(lambda: verify_snapshot(serial, profile["name"], phase, metric, profile["native"], servers))
        adjusted = copy.deepcopy(document)
        for read in adjusted["Snapshot"]["Reads"]:
            read.update(RequestedAt=stamp(3), ForwardedAt=stamp(2), RepliedAt=stamp(1))
        require(verify_snapshot(adjusted, adjusted["Remote"], adjusted["Phase"], metric, native_file, servers)["barrier_pair"],
                "wall-clock backstep invalidated a monotonic barrier pair")
        checks += 1
        for field in ("RequestedNS", "ForwardedNS", "RepliedNS"):
            changed = copy.deepcopy(document)
            changed["Snapshot"]["Reads"][0].pop(field)
            reject(lambda: verify_snapshot(changed, changed["Remote"], changed["Phase"], metric, native_file, servers))
        for mutation in (
            lambda s: s.update(BarrierMatched=False),
            lambda s: s.update(BarrierTimedOut=True),
            lambda s: s.update(Errors=["deliberate selftest error"]),
            lambda s: s.pop("Errors"),
            lambda s: s["Connections"].update({"0": 2}),
            lambda s: s["Reads"][0].update(Offset=1),
            lambda s: s["Reads"][63].update(Offset=CHUNK_SIZE - 1, Count=2),
            lambda s: s["Reads"][0].update(ServerID=1),
            lambda s: s["Reads"][0].update(ReturnedBytes=0),
            lambda s: s["Reads"][0].update(WireStatus=13),
            lambda s: s["Reads"][0].update(Count=True),
            lambda s: s["Reads"][0].update(RepliedAt="0001-01-01T00:00:00Z"),
            lambda s: s["Reads"][1].update(XID=s["Reads"][0]["XID"]),
            lambda s: s["Reads"][63].update(ForwardedNS=632, RepliedNS=633),
            lambda s: s["Reads"][0].update(RequestedNS=0),
            lambda s: s["Reads"][0].update(ForwardedNS=0),
            lambda s: s["Reads"][0].update(RepliedNS=0),
            lambda s: s["Reads"][0].update(RequestedNS=True),
            lambda s: s["Reads"][0].update(ForwardedNS=3, RepliedNS=2),
            lambda s: s["Reads"][0].update(RequestedNS=3, ForwardedNS=2),
        ):
            changed = copy.deepcopy(document)
            mutation(changed["Snapshot"])
            reject(lambda: verify_snapshot(changed, changed["Remote"], changed["Phase"], metric, native_file, servers))
        changed_metric = dict(metric, requests=metric["requests"] + 1)
        reject(lambda: verify_snapshot(document, document["Remote"], document["Phase"], changed_metric, native_file, servers))
        mds = load_json((evidence / f"{document['Remote']}-mds-no-read.json").read_bytes())
        mds["Snapshot"]["Reads"] = copy.deepcopy(records[:1])
        reject(lambda: verify_snapshot(mds, mds["Remote"], "mds-no-read", {"wire_bytes": 0, "requests": 0, "seconds": 0, "rate": 0}, native_file, servers))
        cut = load_json((evidence / f"{document['Remote']}-cut.json").read_bytes())
        for forwarded in (False, True):
            unfinished = copy.deepcopy(cut)
            pending = copy.deepcopy(records[2])
            pending.update(ReturnedBytes=0, RepliedNS=0, RepliedAt="0001-01-01T00:00:00Z")
            if not forwarded:
                pending.update(ForwardedNS=0, ForwardedAt="0001-01-01T00:00:00Z")
            unfinished["Snapshot"]["Reads"].append(pending)
            require(verify_snapshot(unfinished, unfinished["Remote"], "cut",
                                    {"wire_bytes": 2 << 20, "requests": 3, "seconds": 1, "rate": 2},
                                    native_file, servers)["wire_bytes"] == 2 << 20,
                    "unfinished cut READ rejected valid zero event captures")
            checks += 1
        for read in cut["Snapshot"]["Reads"]:
            read["ReturnedBytes"] = 0
        reject(lambda: verify_snapshot(cut, cut["Remote"], "cut", {"wire_bytes": 0, "requests": 2, "seconds": 1, "rate": 0}, native_file, servers))
        original = path.read_bytes()
        path.unlink()
        reject(lambda: verify(root))
        path.write_bytes(original)
        extra = evidence / "unexpected.json"
        extra.write_text("{}", encoding="utf-8")
        reject(lambda: verify(root))
        extra.unlink()
        changed_topology = copy.deepcopy(topology)
        changed_topology["servers"][0]["server_id"], changed_topology["servers"][1]["server_id"] = 1, 0
        topology_path.write_text(json.dumps(changed_topology), encoding="utf-8")
        reject(lambda: verify(root))
        changed_topology = copy.deepcopy(topology)
        changed_topology["servers"][0]["chunkserver_ip"] = "192.0.2.2"
        topology_path.write_text(json.dumps(changed_topology), encoding="utf-8")
        reject(lambda: verify(root))
        changed_topology = copy.deepcopy(topology)
        for i, server in enumerate(changed_topology["servers"]):
            server["chunkserver_ip"] = f"192.0.2.{2 - i}"
            server["advertised"] = server["linux_target"] = f"192.0.2.{2 - i}:2049"
        topology_path.write_text(json.dumps(changed_topology), encoding="utf-8")
        reject(lambda: verify(root))
        topology_path.write_text(json.dumps(topology), encoding="utf-8")
        changed = copy.deepcopy(native)
        changed["files"][0]["chunks"][1]["addresses"][0]["ip"] = "192.0.2.1"
        native_path.write_text(json.dumps(changed), encoding="utf-8")
        reject(lambda: verify(root))
        native_path.write_text(json.dumps(native), encoding="utf-8")
        log = root / "pnfs10-windows-api.log"
        original_log = log.read_text(encoding="utf-8")
        for bad in (original_log + "FAIL\n", original_log.replace("--- PASS:", "--- SKIP:", 1),
                    original_log.replace("binary=false", "binary=true", 1), original_log.replace(digest, "0" * 64, 1)):
            log.write_text(bad, encoding="utf-8")
            reject(lambda: verify(root))
        log.write_text(original_log, encoding="utf-8")
        require(verify(root)["ok"], "selftest restoration failed")
        checks += 1
    print(json.dumps({"ok": True, "operation": "verifier-selftest", "checks": checks,
                      "evidence": "synthetic validator tests only; no fixture contacted"}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, default=Path("bin"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--selftest", action="store_true", help="exercise validation with synthetic evidence; no fixture access")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.output is None:
        parser.error("--output is required unless --selftest is selected")
    artifact_dir, output = args.artifact_dir.resolve(), args.output.resolve()
    protected = {artifact_dir / f"pnfs10-{platform}-{mode}.log" for platform in PLATFORMS for mode in ("api", "release")}
    protected.add(artifact_dir / "pnfs10-independent.json")
    protected.add(artifact_dir / "pnfs10-topology.json")
    if output in protected or output.parent == artifact_dir / "pnfs10-evidence":
        parser.error("output must not overwrite or be placed among input evidence")
    try:
        result = verify(artifact_dir)
    except (InvalidEvidence, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        result = {"ok": False, "operation": "verify-pnfs10-evidence", "error": str(exc)}
    atomic_report(output, result)
    if not result["ok"]:
        print(result["error"], file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "profiles_verified": 12, "snapshot_files_verified": 52, "output": str(output)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
