#!/usr/bin/python3
"""Bounded kernel NFS fixture, loopback client matrix, cleanup and poweroff."""
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
import traceback

ROOT = pathlib.Path("/srv/nfs-viewer-kernel")
EXPORTS = pathlib.Path("/etc/exports.d/nfs-viewer-kernel.exports")
CONFIG = pathlib.Path("/etc/nfs.conf.d/99-nfs-viewer-kernel.conf")
MEDIA = pathlib.Path("/mnt/nfs-viewer-kernel")
OUTPUT = pathlib.Path("/var/lib/nfs-viewer-kernel")
SERVICES = ["nfs-server.service", "nfs-mountd.service", "nfs-idmapd.service",
            "rpc-statd.service", "rpc-statd-notify.service", "nfsdcld.service",
            "rpcbind.service", "rpcbind.socket", "sssd.service"]
BIND_MOUNTS = []


def command(*args, check=True, timeout=40):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Command failed: " + repr(args) + "\n" + result.stdout)
    return result.stdout.strip()


def reject_domain_state():
    """Refuse domain/SSSD ownership before a synthetic fixture can claim it."""
    # Presence is sufficient, including empty files and dangling symlinks. Do
    # not open machine credentials, SSSD configuration or the domain marker.
    for name in ("/etc/krb5.keytab", "/etc/sssd/sssd.conf",
                 "/var/lib/nfs-viewer-msad/domain-joined.json"):
        try:
            pathlib.Path(name).lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise SystemExit("Refusing synthetic kernel fixture: cannot inspect domain indicator " + name) from None
        raise SystemExit("Refusing synthetic kernel fixture: domain indicator exists at " + name)

    fragments = pathlib.Path("/etc/sssd/conf.d")
    try:
        info = fragments.lstat()
    except FileNotFoundError:
        info = None
    except OSError:
        raise SystemExit("Refusing synthetic kernel fixture: cannot inspect SSSD config fragments") from None
    if info is not None:
        if not stat.S_ISDIR(info.st_mode):
            raise SystemExit("Refusing synthetic kernel fixture: SSSD config fragment path is not an ordinary directory")
        try:
            if any(path.name.endswith(".conf") for path in fragments.iterdir()):
                raise SystemExit("Refusing synthetic kernel fixture: SSSD config fragment exists")
        except OSError:
            raise SystemExit("Refusing synthetic kernel fixture: cannot inspect SSSD config fragments") from None

    try:
        unit = subprocess.run(["systemctl", "show", "sssd.service", "--property=LoadState,ActiveState,SubState,MainPID"],
                              text=True, capture_output=True, timeout=5)
        processes = subprocess.run(["pgrep", "-x", "sssd|sssd_.*"], text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        raise SystemExit("Refusing synthetic kernel fixture: cannot establish inactive SSSD") from None
    properties = {}
    for line in unit.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in properties:
            raise SystemExit("Refusing synthetic kernel fixture: ambiguous SSSD service state")
        properties[key] = value
    if (unit.returncode != 0 or set(properties) != {"LoadState", "ActiveState", "SubState", "MainPID"}
            or properties["LoadState"] not in ("loaded", "masked", "not-found")
            or properties["ActiveState"] != "inactive" or properties["SubState"] != "dead"
            or properties["MainPID"] != "0" or processes.returncode != 1 or processes.stdout.strip()):
        raise SystemExit("Refusing synthetic kernel fixture: SSSD is running or its inactive state is unverified")


def entry_gate():
    # This must run outside the poweroff/finally path. An accidental invocation
    # on another machine must be read-only, including when identity checks fail.
    reject_domain_state()
    vendor = pathlib.Path("/sys/class/dmi/id/sys_vendor")
    product = pathlib.Path("/sys/class/dmi/id/product_name")
    prior = pathlib.Path("/var/lib/nfs-lab-packages.json")
    if platform.system() != "Linux" or not vendor.is_file() or not product.is_file() or not prior.is_file():
        raise SystemExit("Refusing foreign host: dedicated VMware Linux package-stage evidence required")
    if vendor.read_text().strip() != "VMware, Inc." or product.read_text().strip() not in ("VMware Virtual Platform", "VMware20,1"):
        raise SystemExit("Refusing foreign host: unexpected VMware DMI")
    if command("hostname", "-f") != "nfs.msad.nfs.test" or command("dpkg", "--print-architecture") != "amd64":
        raise SystemExit("Refusing foreign host: unexpected guest identity")
    if json.loads(prior.read_text()).get("stage") != "offline-packages-installed-services-inactive":
        raise SystemExit("Refusing foreign host: successful offline package stage is missing")


def isolation():
    addresses = json.loads(command("ip", "-j", "address", "show"))
    ipv4 = json.loads(command("ip", "-4", "-j", "route", "show"))
    ipv6 = json.loads(command("ip", "-6", "-j", "route", "show"))
    interfaces = [item for item in addresses if item["ifname"] != "lo"]
    if len(interfaces) != 1 or interfaces[0]["ifname"] != "lab0":
        raise ValueError("Unexpected guest adapter inventory")
    if not interfaces[0]["addr_info"] or any(item["family"] != "inet" or item["local"] != "192.0.2.20" or item["prefixlen"] != 24 for item in interfaces[0]["addr_info"]):
        raise ValueError("Unexpected private guest address")
    if ipv6 or any(item.get("dst") != "192.0.2.0/24" or item.get("gateway") for item in ipv4):
        raise ValueError("Unexpected guest route")
    return {"addresses": addresses, "ipv4_routes": ipv4, "ipv6_routes": ipv6}


def directory(path, mode, uid=0, gid=0):
    path.mkdir()
    os.chown(path, uid, gid)
    path.chmod(mode)


def file(path, contents, mode=0o644, uid=0, gid=0):
    path.write_text(contents)
    path.chmod(mode)
    os.chown(path, uid, gid)


def ensure_acl_tools(run_output):
    bundle = MEDIA / "acl-bundle"
    authentication = command("python3", str(MEDIA / "verify-linux-bundle.py"), "check", str(bundle), "--profile", "posix-acl", timeout=90)
    result = {"authentication": authentication, "installed_now": False}
    if not shutil.which("setfacl") or not shutil.which("getfacl"):
        state = run_output / "acl-apt"
        (state / "lists/partial").mkdir(parents=True)
        (state / "archives/partial").mkdir(parents=True)
        (state / "sources.list").write_text("deb [trusted=yes] file:" + str(bundle) + " ./\n")
        options = ["apt-get", "-o", "Dir::Etc::sourcelist=" + str(state / "sources.list"),
                   "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::State::lists=" + str(state / "lists"),
                   "-o", "Dir::Cache::archives=" + str(state / "archives"), "-o", "Acquire::Languages=none"]
        policy = pathlib.Path("/usr/sbin/policy-rc.d")
        if policy.exists():
            raise ValueError("Refusing to overwrite an existing guest service policy")
        policy.write_text("#!/bin/sh\nexit 101\n")
        policy.chmod(0o755)
        try:
            command(*options, "update")
            result["simulation"] = command(*options, "--no-install-recommends", "--no-remove", "-s", "install", "acl")
            result["installation"] = command("env", "DEBIAN_FRONTEND=noninteractive", *options, "-y", "--no-install-recommends", "--no-remove", "install", "acl", timeout=90)
            result["dependency_check"] = command(*options, "check")
            result["installed_now"] = True
        finally:
            policy.unlink()
    result["dpkg_audit"] = command("dpkg", "--audit")
    if result["dpkg_audit"]:
        raise ValueError("ACL installation left an unfinished package transaction")
    result["version"] = command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Status}\n", "acl", "libacl1")
    result["getfacl_version"] = command("getfacl", "--version")
    return result


def acl_snapshot():
    # Physical recursion avoids following any test-created symlinks.
    return command("getfacl", "--numeric", "--absolute-names", "--recursive", "--physical", str(ROOT / "data/acl"))


def prepare_acl_read_fixture():
    path = ROOT / 'data/acl/inherit/masked.txt'
    file(path, 'acl masked fixture\n', 0o600, 20001, 20001)
    command('setfacl', '-m', 'u::rw-,u:20002:rwx,g::---,m::---,o::---', str(path))


def acl_read_seed_metadata(include_masked=True):
    result = {}
    names = ('grant/read.txt', 'inherit') + (('inherit/masked.txt',) if include_masked else ())
    for name in names:
        path = ROOT / 'data/acl' / name
        info = path.lstat()
        result[name] = {'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(info.st_mode & 0o777),
                        'inode': info.st_ino, 'device': info.st_dev, 'bytes': info.st_size}
        if path.is_file():
            result[name]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def acl_set_snapshot():
    """Read numeric policy and data only from the bounded test-owned objects."""
    result = {}
    roots = sorted((ROOT / 'data').glob('acl-set-*'))
    if len(roots) > 64:
        raise ValueError('Unexpected SETACL fixture count')
    for root in roots:
        if not re.fullmatch(r'acl-set-[0-9]+', root.name) or not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError('Unexpected SETACL fixture root')
        children = sorted(root.iterdir())
        if len(children) > 16:
            raise ValueError('Unexpected SETACL fixture child count')
        objects = {}
        for path in [root, *children]:
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError('Refusing to follow a SETACL fixture link or special file')
            if path != root and stat.S_ISDIR(info.st_mode) and any(path.iterdir()):
                raise ValueError('Unexpected nested SETACL fixture object')
            item = {'type': 'directory' if stat.S_ISDIR(info.st_mode) else 'file',
                    'uid': info.st_uid, 'gid': info.st_gid, 'mode': format(info.st_mode & 0o7777, '04o'),
                    'inode': info.st_ino, 'device': info.st_dev, 'bytes': info.st_size}
            if stat.S_ISREG(info.st_mode):
                if info.st_size > 1048576:
                    raise ValueError('Unexpected SETACL fixture file size')
                item['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            objects[str(path.relative_to(ROOT / 'data'))] = item
        result[root.name] = {'objects': objects, 'acl': command('getfacl', '--numeric', '--absolute-names', '--recursive', '--physical', str(root))}
    return result


def prepare_fixture(run_id):
    if ROOT.is_symlink() or ROOT.parent.resolve() != pathlib.Path("/srv"):
        raise ValueError("Unexpected fixture path")
    # Retain prior fixture contents for debugging, but only move a root marked
    # by this runner. No unrelated path is deleted or reused.
    if ROOT.exists():
        marker = ROOT / ".nfs-viewer-kernel-owned"
        if marker.is_symlink() or not marker.is_file() or not re.fullmatch(r"[a-z0-9-]{1,64}\n?", marker.read_text()):
            raise ValueError("Refusing to reuse an unowned fixture directory")
        archived = OUTPUT / ("fixture-" + marker.read_text().strip())
        if archived.exists():
            raise ValueError("Prior fixture archive already exists")
        ROOT.rename(archived)
    directory(ROOT, 0o755)
    file(ROOT / ".nfs-viewer-kernel-owned", run_id + "\n", 0o600)
    directory(ROOT / "data", 0o777, 20001, 20001)
    directory(ROOT / "data/wide", 0o755)
    for index in range(300):
        file(ROOT / "data/wide" / f"entry-{index:03d}.txt", "kernel page\n")
    file(ROOT / "data/read.txt", "kernel fixture\n")
    (ROOT / "data/link.txt").symlink_to("read.txt")
    (ROOT / "data/dangling").symlink_to("missing")
    directory(ROOT / "data/shared", 0o2770, 0, 20003)
    directory(ROOT / "data/sticky", 0o1777)
    directory(ROOT / "data/private", 0o700, 20001, 20001)
    file(ROOT / "data/private/file", "private fixture\n", 0o600, 20001, 20001)
    directory(ROOT / "data/acl", 0o755, 20001, 20001)
    for name in ("grant", "inherit", "replace", "mismatch"):
        directory(ROOT / "data/acl" / name, 0o700, 20001, 20001)
    for name in ("grant", "replace", "mismatch"):
        command("setfacl", "--no-mask", "--set", "u::rwx,u:20002:r-x,g::---,m::r-x,o::---", str(ROOT / "data/acl" / name))
    file(ROOT / "data/acl/grant/read.txt", "acl grant fixture\n", 0o600, 20001, 20001)
    command("setfacl", "--no-mask", "--set", "u::rw-,u:20002:r--,g::---,m::r--,o::---", str(ROOT / "data/acl/grant/read.txt"))
    file(ROOT / "data/acl/mismatch/foreign-owner", "owner mismatch fixture\n", 0o600, 20002, 20001)
    command("setfacl", "--no-mask", "--set", "u::rw-,u:20001:rw-,g::---,m::rw-,o::---", str(ROOT / "data/acl/mismatch/foreign-owner"))
    file(ROOT / "data/acl/mismatch/foreign-group", "group mismatch fixture\n", 0o600, 20001, 20003)
    command("setfacl", "--no-mask", "--set", "u::rw-,u:20002:r--,g::---,m::r--,o::---", str(ROOT / "data/acl/mismatch/foreign-group"))
    inherited = ROOT / "data/acl/inherit"
    command("setfacl", "--no-mask", "--set", "u::rwx,u:20002:rwx,g::---,m::rwx,o::---", str(inherited))
    command("setfacl", "--no-mask", "--default", "--set", "u::rwx,u:20002:rwx,g::---,m::rwx,o::---", str(inherited))
    directory(ROOT / "squashed", 0o777)
    directory(ROOT / "squashed/private", 0o700)
    file(ROOT / "squashed/private/file", "root private\n", 0o600)
    directory(ROOT / "readonly", 0o755)
    file(ROOT / "readonly/read.txt", "read-only export\n")
    directory(ROOT / "secure", 0o777)


def ready():
    deadline = time.monotonic() + 125
    waiter = threading.Event()
    while time.monotonic() < deadline:
        grace = pathlib.Path("/proc/fs/nfsd/v4_end_grace")
        if grace.exists() and grace.read_text().strip() == "Y":
            for protocol, version in (("tcp", "3"), ("udp", "3"), ("tcp", "4")):
                command("rpcinfo", "-T", protocol, "127.0.0.1", "100003", version, timeout=5)
            return
        waiter.wait(0.25)
    raise TimeoutError("Kernel NFSv4 grace did not end within the readiness deadline")


def run_test(binary, release, mode, run_output, acl_read=False, acl_set=False):
    environment = os.environ.copy()
    environment.update({"NFS_VIEWER_KERNEL": "1", "NFS_VIEWER_KERNEL_PORT": "2049", "NFS_VIEWER_KERNEL_MOUNT_PORT": "20048"})
    environment.pop("NFS_VIEWER_TEST_BINARY", None)
    environment.pop("NFS_VIEWER_KERNEL_NFSACL", None)
    environment.pop("NFS_VIEWER_KERNEL_NFSACL_SET", None)
    for name in tuple(environment):
        if name.startswith(("NFS_VIEWER_KERNEL_KRB5", "NFS_VIEWER_KERNEL_GSS_")):
            environment.pop(name)
    if mode == "release":
        environment["NFS_VIEWER_TEST_BINARY"] = str(release)
    patterns = {"standalone-staged": "^TestKernelNFSBehavior$/^3$/^tcp$/^staged-replacement$",
                "standalone-acl": "^TestKernelNFSPOSIXACL$/^4.1$/^tcp$"}
    required = ["TestKernelNFSBehavior", "TestKernelNFSCLI", "TestKernelNFSPOSIXACL", "TestKernelNFSACLCLI"]
    if mode == "standalone-staged":
        required = ["TestKernelNFSBehavior"]
    elif mode == "standalone-acl":
        required = ["TestKernelNFSPOSIXACL"]
    pattern = patterns.get(mode, "^(TestKernelNFSBehavior|TestKernelNFSCLI|TestKernelNFSPOSIXACL|TestKernelNFSACLCLI)$")
    if acl_read:
        environment['NFS_VIEWER_KERNEL_NFSACL'] = '1'
        pattern = '^TestKernelNFSACLRead$'
        required = ['TestKernelNFSACLRead']
    if acl_set:
        environment['NFS_VIEWER_KERNEL_NFSACL_SET'] = '1'
        pattern = '^TestKernelNFSACLSet$'
        required = ['TestKernelNFSACLSet']
    args = [str(binary), "-test.v", "-test.run", pattern, "-test.timeout", "5m"]
    process = subprocess.Popen(args, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, start_new_session=True, cwd=run_output)
    timed_out = False
    try:
        output, _ = process.communicate(timeout=330)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate(timeout=10)
    (run_output / (mode + ".log")).write_text(output)
    matched = all(re.search(r"(?m)^--- PASS: " + re.escape(name) + r" \(", output) for name in required)
    skipped = bool(re.search(r"(?m)^\s*--- SKIP:", output))
    return {"mode": mode, "returncode": process.returncode, "timed_out": timed_out,
            "matched_tests": matched, "skipped_tests": skipped, "output": output}


def cleanup():
    operations = []
    for args in (("systemctl", "stop", *SERVICES), ("rpc.nfsd", "0"), ("exportfs", "-au"), ("exportfs", "-f"),
                 ("systemctl", "disable", "nfs-server.service", "sssd.service", "rpcbind.service", "rpcbind.socket")):
        try:
            operations.append({"command": list(args), "output": command(*args, check=False)})
        except Exception as error:
            operations.append({"command": list(args), "error": str(error)})
    for path in (EXPORTS, CONFIG):
        if path.exists():
            path.unlink()
    for path in reversed(BIND_MOUNTS):
        command("umount", str(path), check=False)
    remaining_binds = [str(path) for path in BIND_MOUNTS if subprocess.run(
        ["mountpoint", "-q", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0]
    exports = command("exportfs", "-v")
    listeners = command("ss", "-H", "-lntu")
    threads_path = pathlib.Path("/proc/fs/nfsd/threads")
    threads = threads_path.read_text().strip() if threads_path.exists() else "0"
    services = command("systemctl", "show", *SERVICES, "--property=Id,ActiveState,UnitFileState", check=False)
    clean = not exports and not remaining_binds and threads == "0" and "ActiveState=active" not in services and not any(
        line.split()[4].rsplit(":", 1)[-1] in ("111", "2049", "20048") for line in listeners.splitlines())
    return {"passed": clean, "operations": operations, "exports": exports, "listeners": listeners,
            "nfsd_threads": threads, "services": services, "remaining_local_bind_mounts": remaining_binds}


def execute(evidence):
    reject_domain_state()
    if command("hostname", "-f") != "nfs.msad.nfs.test" or command("dpkg", "--print-architecture") != "amd64":
        raise ValueError("Unexpected guest identity")
    evidence["before"] = isolation()
    if command("exportfs", "-v") or EXPORTS.exists() or CONFIG.exists():
        raise ValueError("Refusing to replace an existing NFS export or fixture configuration")
    evidence["cleanup_authorized"] = True
    MEDIA.mkdir(exist_ok=True)
    command("mount", "-o", "ro,nosuid,nodev,noexec", "/dev/disk/by-label/cidata", str(MEDIA))
    metadata = json.loads((MEDIA / "run.json").read_text())
    acl_read = metadata.get('NFS3ACLRead', False)
    acl_set = metadata.get('NFS3ACLSet', False)
    if type(acl_read) is not bool or type(acl_set) is not bool or (acl_read and acl_set) or ((acl_read or acl_set) and (metadata.get('Security') != 'kernel-auth-sys' or metadata.get('AuthSysOnGssGuest') is not True)):
        raise ValueError('Invalid AUTH_SYS NFSACL profile')
    run_id = metadata["RunId"]
    if not re.fullmatch(r"[a-z0-9-]{1,64}", run_id):
        raise ValueError("Invalid run identity")
    OUTPUT.mkdir(exist_ok=True)
    run_output = OUTPUT / run_id
    run_output.mkdir()
    evidence["run_id"] = run_id
    evidence["artifacts"] = metadata
    for name in ("cli.test", "nfs-viewer-linux-amd64"):
        source = MEDIA / name
        if hashlib.sha256(source.read_bytes()).hexdigest().upper() != metadata["Hashes"][name]:
            raise ValueError("Test artifact changed after ISO preparation: " + name)
        shutil.copyfile(source, run_output / name)
        (run_output / name).chmod(0o700)
    evidence["acl_tools"] = ensure_acl_tools(run_output)
    prepare_fixture(run_id)
    if acl_read:
        prepare_acl_read_fixture()
        evidence['protocol_profile'] = 'nfs3-acl-read-auth-sys'
        evidence['acl_read_seed_initial'] = acl_read_seed_metadata()
    if acl_set:
        evidence['protocol_profile'] = 'nfs3-acl-set-auth-sys'
        evidence['acl_set_seed_initial'] = acl_read_seed_metadata(include_masked=False)
        evidence['acl_set_initial'] = acl_set_snapshot()
    evidence["acl_initial"] = acl_snapshot()
    evidence["filesystem"] = json.loads(command("findmnt", "-J", "-T", str(ROOT), "-o", "SOURCE,TARGET,FSTYPE,UUID,OPTIONS"))
    if evidence["filesystem"]["filesystems"][0]["fstype"] != "ext4":
        raise ValueError("Kernel fixture requires the existing ext4 guest disk")
    # Explicit local mount boundaries make NFSv4 LOOKUP cross into each child
    # export, rather than continuing with the read-only pseudo-root's policy.
    # These are local ext4 self-bind mounts, never kernel NFS client mounts.
    evidence["child_filesystems"] = {}
    for name in ("data", "squashed", "readonly", "secure"):
        child = ROOT / name
        command("mount", "--bind", str(child), str(child))
        BIND_MOUNTS.append(child)
        evidence["child_filesystems"][name] = json.loads(command("findmnt", "-J", "-M", str(child), "-o", "SOURCE,TARGET,FSTYPE,UUID,OPTIONS"))
    CONFIG.parent.mkdir(exist_ok=True)
    CONFIG.write_text("[nfsd]\nhost=127.0.0.1\nport=2049\nthreads=8\nvers3=y\nvers4=y\nvers4.0=y\nvers4.1=y\nvers4.2=y\nudp=y\ntcp=y\n[mountd]\nport=20048\nmanage-gids=n\n")
    EXPORTS.parent.mkdir(exist_ok=True)
    EXPORTS.write_text(
        f"{ROOT} 127.0.0.1(ro,fsid=0,insecure,root_squash,subtree_check,sec=sys,sync)\n" +
        "".join(f"{ROOT / name} 127.0.0.1({policy},fsid={index},subtree_check,sec=sys,sync)\n" for index, (name, policy) in enumerate([
            ("data", "rw,insecure,no_root_squash"), ("squashed", "rw,insecure,root_squash"),
            ("readonly", "ro,insecure,no_root_squash"), ("secure", "rw,secure,no_root_squash")], 101)))
    command("systemctl", "start", "nfs-server.service", timeout=60)
    ready()
    evidence["versions"] = pathlib.Path("/proc/fs/nfsd/versions").read_text().strip()
    evidence["grace_ended"] = pathlib.Path("/proc/fs/nfsd/v4_end_grace").read_text().strip()
    evidence["exports"] = command("exportfs", "-v")
    evidence["rpcinfo"] = command("rpcinfo", "-p", "127.0.0.1")
    evidence["listeners"] = command("ss", "-H", "-lntu")
    nfs_listeners = [line.split()[4] for line in evidence["listeners"].splitlines() if line.split()[4].rsplit(":", 1)[-1] == "2049"]
    if not nfs_listeners or any(address != "127.0.0.1:2049" for address in nfs_listeners):
        raise ValueError("Kernel NFS daemon is not bound only to guest loopback")
    evidence["kernel"] = command("uname", "-r")
    evidence["package_versions"] = command("dpkg-query", "-W", "-f=${Package}\t${Version}\n", "nfs-kernel-server", "nfs-common")
    evidence["nfs_client_mounts"] = command("findmnt", "-rn", "-t", "nfs,nfs4", check=False)
    if evidence["nfs_client_mounts"]:
        raise ValueError("Unexpected kernel NFS client mount")
    evidence["tests"] = []
    evidence["acl_by_mode"] = {}
    modes = ('in-process',) if acl_set else (('in-process', 'release') if acl_read else ("in-process", "release", "standalone-staged", "standalone-acl"))
    for mode in modes:
        evidence["acl_by_mode"][mode] = {"before": acl_snapshot()}
        if acl_read or acl_set:
            evidence['acl_by_mode'][mode]['seed_before'] = acl_read_seed_metadata(include_masked=acl_read)
        if acl_set:
            evidence['acl_by_mode'][mode]['created_before'] = acl_set_snapshot()
        evidence["tests"].append(run_test(run_output / "cli.test", run_output / "nfs-viewer-linux-amd64", mode, run_output, acl_read, acl_set))
        evidence["acl_by_mode"][mode]["after"] = acl_snapshot()
        if acl_read or acl_set:
            evidence['acl_by_mode'][mode]['seed_after'] = acl_read_seed_metadata(include_masked=acl_read)
        if acl_set:
            evidence['acl_by_mode'][mode]['created_after'] = acl_set_snapshot()
    evidence["after"] = isolation()
    evidence["tests_passed"] = all(test["returncode"] == 0 and not test["timed_out"] and test["matched_tests"] and not test["skipped_tests"] for test in evidence["tests"])


if __name__ == "__main__":
    entry_gate()
    result = {"stage": "kernel-nfs-loopback-auth-sys", "domain_joined": False, "microsoft_ad_verified": False, "tests_passed": False}
    try:
        execute(result)
    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        if result.get("cleanup_authorized"):
            try:
                result["cleanup"] = cleanup()
            except Exception:
                result["cleanup"] = {"passed": False, "error": traceback.format_exc()}
        else:
            result["cleanup"] = {"passed": False, "reason": "Guest preflight rejected; no fixture services were touched"}
    passed = result["tests_passed"] and result["cleanup"]["passed"] and "error" not in result
    text = json.dumps(result, sort_keys=True)
    pathlib.Path("/var/lib/nfs-lab-kernel.json").write_text(text + "\n")
    with open("/dev/ttyS0", "w") as serial:
        serial.write("NFS_LAB_KERNEL_EVIDENCE " + text + "\n")
        serial.write("NFS_LAB_KERNEL_" + ("COMPLETE" if passed else "FAILED") + "\n")
    subprocess.run(["systemctl", "poweroff"], check=True)
