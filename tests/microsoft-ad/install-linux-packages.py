#!/usr/bin/python3
"""Install the authenticated ISO locally; report evidence and always power off."""
import json
import pathlib
import subprocess
import traceback

TARGETS = ["nfs-kernel-server", "sssd-ad", "sssd-tools", "adcli", "krb5-user"]
MOUNT = pathlib.Path("/mnt/nfs-lab-packages")
STATE = pathlib.Path("/var/lib/nfs-lab-offline-apt")


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def isolation():
    addresses = json.loads(run("ip", "-j", "address", "show"))
    routes4 = json.loads(run("ip", "-4", "-j", "route", "show"))
    routes6 = json.loads(run("ip", "-6", "-j", "route", "show"))
    interfaces = [item for item in addresses if item["ifname"] != "lo"]
    if len(interfaces) != 1 or interfaces[0]["ifname"] != "lab0":
        raise ValueError("Unexpected guest network adapter")
    if interfaces[0]["addr_info"] != []:
        for address in interfaces[0]["addr_info"]:
            if address["family"] != "inet" or address["local"] != "192.0.2.20" or address["prefixlen"] != 24:
                raise ValueError("Unexpected guest address")
    else:
        raise ValueError("Guest static address missing")
    if routes6 or any(item.get("dst") != "192.0.2.0/24" or item.get("gateway") for item in routes4):
        raise ValueError("Unexpected guest route")
    return {"addresses": addresses, "ipv4_routes": routes4, "ipv6_routes": routes6}


def install():
    if run("hostname", "-f") != "nfs.msad.nfs.test" or run("dpkg", "--print-architecture") != "amd64":
        raise ValueError("This installer is only for the existing dedicated NFS guest")
    if 'VERSION_CODENAME=noble' not in pathlib.Path("/etc/os-release").read_text():
        raise ValueError("Unexpected Ubuntu version")
    evidence = {"before": isolation(), "domain_joined": False, "nfs_interoperability_verified": False}
    MOUNT.mkdir(parents=True, exist_ok=True)
    run("mount", "-o", "ro,nosuid,nodev,noexec", "/dev/disk/by-label/cidata", str(MOUNT))
    evidence["authentication"] = run("python3", str(MOUNT / "verify-linux-bundle.py"), "check", str(MOUNT / "bundle"))
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "lists/partial").mkdir(parents=True, exist_ok=True)
    (STATE / "archives/partial").mkdir(parents=True, exist_ok=True)
    (STATE / "sources.list").write_text("deb [trusted=yes] file:" + str(MOUNT / "bundle") + " ./\n")
    options = ["apt-get", "-o", "Dir::Etc::sourcelist=" + str(STATE / "sources.list"),
               "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::State::lists=" + str(STATE / "lists"),
               "-o", "Dir::Cache::archives=" + str(STATE / "archives"), "-o", "Acquire::Languages=none"]
    # No services may start automatically while domain/service configuration is
    # incomplete. This policy is guest-local and removed in the finally block.
    policy = pathlib.Path("/usr/sbin/policy-rc.d")
    if policy.exists():
        raise ValueError("Unexpected existing guest service policy; refusing to overwrite it")
    policy.write_text("#!/bin/sh\nexit 101\n")
    policy.chmod(0o755)
    try:
        run(*options, "update")
        simulation = run(*options, "--no-install-recommends", "--no-remove", "-s", "install", *TARGETS)
        (STATE / "simulation.log").write_text(simulation + "\n")
        output = run("env", "DEBIAN_FRONTEND=noninteractive", *options,
                     "-y", "--no-install-recommends", "--no-remove", "install", *TARGETS)
        (STATE / "installation.log").write_text(output + "\n")
        evidence["transaction_summary"] = [line for line in output.splitlines() if "newly installed" in line]
    finally:
        policy.unlink()
    # Leave unconfigured identity and NFS services inactive after installation.
    run("systemctl", "disable", "--now", "nfs-server.service", "sssd.service", "rpcbind.service", "rpcbind.socket")
    evidence["packages"] = run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Status}\n", *TARGETS)
    evidence["dependency_check"] = run(*options, "check")
    evidence["dpkg_audit"] = run("dpkg", "--audit")
    if evidence["dpkg_audit"]:
        raise ValueError("dpkg audit reported unfinished installation")
    evidence["after"] = isolation()
    evidence["services"] = run("systemctl", "show", "nfs-server.service", "sssd.service", "rpcbind.service", "rpcbind.socket",
                               "--property=Id,ActiveState,UnitFileState")
    if "ActiveState=active" in evidence["services"] or "ActiveState=failed" in evidence["services"]:
        raise ValueError("A prepared service is unexpectedly active or failed")
    evidence["listeners"] = run("ss", "-H", "-lntu")
    if any(line.split()[4].rsplit(":", 1)[-1] in ("111", "2049") for line in evidence["listeners"].splitlines()):
        raise ValueError("An NFS/RPC network listener is unexpectedly active")
    evidence["exports"] = run("exportfs", "-v")
    if evidence["exports"] or pathlib.Path("/etc/sssd/sssd.conf").exists() or pathlib.Path("/etc/krb5.keytab").exists():
        raise ValueError("Unexpected pre-existing NFS export or AD identity configuration")
    evidence["kernel"] = run("uname", "-r")
    module = subprocess.run(["modinfo", "-F", "filename", "nfsd"], text=True, capture_output=True)
    evidence["nfsd_module_available"] = module.returncode == 0
    evidence["nfsd_module"] = module.stdout.strip() if module.returncode == 0 else None
    evidence["hostname"] = run("hostname", "-f")
    evidence["stage"] = "offline-packages-installed-services-inactive"
    return evidence


if __name__ == "__main__":
    try:
        result = install()
        marker = "NFS_LAB_PACKAGES_COMPLETE"
    except Exception:
        result = {"stage": "offline-package-installation-failed", "error": traceback.format_exc()}
        marker = "NFS_LAB_PACKAGES_FAILED"
    text = json.dumps(result, sort_keys=True)
    pathlib.Path("/var/lib/nfs-lab-packages.json").write_text(text + "\n")
    with open("/dev/ttyS0", "w") as serial:
        serial.write("NFS_LAB_PACKAGES_EVIDENCE " + text + "\n" + marker + "\n")
    subprocess.run(["systemctl", "poweroff"], check=True)
