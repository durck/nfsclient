"""Run local regression checks without enabling external service fixtures."""

import argparse
import collections
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
RELEASE_CASES = (
    "^(TestStateMigrationProtected|TestObjectDownloadPublication|"
    "TestISCSIBlockUpload|TestISCSIBlockDownloadPublication|TestSecureISCSIBlockCLI|"
    "TestLockProcessCrashRecovery|TestOffloadProcessReconciliation|"
    "TestOffloadSessionProcessRecovery|TestBlockLargeProcessRecovery|TestLegacyACLRelease|"
    "TestISCSIReadRecoveryPublication|TestSecuredObjectRangeWrite)$"
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-container", action="store_true",
                        help="Run Linux Go checks in a temporary golang:1.26.8 container")
    args = parser.parse_args()
    target = "linux" if args.linux_container else platform.system().lower()
    if target not in ("windows", "linux"):
        parser.error("self-check supports Windows and Linux")
    out = ROOT / "bin" / "verification"
    out.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("NFS_", "KRB5_"))}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result_file = out / (target + "-summary.json")
    results = []
    binary_name = "nfsclient-windows-amd64.exe" if target == "windows" else "nfsclient-linux-amd64"
    binary = ROOT / "bin" / binary_name
    module_cache = None
    if args.linux_container:
        module_cache = subprocess.check_output(
            ["go", "env", "GOMODCACHE"], cwd=ROOT, env=env, text=True).strip()

    def go_command(arguments, extra_env=None):
        extra_env = extra_env or {}
        if not args.linux_container:
            return ["go", *arguments], {**env, **extra_env}
        command = ["docker", "run", "--rm", "--name", "nfsclient-selfcheck",
                   "-v", str(ROOT) + ":/work:ro",
                   "-v", str(ROOT / "bin") + ":/work/bin",
                   "-v", module_cache + ":/go/pkg/mod:ro",
                   "-v", "nfsclient-go-build:/root/.cache/go-build", "-w", "/work"]
        for key, value in extra_env.items():
            command.extend(["-e", key + "=" + value])
        return [*command, "golang:1.26.8", "go", *arguments], env

    def run(name, command, run_env=None, cwd=ROOT, go_json=False):
        log = out / (target + "-" + name + ".log")
        print(target, name, "running", flush=True)
        with log.open("wb") as stream:
            process = subprocess.run(command, cwd=cwd, env=run_env or env,
                                     stdout=stream, stderr=subprocess.STDOUT, timeout=900)
        result = {"phase": name, "exit_code": process.returncode,
                  "log": str(log.relative_to(ROOT))}
        if go_json:
            tests, packages = collections.Counter(), collections.Counter()
            failures = []
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                action = event.get("Action")
                if action in ("pass", "fail", "skip"):
                    (tests if "Test" in event else packages)[action] += 1
                    if action == "fail":
                        failures.append({"package": event.get("Package"),
                                         "test": event.get("Test")})
            result.update(test_events=tests, packages=packages, failures=failures)
        results.append(result)
        result_file.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result), flush=True)
        if process.returncode:
            raise SystemExit(process.returncode)

    for phase, arguments in (
        ("vet", ["vet", "./..."]),
        ("race", ["test", "-race", "-json", "-count=1", "-timeout=10m", "./..."]),
    ):
        command, run_env = go_command(arguments)
        run(phase, command, run_env, go_json=phase == "race")

    if not args.linux_container:
        # Discover each directory separately: the evidence decoders have local
        # imports and several directories intentionally reuse test_audit.py.
        directories = sorted({p.parent for p in (ROOT / "tests").rglob("test_*.py")})
        for index, directory in enumerate(directories, 1):
            run("python-" + str(index),
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", ".",
                 "-p", "test_*.py"], cwd=directory)

    destination = "/work/bin/" + binary_name if args.linux_container else str(binary)
    command, run_env = go_command(["build", "-trimpath", "-o", destination, "."],
                                  {"CGO_ENABLED": "0", "GOARCH": "amd64"})
    run("build", command, run_env)
    run("licenses", [sys.executable, "-B", str(ROOT / "tests" / "package_licenses.py")])
    if args.linux_container:
        run("help", ["docker", "run", "--rm", "-v", str(ROOT / "bin") + ":/artifacts:ro",
                     "golang:1.26.8", "/artifacts/" + binary_name, "--help"])
    else:
        run("help", [str(binary), "--help"])
    release_path = "/work/bin/" + binary_name if args.linux_container else str(binary)
    command, run_env = go_command(
        ["test", "-race", "-json", "-count=1", "-timeout=10m", "./internal/cli",
         "-run", RELEASE_CASES], {"NFS_VIEWER_TEST_BINARY": release_path})
    run("release", command, run_env, go_json=True)


if __name__ == "__main__":
    main()
