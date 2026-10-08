"""Record the real Windows interactive client against a fresh disposable export.

Requires pywinpty and a test-owned NFSv4.1 server exposing /data. This script
creates fixture files, types into a native PTY and saves its unchanged output
with observed timestamps. It never synthesizes terminal output or captions.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time


def check_public_transcript(transcript, private_values):
    """Refuse publication rather than redact or reconstruct terminal output."""
    normalized = transcript.casefold().replace("\\\\", "\\")
    if (re.search(r"[a-z]:[\\/]", normalized)
            or re.search(r"\\\\[a-z0-9_.-]+[\\/]", transcript.casefold())):
        raise RuntimeError("recording contains an absolute Windows path; not saved")
    for value in private_values:
        if value and len(value) >= 3 and value.casefold() in normalized:
            raise RuntimeError("recording contains private profile information; not saved")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True,
                        help="fresh neutral directory outside the personal user profile")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this recorder uses the native Windows PTY")
    from winpty import PtyProcess
    import pyte

    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = args.work_dir.resolve()
    profile = Path.home().resolve()
    if work == profile or profile in work.parents:
        parser.error("--work-dir must be outside the personal user profile")
    work.mkdir(parents=True)  # Refuse reused fixture inputs or a previous download.
    fixtures = {
        "README.txt": "Welcome to nfsclient.\n\nBrowse remote files without mounting the export.\nThis session uses a disposable local NFS server.\n",
        "client.conf": "server = localhost\nexport = /data\nversion = 4.1\n",
        "notes.txt": "Project notes\n- Browse the export\n- Preview text files\n- Upload and download a file\n",
        "release-notes.txt": "nfsclient release notes\n\nInteractive NFS access on Windows and Linux.\nNo local NFS mount required.\n",
    }
    for name, content in fixtures.items():
        (work / name).write_text(content, encoding="utf-8", newline="\n")
    base = [str(binary), "localhost", "--nfs-port", str(args.port),
            "--nfs-version", "4.1", "--export", "/data",
            "--auto-uid=false", "--auto-escape=false"]
    seed = [*base, "--uid", "0", "--gid", "0"]
    for command in ("mkdir docs", "mkdir uploads", "mkdir ProgramData", "chmod 777 uploads",
                    "mkdir infrastructure", "mkdir cloud", "mkdir cloud/.aws",
                    "put README.txt README.txt", "put README.txt docs/README.txt",
                    "put client.conf docs/client.conf", "put notes.txt docs/notes.txt",
                    "put client.conf infrastructure/web.config",
                    "put client.conf infrastructure/tnsnames.ora",
                    "put notes.txt infrastructure/network-backup.cfg",
                    "put notes.txt infrastructure/mailbox.pst",
                    "put client.conf cloud/.aws/config",
                    "put notes.txt cloud/terraform.tfstate",
                    "put client.conf cloud/.env.example"):
        seed.extend(["-c", command])
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("NFS_", "KRB5_")) and k != "NO_COLOR"}
    prepared = subprocess.run(seed, cwd=work, env=env, capture_output=True, timeout=90)
    (output / "seed.log").write_bytes(prepared.stdout + prepared.stderr)
    if prepared.returncode:
        raise RuntimeError("fixture setup failed; inspect " + str(output / "seed.log"))

    argv = [*base, "--uid", "1000", "--gid", "1000", "--color=always"]
    started = time.perf_counter()
    # Match a UTF-8 Windows terminal; legacy console code pages corrupt glyphs.
    launch = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/q", "/c",
              "chcp 65001 >nul && title nfsclient && " + subprocess.list2cmdline(argv)]
    proc = PtyProcess.spawn(launch, cwd=str(work), env=env, dimensions=(32, 110))
    events, inputs, chunks, failures, typing_checks = [], [], [], [], []
    screen = pyte.Screen(110, 32)
    stream = pyte.Stream(screen)
    screen_lock = threading.Lock()
    finished = threading.Event()

    def read_output():
        try:
            while True:
                chunk = proc.read(65536)
                if chunk:
                    events.append([round(time.perf_counter() - started, 6), "o", chunk])
                    chunks.append(chunk)
                    with screen_lock:
                        stream.feed(chunk)
                    # ConPTY can request the initial cursor position before startup.
                    if "\x1b[6n" in chunk:
                        proc.write("\x1b[1;1R")
        except EOFError:
            pass
        except Exception as exc:
            failures.append(repr(exc))
        finally:
            finished.set()

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")

    def wait_prompt(path, offset):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            text = ansi.sub("", "".join(chunks)[offset:])
            if re.search(r"nfs [^\r\n]* " + re.escape(path) + r" >", text):
                return
            if finished.is_set():
                raise RuntimeError("client exited before prompt: " + repr(text[-1000:]))
            time.sleep(0.025)
        raise TimeoutError("interactive prompt missing: " + repr("".join(chunks)[-1500:]))

    def type_command(command, path):
        visible = ""
        for char in command:
            proc.write(char)
            if char == "\t":
                time.sleep(0.6)  # Real completion deliberately inserts the suffix at once.
                continue
            visible += char
            expected = path + " > " + visible
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with screen_lock:
                    echoed = expected in screen.display[screen.cursor.y]
                if echoed:
                    typing_checks.append({"at": round(time.perf_counter() - started, 6),
                                          "visible": expected})
                    break
                if finished.is_set():
                    raise RuntimeError("client exited while typing")
                time.sleep(0.01)
            else:
                raise TimeoutError("typed character was not displayed")
            # Do not send the next key until this actual screen state has been
            # held long enough to remain visible in both GIF and video.
            time.sleep(0.08)

    try:
        wait_prompt("/", 0)
        time.sleep(1.8)
        # Chapter boundaries use readline's real clear-screen key. No output is
        # inserted, deleted or reconstructed in the recording.
        steps = (
            ("Connection and help", "ls", "/", 1.5),
            (None, "help ls", "/", 1.5),
            (None, "pwd", "/", 0.5),
            ("Navigation and preview", "cd docs", "/docs", 0.8),
            (None, "ls", "/docs", 1.5),
            (None, "cat RE\t", "/docs", 1.5),
            (None, "hex client.conf", "/docs", 1.5),
            ("Corporate and cloud hints", "ls /infrastructure", "/docs", 1.5),
            (None, "legend /infrastructure/web.config", "/docs", 1.5),
            (None, "ls /cloud", "/docs", 1.5),
            (None, "legend /cloud/terraform.tfstate", "/docs", 1.5),
            (None, "ls /cloud/.aws", "/docs", 1.5),
            (None, "legend /cloud/.aws/config", "/docs", 1.5),
            ("Upload and verified download", "cd /uploads", "/uploads", 0.8),
            (None, "help put", "/uploads", 1.5),
            (None, "put release-notes.txt", "/uploads", 1.5),
            (None, "get release-notes.txt downloaded-notes.txt", "/uploads", 1.5),
            (None, "cat release-notes.txt", "/uploads", 1.5),
            ("Links and permissions", "ln -s release-notes.txt latest.txt", "/uploads", 1.5),
            (None, "readlink latest.txt", "/uploads", 1.0),
            (None, "ln release-notes.txt release-copy.txt", "/uploads", 1.5),
            (None, "chmod 640 release-notes.txt", "/uploads", 1.5),
            (None, "access release-notes.txt", "/uploads", 1.5),
            (None, "ls", "/uploads", 1.5),
            ("Organize and clean up", "mkdir archive", "/uploads", 1.0),
            (None, "mv release-copy.txt archive/release-notes.txt", "/uploads", 1.5),
            (None, "ls archive", "/uploads", 1.5),
            (None, "rm latest.txt", "/uploads", 0.8),
            (None, "rm archive/release-notes.txt", "/uploads", 0.8),
            (None, "rmdir archive", "/uploads", 0.8),
            (None, "rm release-notes.txt", "/uploads", 0.8),
            (None, "ls", "/uploads", 1.5),
            (None, "cd /", "/", 0.8),
            (None, "ls", "/", 1.5),
        )
        current_path = "/"
        for index, (chapter, command, path, pause) in enumerate(steps):
            if chapter and index:
                proc.write("\x0c")
                time.sleep(0.4)
            inputs.append({"at": round(time.perf_counter() - started, 6),
                           "input": command, "chapter": chapter})
            type_command(command, current_path)
            time.sleep(0.15)
            offset = len("".join(chunks))
            proc.write("\r")
            wait_prompt(path, offset)
            current_path = path
            command_output = ansi.sub("", "".join(chunks)[offset:])
            if re.search(r"(?im)^\s*(error:|failed:|unknown command)", command_output):
                raise RuntimeError(f"demo command failed: {command}: {command_output}")
            time.sleep(pause)
        type_command("exit", "/")
        proc.write("\r")
        if not finished.wait(10):
            raise TimeoutError("client did not exit")
        if failures:
            raise RuntimeError(failures)
        source = (work / "release-notes.txt").read_bytes()
        downloaded = (work / "downloaded-notes.txt").read_bytes()
        assert source == downloaded, "downloaded bytes differ"
        transcript = "".join(chunks)
        check_public_transcript(ansi.sub("", transcript),
                                [str(profile), profile.name, os.environ.get("USERNAME"),
                                 os.environ.get("COMPUTERNAME")])
        for expected in ("Connected", "Welcome to nfsclient.", "DONE", "PUT", "GET"):
            assert expected in ansi.sub("", transcript), expected
        duration = round(time.perf_counter() - started, 6)
        header = {"version": 2, "width": 110, "height": 32,
                  "title": "nfsclient: Windows interactive session", "duration": duration}
        (output / "demo.cast").write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in [header, *events]) + "\n",
            encoding="utf-8", newline="\n")
        (output / "terminal-output.txt").write_text(transcript, encoding="utf-8", newline="")
        evidence = {"argv": argv, "duration": duration, "output_events": len(events),
                    "output_source": "native Windows PTY, unchanged chunks and observed timestamps",
                    "typed_inputs": inputs, "download_sha256": hashlib.sha256(downloaded).hexdigest(),
                    "visible_prefix_checks": typing_checks,
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "roundtrip_equal": True}
        (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"duration": duration, "events": len(events), "roundtrip_equal": True}))
    finally:
        if proc.isalive():
            proc.terminate(force=True)
        reader.join(timeout=2)


if __name__ == "__main__":
    main()
