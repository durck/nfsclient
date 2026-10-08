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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this recorder uses the native Windows PTY")
    from winpty import PtyProcess

    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = output / "files"
    work.mkdir()  # Refuse reused fixture inputs or a previous download.
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
                    "put README.txt README.txt", "put README.txt docs/README.txt",
                    "put client.conf docs/client.conf", "put notes.txt docs/notes.txt"):
        seed.extend(["-c", command])
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("NFS_", "KRB5_")) and k != "NO_COLOR"}
    prepared = subprocess.run(seed, cwd=work, env=env, capture_output=True, timeout=30)
    (output / "seed.log").write_bytes(prepared.stdout + prepared.stderr)
    if prepared.returncode:
        raise RuntimeError("fixture setup failed; inspect " + str(output / "seed.log"))

    argv = [*base, "--uid", "1000", "--gid", "1000", "--color=always"]
    started = time.perf_counter()
    # Match a UTF-8 Windows terminal; legacy console code pages corrupt glyphs.
    launch = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/q", "/c",
              "chcp 65001 >nul && title nfsclient && " + subprocess.list2cmdline(argv)]
    proc = PtyProcess.spawn(launch, cwd=str(work), env=env, dimensions=(30, 100))
    events, inputs, chunks, failures = [], [], [], []
    finished = threading.Event()

    def read_output():
        try:
            while True:
                chunk = proc.read(65536)
                if chunk:
                    events.append([round(time.perf_counter() - started, 6), "o", chunk])
                    chunks.append(chunk)
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

    try:
        wait_prompt("/", 0)
        time.sleep(1.5)
        for command, path, pause in (
            ("ls", "/", 2.0),
            ("cd docs", "/docs", 0.6),
            ("ls", "/docs", 1.8),
            ("cat RE\t", "/docs", 2.5),
            ("cd /uploads", "/uploads", 0.6),
            ("put release-notes.txt", "/uploads", 1.3),
            ("ls", "/uploads", 1.5),
            ("get release-notes.txt downloaded-notes.txt", "/uploads", 1.8),
        ):
            inputs.append({"at": round(time.perf_counter() - started, 6), "input": command})
            for char in command:
                proc.write(char)
                time.sleep(0.07 if char != "\t" else 0.6)
            time.sleep(0.15)
            offset = len("".join(chunks))
            proc.write("\r")
            wait_prompt(path, offset)
            time.sleep(pause)
        for char in "exit":
            proc.write(char)
            time.sleep(0.09)
        proc.write("\r")
        if not finished.wait(10):
            raise TimeoutError("client did not exit")
        if failures:
            raise RuntimeError(failures)
        source = (work / "release-notes.txt").read_bytes()
        downloaded = (work / "downloaded-notes.txt").read_bytes()
        assert source == downloaded, "downloaded bytes differ"
        transcript = "".join(chunks)
        for expected in ("Connected", "Welcome to nfsclient.", "DONE", "PUT", "GET"):
            assert expected in ansi.sub("", transcript), expected
        duration = round(time.perf_counter() - started, 6)
        header = {"version": 2, "width": 100, "height": 30,
                  "title": "nfsclient: Windows interactive session", "duration": duration}
        (output / "demo.cast").write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in [header, *events]) + "\n",
            encoding="utf-8", newline="\n")
        (output / "terminal-output.txt").write_text(transcript, encoding="utf-8", newline="")
        evidence = {"argv": argv, "duration": duration, "output_events": len(events),
                    "output_source": "native Windows PTY, unchanged chunks and observed timestamps",
                    "typed_inputs": inputs, "download_sha256": hashlib.sha256(downloaded).hexdigest(),
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
