"""Coalesce split ConPTY erase/redraw events for video rendering only.

The original cast remains the timing/source of truth. No output bytes are
removed or generated; erase-only events wait at most 150 ms for their redraw.
"""

import argparse
import json
from pathlib import Path
import re


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")


def coalesce(events):
    result = []
    pending = None
    for event in events:
        if pending is not None:
            if event[1] == "o" and 0 <= event[0] - pending[0] <= 0.15:
                result.append([event[0], "o", pending[2] + event[2]])
                pending = None
                continue
            result.append(pending)
            pending = None
        if event[1] == "o" and "\x1b[K" in event[2] and not ANSI.sub("", event[2]).strip():
            pending = event
        else:
            result.append(event)
    if pending is not None:
        result.append(pending)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("render copy must not replace the original recording")
    rows = [json.loads(line) for line in args.source.read_text(encoding="utf-8").splitlines()]
    rendered = coalesce(rows[1:])
    assert "".join(r[2] for r in rows[1:] if r[1] == "o") == "".join(
        r[2] for r in rendered if r[1] == "o")
    args.destination.write_text("\n".join(json.dumps(r, ensure_ascii=False)
                                        for r in [rows[0], *rendered]) + "\n", encoding="utf-8")
    print(f"Coalesced {len(rows) - 1 - len(rendered)} split redraws; output bytes unchanged")


if __name__ == "__main__":
    main()
