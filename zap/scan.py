"""Scan completed snapshots offline; queue only successfully sanitized events."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def scan_once(private=Path("/zap/wrk"), events=Path("/events")):
    ready = private / "ready"
    # Backpressure preserves queued events during publisher outages.
    if not ready.exists() or len(list(events.glob("*.json"))) >= 100:
        return
    try:
        (private / "report.json").unlink(missing_ok=True)
        (private / "event.json").unlink(missing_ok=True)
        # ZAP output can contain raw URLs/evidence; keep logs local too.
        with (private / "scan.log").open("w") as log, tempfile.TemporaryDirectory(dir=private) as home:
            subprocess.run(
                ["zap.sh", "-cmd", "-silent", "-dir", home,
                 "-autorun", "/zap/plan.yaml"],
                check=True, stdout=log, stderr=log, timeout=900,
            )
            subprocess.run(["sh", "/pipeline/export.sh"], check=True,
                           stdout=log, stderr=log, timeout=30)
        payload = (private / "event.json").read_bytes()
        event_id = json.loads(payload)["event_id"]
        if len(event_id) != 64 or any(c not in "0123456789abcdef" for c in event_id):
            raise ValueError("invalid event ID")
        temporary = events / ".event.tmp"
        temporary.write_bytes(payload)
        temporary.replace(events / f"{event_id}.json")
        print("Sanitized scan queued", flush=True)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Scan/conversion failed; nothing queued. See local scan.log", flush=True)
    finally:
        ready.unlink(missing_ok=True)


if __name__ == "__main__":
    os.umask(0o077)
    while True:
        scan_once()
        time.sleep(5)