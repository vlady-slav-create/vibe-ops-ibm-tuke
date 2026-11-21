"""Bounded rolling HAR snapshots; never overwrite a snapshot being scanned."""
import asyncio
from collections import deque
import logging
import os
from pathlib import Path

from mitmproxy import ctx


class Snapshots:
    def __init__(self):
        self.interval = int(os.environ.get("SCAN_INTERVAL", "60"))
        limit = int(os.environ.get("CAPTURE_MAX_FLOWS", "1000"))
        if self.interval < 1 or limit < 1:
            raise ValueError("SCAN_INTERVAL and CAPTURE_MAX_FLOWS must be positive")
        # ponytail: flow count bounds demo history, not bytes; add byte limits for large bodies.
        self.flows = deque(maxlen=limit)
        self.dirty = False
        self.directory = Path("/capture")

    def response(self, flow):
        self.flows.append(flow.copy())
        self.dirty = True

    def snapshot(self):
        ready = self.directory / "ready"
        if not self.dirty or ready.exists():
            return
        temporary = self.directory / ".traffic.har"
        try:
            ctx.master.commands.call("save.har", list(self.flows), str(temporary))
            temporary.chmod(0o600)
            temporary.replace(self.directory / "traffic.har")
            ready.touch(mode=0o600)
            self.dirty = False
        except Exception:
            temporary.unlink(missing_ok=True)
            logging.error("HAR snapshot failed; will retry")

    async def run(self):
        while True:
            await asyncio.sleep(self.interval)
            self.snapshot()

    def running(self):
        self.task = asyncio.create_task(self.run())

    def done(self):
        self.task.cancel()


addons = [Snapshots()]