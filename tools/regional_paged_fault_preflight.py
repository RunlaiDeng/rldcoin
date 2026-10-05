"""Fixed-head Native inspection after reviewed scope; never open signing custody."""
from dataclasses import dataclass
import math
from pathlib import Path
import subprocess
import tempfile
import time

from regional_bft_pinned_cold import checked_history
from regional_fixture_native_json import decode_native_json
from regional_paged_fault_scope import document, inventory, require, review_scope, safe


class HistoryOnly:
    def __init__(self, project, binary, ledger, authority, currency, head, deadline):
        self.project, self.binary, self.ledger = map(safe, (project, binary, ledger))
        self.authority, self.currency, self.head = authority, currency, head
        self.deadline = deadline

    def call(self, *args):
        require(args == ('history-check', '--expected-head', self.head),
                'preflight only permits exact pinned history inspection')
        require(type(self.deadline) in (int, float) and math.isfinite(self.deadline),
                'finite preflight deadline required')
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'preflight deadline exhausted')
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run([str(self.binary), '--dir', str(self.ledger),
                '--authority', self.authority, '--currency', self.currency, *args],
                cwd=self.project, stdout=output, stderr=errors, input=None,
                timeout=min(30, remaining), check=False)
            require(output.tell() <= 8 * 1024 * 1024 and errors.tell() <= 64 * 1024,
                    'preflight Native response capacity')
            errors.seek(0)
            require(result.returncode == 0, 'preflight Native refusal: '
                    + errors.read(2048).decode('utf-8', errors='replace').strip())
            output.seek(0)
            return decode_native_json(output.read(8 * 1024 * 1024 + 1))


@dataclass(frozen=True)
class Inspection:
    scope: object
    native_history_checks: int
    prior_custody_evidence_reused: bool = True
    signer_custody_opened: bool = False
    signing_authority: bool = False
    independent_freshness: bool = False


def inspect_scope(project, root, checks, stage, retained, binary, core, pins, deadline):
    """Complete Native pinned genesis replay; immutable prior custody stays closed.

    Reuse the exact original report's custody/envelope/owner checks only while its
    full protected source and retained byte inventory agree. No status, signer or
    wallet command can reconcile or recover custody here. Any later failure returns
    no partial inspection. A future network scope needs its own startup protocol.
    """
    scope = review_scope(project, root, checks, stage, retained, binary, core, pins)
    root = safe(root)
    authority = document(root / 'signed-fresh-bootstrap.json')['currency']['authority']
    for p in pins.replicas:
        native = HistoryOnly(project, binary, root / p.region / f'native-{p.index}',
                             authority, pins.currency, p.history_head, deadline)
        current = checked_history(native, p.history_head)
        require(current['height'] == p.height and current['region'] == p.region_id,
                'preflight Native height/region differs from reviewed scope')
    require(time.monotonic() < deadline, 'preflight deadline exhausted')
    require(inventory(root) == document(retained, pins.inventory)[str(root)],
            'Native preflight changed retained source')
    return Inspection(scope, 12)
