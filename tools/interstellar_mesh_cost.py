"""Fixed process-local mesh lease costs; never custody or ledger authority."""
import math
import threading

ROLES = ('receive', 'carriage', 'tcp-outbound', 'tcp-input', 'tcp-handler')
STAGES = ('purpose', 'acquire', 'open', 'hold')
MAX_COUNT = 2 ** 63 - 1
MAX_SECONDS = 1e12
MAX_BYTES = 8192


class MeshCosts:
    def __init__(self):
        self.guard = threading.Lock()
        self.rows = {(role, stage): dict(calls=0, failures=0, total_seconds=0.0,
                    max_seconds=0.0, last_seconds=0.0, saturated=False)
                     for role in ROLES for stage in STAGES}

    def record(self, role, stage, duration, succeeded):
        if (type(role) is not str or type(stage) is not str
                or (role, stage) not in self.rows or type(duration) not in (int, float)
                or not math.isfinite(duration) or type(succeeded) is not bool):
            return
        duration = max(0.0, duration)
        with self.guard:
            row = self.rows[role, stage]
            row['saturated'] |= (row['calls'] == MAX_COUNT
                                or row['total_seconds'] + duration > MAX_SECONDS)
            row['calls'] = min(MAX_COUNT, row['calls'] + 1)
            row['failures'] = min(MAX_COUNT, row['failures'] + int(not succeeded))
            row['total_seconds'] = min(MAX_SECONDS, row['total_seconds'] + duration)
            row['max_seconds'] = min(MAX_SECONDS, max(row['max_seconds'], duration))
            row['last_seconds'] = min(MAX_SECONDS, duration)

    def snapshot(self):
        with self.guard:
            rows = {role: {stage: {key: round(value, 6) if type(value) is float else value
                                  for key, value in self.rows[role, stage].items()}
                           for stage in STAGES} for role in ROLES}
        return dict(format='RLD-MESH-LEASE-COST-V1', process_local_only=True,
                    timing_is_authority=False, duration_is_wall_not_cpu=True,
                    node_open_includes_validation=True, hold_includes_open_and_close=True,
                    hold_success_is_close_only=True, acquisition_includes_open=True, rows=rows)
