"""Bounded local submission boundary observations; never Native authority.

Input-read digests identify unchecked bytes. Only ordinary Runtime.retain performs
complete Native authentication and durable retention. No ledger, key, input or
head is kept by this module, and diagnostics cannot suppress ordinary work.
"""
import interstellar_mesh as mesh
import interstellar_transfer as wire


def event(runtime, stage, envelope=None, **fields):
    trace = getattr(runtime, 'contact_trace', None)
    if trace is None: return
    try:
        if envelope is not None: fields['envelope_id'] = mesh.digest(envelope)
        trace.event(stage, **fields)
    except Exception:
        try: trace.reject()
        except Exception: pass


def read_submissions(runtime):
    # Exact original spool bounds, file validation, typed read, body dedup and
    # complete native retain order. This extraction changes no admission rule.
    from regional_bft_node import private
    event(runtime, 'submission_scan_started')
    queue = runtime.native.ledger / 'bft-submissions'
    fresh = count = 0
    if queue.exists():
        private(queue, True)
        files = sorted(queue.iterdir())
        mesh.require(len(files) <= 32, 'BFT submission spool capacity')
        count = len(files)
        for path in files[:32]:
            envelope = wire.decode_json(wire.read_file(private(path), wire.MAX_PAYLOAD))
            event(runtime, 'submission_input_read', envelope)
            if mesh.digest(envelope['body']) not in runtime.state['messages']:
                event(runtime, 'submission_auth_started', envelope)
                try: runtime.retain(envelope, local=True)
                except BaseException:
                    event(runtime, 'submission_retention_failed', envelope)
                    raise
                fresh += 1
                event(runtime, 'submission_retained', envelope)
            else:
                event(runtime, 'submission_duplicate_seen', envelope)
    event(runtime, 'submission_scan_finished', selected=count, offered=fresh)
    return fresh
