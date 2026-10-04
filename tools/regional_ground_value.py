"""Derive a bounded value observation from the controller's normal Native reads.

The callback must run the exact pinned Native CLI, with complete normal replay.
No serialized observation, Python ledger or digest is an authorization input.
This module signs/installs nothing and retains no ledger between calls.
"""
import hashlib
import time

from regional_ground_resources import HEX, canonical, require

NAMES = ('earth', 'proxima', 'andromeda')


def amount(value):
    require(type(value) is str and value.isascii() and value.isdigit()
            and len(value) <= 39 and (value == '0' or not value.startswith('0')),
            'canonical bounded Native amount required')
    return int(value)


def audit_certified_prefixes(read, regions, currency):
    """Use the same 12 status + 3 proof calls as the finite fault audit.

    'read' is the executing controller's Native callback, never a JSON loader.
    Each response still requires complete Native authentication/replay. A
    changed or incompatible observation refuses, rather than inventing zero.
    This is the highest *observed* certified prefix, not global current state.
    """
    require(set(regions) == set(NAMES) and HEX.fullmatch(currency) is not None
            and len(set(regions.values())) == 3
            and all(HEX.fullmatch(value) is not None for value in regions.values()),
            'exact three-region Native binding required')
    transcript, heights, selected, ledgers = [], {}, [], []
    started = time.monotonic()

    def call(name, replica, command):
        before = time.monotonic()
        value = read(name, replica, command)
        raw = canonical(value)
        require(len(raw) <= 8 * 1024 * 1024, 'Native observation response exceeds bound')
        transcript.append(dict(region=name, replica=replica, command=command,
                               response_sha256=hashlib.sha256(raw).hexdigest(),
                               response_bytes=len(raw), monotonic_start=before,
                               monotonic_end=time.monotonic()))
        return value

    for name in NAMES:
        summaries, highest, index = [], None, None
        for replica in range(4):
            state = call(name, replica, 'status')
            require(state['fixture_only'] is True and state['live_rld'] is False
                    and state['currency'] == currency and state['region'] == regions[name]
                    and type(state['height']) is int and 0 <= state['height'] <= 24
                    and HEX.fullmatch(state['tip']) is not None
                    and HEX.fullmatch(state['state']) is not None,
                    'Native observation domain or height differs')
            summaries.append(dict(height=state['height'], tip=state['tip'], state=state['state']))
            if highest is None or state['height'] > highest['height']:
                highest, index = state, replica
        heights[name] = [state['height'] for state in summaries]
        proof = call(name, index, 'proof')
        snapshots = [s for s in proof['snapshots'] if s['statement']['currency'] == currency
                     and s['statement']['region'] == regions[name]
                     and s['statement']['height'] == highest['height']
                     and s['statement']['block'] == highest['tip']
                     and s['statement']['state'] == highest['state']]
        require(snapshots, 'highest observed Native prefix lacks exact complete certified checkpoint')
        blocks = snapshots[0]['blocks']
        require(snapshots[0].get('base') is None and len(blocks) == highest['height'],
                'finite BFT observation requires complete genesis-derived prefix')
        for state in summaries:
            tip = highest['tip'] if state['height'] == highest['height'] else blocks[state['height']]['header']['parent']
            require(state['tip'] == tip and (state['height'] != highest['height']
                    or state['state'] == highest['state']),
                    'Native replica observation is not a compatible certified prefix')
        selected.append(dict(region=name, replica=index, height=highest['height'],
                             tip=highest['tip'], state=highest['state']))
        ledgers.append(highest['ledger'])

    exports, imports = {}, {}
    issued = liquid = received = 0
    for name, ledger in zip(NAMES, ledgers):
        require(all(type(ledger[key]) is dict and len(ledger[key]) <= 4096
                    for key in ('coins', 'exports', 'imports')), 'bounded Native indexes required')
        issued += amount(ledger['minted'])
        received += amount(ledger['received'])
        liquid += sum(amount(coin['payment']['amount']) for coin in ledger['coins'].values())
        for ident, record in ledger['exports'].items():
            require(HEX.fullmatch(ident) is not None and record['id'] == ident and ident not in exports
                    and record['source'] == regions[name] and record['destination'] in regions.values(),
                    'duplicate or mismatched Native export observation')
            require(amount(record['recipient']['amount']) >= amount(record['destination_fee']),
                    'Native export fee exceeds gross amount')
            exports[ident] = record
        for ident in ledger['imports']:
            require(HEX.fullmatch(ident) is not None and ident not in imports,
                    'duplicate Native import observation')
            imports[ident] = regions[name]
    require(imports.keys() <= exports.keys() and all(exports[ident]['destination'] == destination
            for ident, destination in imports.items()), 'Native import lacks observed exact destination export')
    require(received == sum(amount(exports[ident]['recipient']['amount']) for ident in imports),
            'Native received counters differ from observed permanent imports')
    pending = {ident:record for ident, record in exports.items() if ident not in imports}
    gross = sum(amount(record['recipient']['amount']) for record in pending.values())
    net = sum(amount(record['recipient']['amount']) - amount(record['destination_fee']) for record in pending.values())
    require(issued == liquid + gross, 'highest observed certified prefix conservation failed')
    return dict(issued=str(issued), liquid=str(liquid), pending_exports=str(gross),
                pending_export_net_amount=str(net), observed_export_count=len(exports),
                observed_import_count=len(imports), unresolved_export_count=len(pending),
                conserved=True, compatible_prefixes_verified=True, replica_heights=heights,
                selected_native_checkpoints=selected, native_read_transcript=transcript,
                native_read_transcript_sha256=hashlib.sha256(canonical(transcript)).hexdigest(),
                native_observation_seconds=time.monotonic()-started,
                scope='highest observed certified prefix per region; not all-replica agreement',
                custody_or_signing_authority=False, independent_freshness_qualified=False,
                request_queue_or_oldest_wait_measured=False)
