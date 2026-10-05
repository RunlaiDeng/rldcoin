#!/usr/bin/env python3
"""Bounded executable specification, NOT a ledger or cryptographic verifier.

One indivisible fixture asset, three regions, two owners, up to three exports.
Finality is an ideal, non-equivocating oracle; authorization is pre-established.
No transport timing or real-world liveness is proved. Never accepts live funds.
"""
import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path

REGIONS = ('earth', 'proxima', 'andromeda')
OWNERS = ('alice', 'bob')


@dataclass(frozen=True)
class Coin:
    region: str
    owner: str
    lineage: tuple = ()
    mature: bool = True
    final: bool = True


@dataclass(frozen=True)
class Export:
    source: str
    destination: str
    owner: str
    recipient: str
    lineage: tuple
    certified: bool = False
    imported: bool = False


@dataclass(frozen=True)
class State:
    coins: tuple = (Coin('earth', 'alice'),)
    exports: tuple = ()


def update_export(state, index, **fields):
    records = list(state.exports)
    records[index] = replace(records[index], **fields)
    return replace(state, exports=tuple(records))


def deliver(state, index, destination, authorized=True):
    record = state.exports[index]
    if not authorized or destination != record.destination or not record.certified or record.imported:
        return state
    state = update_export(state, index, imported=True)
    coin = Coin(destination, record.recipient, record.lineage + (index,), False, False)
    return replace(state, coins=state.coins + (coin,))


def invariant(state):
    pending = sum(not r.imported for r in state.exports)
    if len(state.coins) + pending != 1:
        raise ValueError('CONSERVATION: liquid + locked/in-transit != issued fixture unit')
    for index, record in enumerate(state.exports):
        if record.imported and not record.certified:
            raise ValueError('import without final source debit')
        region = 'earth'
        for ancestor in record.lineage:
            if not 0 <= ancestor < index:
                raise ValueError('non-causal lineage')
            parent = state.exports[ancestor]
            if parent.source != region or not parent.imported or not parent.certified:
                raise ValueError('unauthenticated asset ancestry')
            region = parent.destination
        if region != record.source or record.source == record.destination:
            raise ValueError('wrong exporting region')
    for coin in state.coins:
        if coin.lineage:
            record = state.exports[coin.lineage[-1]]
            if not record.imported or record.destination != coin.region:
                raise ValueError('coin not authenticated by an import')
        elif coin.region != 'earth':
            raise ValueError('unauthorized native issuance')
        if coin.final and not coin.mature:
            raise ValueError('immature coin marked spendably final')


def successors(state, max_exports):
    for i, coin in enumerate(state.coins):
        def coin_state(new_coin):
            return replace(state, coins=state.coins[:i] + (new_coin,) + state.coins[i+1:])
        if not coin.mature:
            yield f'mature:{coin.region}', coin_state(replace(coin, mature=True))
        if coin.mature and not coin.final:
            yield f'local-finality:{coin.region}', coin_state(replace(coin, final=True))
        if coin.mature:
            owner = OWNERS[1 - OWNERS.index(coin.owner)]
            yield f'pay:{coin.region}:{coin.owner}->{owner}', coin_state(replace(coin, owner=owner, final=False))
        if coin.mature and coin.final and len(state.exports) < max_exports:
            for destination in REGIONS:
                if destination == coin.region:
                    continue
                for recipient in OWNERS:
                    record = Export(coin.region, destination, coin.owner, recipient, coin.lineage)
                    yield f'export:{coin.region}->{destination}:{recipient}', State(state.coins[:i] + state.coins[i+1:], state.exports + (record,))
    for i, record in enumerate(state.exports):
        if not record.certified:
            yield f'certify-debit:{i}', update_export(state, i, certified=True)
        if record.certified and not record.imported:
            yield f'deliver:{i}:{record.destination}', deliver(state, i, record.destination)


def trace_to(parents, state):
    trace = []
    while parents[state] is not None:
        state, action = parents[state]
        trace.append(action)
    return list(reversed(trace))


def check(max_exports=3):
    if max_exports not in (1, 2, 3):
        raise ValueError('bounded model admits only one to three exports')
    initial = State()
    parents = {initial: None}
    queue = deque([initial])
    transitions = 0
    round_trip = None
    local_payment = None
    timeout_counterexample = None
    replay_checks = 0
    while queue:
        state = queue.popleft()
        invariant(state)
        for i, record in enumerate(state.exports):
            # Loss, silence, duplicate delivery, wrong destination and a
            # self-declared unauthorized region cannot authorize an import.
            wrong = next(r for r in REGIONS if r != record.destination)
            assert deliver(state, i, wrong) == state
            assert deliver(state, i, record.destination, authorized=False) == state
            if record.imported or not record.certified:
                assert deliver(state, i, record.destination) == state
            replay_checks += 1
            if timeout_counterexample is None and record.certified and not record.imported:
                # Deliberately broken refund: a lost acknowledgement is
                # indistinguishable from late delivery or accepted payment.
                broken = replace(state, coins=state.coins + (Coin(record.source, record.owner, record.lineage),))
                try:
                    invariant(broken)
                except ValueError:
                    double = deliver(broken, i, record.destination)
                    timeout_counterexample = trace_to(parents, state) + ['unsafe-timeout-refund', f'late-delivery:{i}']
                    assert len(double.coins) == 2
        if len(state.exports) == 3:
            path = [(e.source, e.destination) for e in state.exports]
            if path == [('earth', 'proxima'), ('proxima', 'andromeda'), ('andromeda', 'earth')] and all(e.imported for e in state.exports) and state.coins[0].mature and state.coins[0].final:
                round_trip = round_trip or trace_to(parents, state)
        for action, following in successors(state, max_exports):
            transitions += 1
            invariant(following)
            if action.startswith('pay:proxima') and local_payment is None:
                local_payment = trace_to(parents, state) + [action]
            if following not in parents:
                parents[following] = (state, action)
                queue.append(following)
    if max_exports == 3 and round_trip is None:
        raise ValueError('three-region return path was not reachable')
    if timeout_counterexample is None or local_payment is None:
        raise ValueError('missing counterexample or autonomous local payment')
    return {
        'format': 'RLD-INTERSTELLAR-VALUE-MODEL-V1', 'result': 'PASS_BOUNDED_ABSTRACT_MODEL',
        'regions': REGIONS, 'owners': OWNERS, 'fixture_units': 1, 'max_exports': max_exports,
        'exhaustive_reachable_states': len(parents), 'transitions': transitions,
        'wrong_region_unauthorized_duplicate_or_unfinalized_checks': replay_checks,
        'three_region_return_trace': round_trip, 'remote_local_payment_trace': local_payment,
        'unsafe_timeout_refund_counterexample': timeout_counterexample,
        'time_and_transport_receipt_have_no_value_transition': True,
        'assumptions': ['ideal non-equivocating local finality', 'preauthorized compatible regions', 'authenticated owner operations', 'one indivisible asset with no fees, splits, native rewards or ledger forks'],
        'proof_scope': 'all reachable states of this finite symbolic state machine; no Rust refinement proof',
        'implemented_in_native_ledger': False, 'cryptography_or_transport_exercised': False,
        'physical_interstellar_route_verified': False, 'mainnet_authorized': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-exports', type=int, default=3)
    args = parser.parse_args()
    report = check(args.max_exports)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
