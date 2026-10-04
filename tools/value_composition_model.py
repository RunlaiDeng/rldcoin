"""Executable value-composition model, never a native ledger/verifier.

Ideal authenticated owner/finality/incident oracles are explicit preconditions.
The initial state is a compatible issued slice, not new issuance authorization.
Amounts use the real cap/u128 bounds. Small traces model a subset of supply;
untouched outside supply cancels from both sides of conservation. No transport,
custody rollback, crypto, full fork choice or liveness qualification is implied.
"""
from dataclasses import dataclass, replace

CAP = 10**35
U128 = 2**128 - 1
U64 = 2**64 - 1
REGIONS = ('earth', 'proxima', 'andromeda')
# Search limits only, never a signed native profile or a raised native bound.
MAX_NODES = 128
MAX_OUTPUTS = 512
MAX_DEPTH = 128
MAX_FANOUT = 16


class Refusal(ValueError):
    pass


class InvariantFailure(RuntimeError):
    """A model defect/altered history must never become a normal refusal."""


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def integer(value, maximum=CAP, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value <= maximum,
            'bounded canonical integer')
    return value


def total(values):
    result = 0
    for value in values:
        integer(value)
        result += value
        require(result <= U128 and result <= CAP, 'checked amount sum')
    return result


@dataclass(frozen=True)
class Asset:
    ident: tuple
    region: str
    owner: str
    amount: int
    lineage: tuple
    available_height: int


@dataclass(frozen=True)
class Node:
    region: str
    kind: str
    inputs: tuple
    outputs: tuple
    selected: bool = True
    references: tuple = ()


@dataclass(frozen=True)
class Export:
    asset: Asset
    destination: str
    recipient: str
    destination_fee: int
    certified: bool = False
    imported: bool = False
    orphaned: bool = False


@dataclass(frozen=True)
class Channel:
    ident: tuple
    asset: Asset
    parties: tuple
    sequence: int = 0
    split: tuple = ()
    phase: str = 'open'
    deadline: int | None = None


@dataclass(frozen=True)
class Reserve:
    channel: tuple
    asset: Asset


@dataclass(frozen=True)
class Incident:
    region: str
    left: str
    right: str


@dataclass(frozen=True)
class State:
    issued_slice: int
    nodes: tuple = ()
    coins: tuple = ()
    exports: tuple = ()
    channels: tuple = ()
    reserves: tuple = ()
    incidents: tuple = ()
    heights: tuple = (0, 0, 0)

    def height(self, region):
        require(region in REGIONS, 'region not admitted in model')
        return self.heights[REGIONS.index(region)]

    def asset(self, ident):
        n, i = ident
        require(type(n) is int and type(i) is int and 0 <= n < len(self.nodes)
                and 0 <= i < len(self.nodes[n].outputs), 'missing asset root')
        return self.nodes[n].outputs[i]

    def quarantined(self, asset):
        affected = {incident.region for incident in self.incidents}
        return asset.region in affected or any(self.nodes[n].region in affected
                                              for n in asset.lineage)

    def buckets(self):
        return (total(c.amount for c in self.coins),
                total([c.asset.amount for c in self.channels] +
                      [r.asset.amount for r in self.reserves]),
                total(x.asset.amount for x in self.exports
                      if not x.imported and not x.orphaned))

    def validate(self):
        try:
            return self._validate()
        except Refusal as error:
            raise InvariantFailure(str(error)) from error

    def _validate(self):
        integer(self.issued_slice)
        require(len(self.nodes) <= MAX_NODES, 'model object bound')
        records = {}
        consumed = set()
        depths = []
        selected_roots = []
        for n, node in enumerate(self.nodes):
            require(node.region in REGIONS and len(node.inputs)+len(node.references) <= MAX_FANOUT,
                    'model region/fanout bound')
            require(node.kind in ('issued-slice', 'pay', 'export', 'import', 'open-channel',
                                 'reserve-fee', 'challenge', 'settle'), 'unknown transition kind')
            require(len(node.inputs) == len(set(node.inputs)), 'duplicate input')
            parents = []
            for ident in node.inputs:
                require(ident in records and ident[0] < n, 'missing/self/forward ancestor')
                require(self.nodes[ident[0]].selected, 'orphaned ancestor')
                parents.append(records[ident])
                if node.selected:
                    require(ident not in consumed, 'duplicate consumption')
                    consumed.add(ident)
            value_parents = tuple(parents)
            require(len(node.references) == len(set(node.references)), 'duplicate dependency reference')
            for ident in node.references:
                require(ident in records and ident[0] < n and self.nodes[ident[0]].selected,
                        'missing/self/forward referenced ancestor')
                parents.append(records[ident])
            expected = tuple(sorted({n}.union(*(set(a.lineage) for a in parents))))
            depth = 1 + max((depths[a.ident[0]] for a in parents), default=0)
            require(depth <= MAX_DEPTH, 'model graph depth bound')
            depths.append(depth)
            for i, asset in enumerate(node.outputs):
                require(asset.ident == (n, i) and asset.region in REGIONS
                        and isinstance(asset.owner, str) and asset.owner,
                        'immutable output identity')
                integer(asset.amount, positive=True)
                integer(asset.available_height, U64)
                require(asset.lineage == expected, 'complete provenance union')
                records[asset.ident] = asset
            require(len(records) <= MAX_OUTPUTS, 'model recovery index bound')
            output_sum = total(a.amount for a in node.outputs)
            if node.kind == 'issued-slice':
                require(node.region == 'earth' and not node.inputs and not node.references,
                        'unrooted issuance slice')
                if node.selected:
                    selected_roots.append(output_sum)
            else:
                require(node.inputs and total(a.amount for a in value_parents) == output_sum,
                        'transition amount conservation')
        require(total(selected_roots) == self.issued_slice, 'issued slice changed')
        live = list(self.coins) + [c.asset for c in self.channels] + [r.asset for r in self.reserves]
        for export in self.exports:
            require(export.asset.ident in records and export.destination in REGIONS
                    and export.destination != export.asset.region,
                    'export identity/destination')
            integer(export.destination_fee)
            require(export.destination_fee < export.asset.amount, 'export net amount')
            require(not export.imported or export.certified and not export.orphaned,
                    'import without selected finalized debit')
            require(not export.orphaned or not export.certified and not export.imported,
                    'cannot orphan a finalized debit')
            if not export.imported and not export.orphaned:
                live.append(export.asset)
        require(len({a.ident for a in live}) == len(live), 'asset counted in multiple buckets')
        for asset in live:
            require(records.get(asset.ident) == asset and asset.ident not in consumed
                    and self.nodes[asset.ident[0]].selected, 'live asset not in selected history')
        expected_live = {ident for ident in records if self.nodes[ident[0]].selected and ident not in consumed}
        require({a.ident for a in live} == expected_live, 'lost or fabricated liability')
        channel_ids = {c.ident for c in self.channels}
        require(len(channel_ids) == len(self.channels), 'duplicate channel')
        for channel in self.channels:
            require(len(set(channel.parties)) == 2 and channel.asset.owner == 'escrow'
                    and len(channel.split) == 2 and total(channel.split) == channel.asset.amount,
                    'channel funding/state conservation')
            integer(channel.sequence, U64)
            require(channel.phase in ('open', 'closing'), 'unknown channel phase')
            require((channel.deadline is None) == (channel.phase == 'open'), 'channel deadline')
        require(all(r.channel in channel_ids for r in self.reserves), 'orphan fee reserve')
        require(total(self.buckets()) == self.issued_slice, 'I = U + E + T')
        return self


def _node(state, region, kind, inputs, specifications, references=()):
    state.validate()
    require(region in REGIONS and len(state.nodes) < MAX_NODES, 'model node bound')
    require(region not in {i.region for i in state.incidents}, 'local finality incident')
    require(len(inputs)+len(references) <= MAX_FANOUT and len({a.ident for a in inputs}) == len(inputs),
            'input fanout/duplicate')
    n = len(state.nodes)
    lineage = tuple(sorted({n}.union(*(set(a.lineage) for a in (*inputs, *references)))))
    outputs = tuple(Asset((n, i), destination, owner, integer(amount, positive=True),
                          lineage, integer(height, U64))
                    for i, (destination, owner, amount, height) in enumerate(specifications))
    require(total(a.amount for a in inputs) == total(a.amount for a in outputs),
            'inputs = outputs plus named allocations')
    node = Node(region, kind, tuple(a.ident for a in inputs), outputs,
                references=tuple(a.ident for a in references))
    return replace(state, nodes=state.nodes + (node,)), outputs


def issued_slice(amounts):
    """Trusted symbolic slice precondition; this never signs or mints native RLD."""
    require(len(amounts) <= MAX_NODES, 'model initial node bound')
    nodes, coins = [], []
    for amount in amounts:
        n = len(nodes)
        asset = Asset((n, 0), 'earth', 'alice', integer(amount, positive=True), (n,), 0)
        nodes.append(Node('earth', 'issued-slice', (), (asset,)))
        coins.append(asset)
    return State(total(amounts), nodes=tuple(nodes), coins=tuple(coins)).validate()


def advance(state, region, height):
    integer(height, U64)
    require(height >= state.height(region), 'height regression')
    heights = list(state.heights)
    heights[REGIONS.index(region)] = height
    return replace(state, heights=tuple(heights)).validate()


def _coins(state, region, ids, owners_authenticated):
    require(owners_authenticated and ids and len(set(ids)) == len(ids), 'owner authorization/inputs')
    result = tuple(next((c for c in state.coins if c.ident == ident), None) for ident in ids)
    require(all(c is not None and c.region == region for c in result), 'unspent local inputs')
    require(all(c.available_height <= state.height(region) and not state.quarantined(c)
                for c in result), 'immature/quarantined input')
    return result


def pay(state, region, ids, payouts, fee=0, miner='miner', owners_authenticated=True):
    inputs = _coins(state, region, ids, owners_authenticated)
    integer(fee)
    specs = [(region, owner, amount, state.height(region)) for owner, amount in payouts]
    if fee:
        specs.append((region, miner, fee, state.height(region)))
    next_state, outputs = _node(state, region, 'pay', inputs, specs)
    return replace(next_state, coins=tuple(c for c in state.coins if c.ident not in ids) + outputs).validate()


def export(state, region, ids, destination, recipient, gross, change=(), source_fee=0,
           destination_fee=0, owners_authenticated=True):
    require(destination in REGIONS and destination != region, 'exact admitted destination')
    integer(gross, positive=True)
    integer(source_fee)
    integer(destination_fee)
    require(destination_fee < gross, 'positive net credit')
    inputs = _coins(state, region, ids, owners_authenticated)
    specs = [(region, recipient, gross, state.height(region))]
    specs += [(region, owner, amount, state.height(region)) for owner, amount in change]
    if source_fee:
        specs.append((region, 'source-miner', source_fee, state.height(region)))
    next_state, outputs = _node(state, region, 'export', inputs, specs)
    record = Export(outputs[0], destination, recipient, destination_fee)
    return replace(next_state, coins=tuple(c for c in state.coins if c.ident not in ids) + outputs[1:],
                   exports=state.exports + (record,)).validate()


def certify(state, index, authenticated_finality=True):
    record = state.exports[index]
    require(authenticated_finality and not record.orphaned, 'selected authenticated source finality')
    return replace(state, exports=state.exports[:index] + (replace(record, certified=True),) +
                   state.exports[index+1:]).validate()


def orphan_unfinalized_export_tail(state, index, selected_tail_oracle=True):
    """One isolated last source transition, not general native fork recovery.

    Original immutable proof records remain. A finalized or consumed suffix
    refuses; a full source suffix rollback requires a separate model/refinement.
    """
    record = state.exports[index]
    n = record.asset.ident[0]
    node = state.nodes[n]
    require(selected_tail_oracle and not record.certified and not record.imported
            and not record.orphaned and node.selected, 'unfinalized selected tail required')
    require(not any(later.selected and (later.region == node.region or
                        any(ident[0] == n for ident in later.inputs + later.references))
                    for later in state.nodes[n+1:]), 'selected suffix must first be replayed')
    created = set(a.ident for a in node.outputs)
    require(created - {record.asset.ident} <= {c.ident for c in state.coins},
            'tail change/fees no longer unspent')
    restored = tuple(state.asset(ident) for ident in node.inputs)
    return replace(state, nodes=state.nodes[:n] + (replace(node, selected=False),) + state.nodes[n+1:],
                   coins=tuple(c for c in state.coins if c.ident not in created) + restored,
                   exports=state.exports[:index] + (replace(record, orphaned=True),) +
                   state.exports[index+1:]).validate()


def import_value(state, index, destination, maturity=1, authentic_complete_closure=True):
    record = state.exports[index]
    require(authentic_complete_closure and destination == record.destination
            and record.certified and not record.orphaned, 'complete finality/destination closure')
    # Exact repeated delivery is an idempotent observation, never another credit.
    if record.imported:
        return state.validate()
    require(not state.quarantined(record.asset), 'quarantined pending import')
    height = state.height(destination) + integer(maturity, U64)
    integer(height, U64)
    specs = [(destination, record.recipient, record.asset.amount - record.destination_fee, height)]
    if record.destination_fee:
        specs.append((destination, 'destination-miner', record.destination_fee, height))
    next_state, outputs = _node(state, destination, 'import', (record.asset,), specs)
    return replace(next_state, coins=state.coins + outputs,
                   exports=state.exports[:index] + (replace(record, imported=True),) + state.exports[index+1:]).validate()


def open_channel(state, region, ids, parties, capacity, change=(), fee=0, owners_authenticated=True):
    require(len(parties) == 2 and len(set(parties)) == 2, 'exact two distinct parties')
    integer(capacity, positive=True)
    integer(fee)
    inputs = _coins(state, region, ids, owners_authenticated)
    specs = [(region, 'escrow', capacity, state.height(region))]
    specs += [(region, owner, amount, state.height(region)) for owner, amount in change]
    if fee:
        specs.append((region, 'channel-miner', fee, state.height(region)))
    next_state, outputs = _node(state, region, 'open-channel', inputs, specs)
    channel = Channel(outputs[0].ident, outputs[0], tuple(parties), split=(capacity, 0))
    return replace(next_state, coins=tuple(c for c in state.coins if c.ident not in ids) + outputs[1:],
                   channels=state.channels + (channel,)).validate()


def reserve_fee(state, channel_id, coin_id, owner_authenticated=True):
    channel = _channel(state, channel_id)
    require(channel.phase == 'open' and not state.quarantined(channel.asset), 'open clean escrow')
    coin, = _coins(state, channel.asset.region, (coin_id,), owner_authenticated)
    require(coin.owner in channel.parties, 'fee reserve actual owner')
    # Carry the exact escrow unchanged through this atomic allocation. Both
    # resulting objects inherit the complete union; a disputed fee lineage
    # cannot protect an otherwise clean escrow from the baseline mixing rule.
    next_state, outputs = _node(state, channel.asset.region, 'reserve-fee', (channel.asset, coin),
                               [(channel.asset.region, 'escrow', channel.asset.amount,
                                 channel.asset.available_height),
                                (coin.region, coin.owner, coin.amount, coin.available_height)])
    updated = replace(channel, asset=outputs[0])
    return replace(next_state, coins=tuple(c for c in state.coins if c.ident != coin_id),
                   channels=tuple(updated if c.ident == channel_id else c for c in state.channels),
                   reserves=state.reserves + (Reserve(channel_id, outputs[1]),)).validate()


def _channel(state, ident):
    channel = next((c for c in state.channels if c.ident == ident), None)
    require(channel is not None and not state.quarantined(channel.asset), 'available channel')
    require(all(not state.quarantined(r.asset) for r in state.reserves if r.channel == ident),
            'quarantined reserve')
    return channel


def _signed_state(channel, sequence, split, both_parties_authenticated):
    integer(sequence, U64)
    require(both_parties_authenticated and len(split) == 2
            and total(split) == channel.asset.amount, 'exact authenticated channel state')


def review_channel_payment(state, ident, sequence, split, both_parties_authenticated=True):
    """A model acceptance predicate, never signing or a ledger mutation."""
    channel = _channel(state, ident)
    require(channel.phase == 'open', 'payment requires open channel')
    _signed_state(channel, sequence, split, both_parties_authenticated)
    require(sequence > channel.sequence and any(r.channel == ident for r in state.reserves),
            'new state and mandatory retained challenge reserve')
    return state.validate()


def close(state, ident, sequence, split, window=2016, both_parties_authenticated=True):
    channel = _channel(state, ident)
    require(channel.phase == 'open', 'already closing')
    _signed_state(channel, sequence, split, both_parties_authenticated)
    deadline = state.height(channel.asset.region) + integer(window, U64, positive=True)
    integer(deadline, U64)
    updated = replace(channel, phase='closing', sequence=sequence, split=tuple(split), deadline=deadline)
    return replace(state, channels=tuple(updated if c.ident == ident else c for c in state.channels)).validate()


def challenge(state, ident, sequence, split, reserve_id, fee,
              both_parties_authenticated=True, fee_owner_authenticated=True):
    channel = _channel(state, ident)
    require(channel.phase == 'closing' and state.height(channel.asset.region) <= channel.deadline,
            'challenge deadline')
    _signed_state(channel, sequence, split, both_parties_authenticated)
    require(sequence > channel.sequence, 'strictly higher channel state')
    reserve = next((r for r in state.reserves if r.channel == ident and r.asset.ident == reserve_id), None)
    require(reserve is not None and fee_owner_authenticated, 'exact retained fee reserve owner')
    integer(fee, positive=True)
    require(fee <= reserve.asset.amount, 'funded challenge fee')
    region = channel.asset.region
    specs = [(region, 'escrow', channel.asset.amount, state.height(region)),
             (region, 'challenge-miner', fee, state.height(region))]
    if fee < reserve.asset.amount:
        specs.append((region, reserve.asset.owner, reserve.asset.amount-fee, state.height(region)))
    next_state, outputs = _node(state, region, 'challenge', (channel.asset, reserve.asset), specs)
    updated = replace(channel, asset=outputs[0], sequence=sequence, split=tuple(split))
    return replace(next_state, channels=tuple(updated if c.ident == ident else c for c in state.channels),
                   reserves=tuple(r for r in state.reserves if r != reserve), coins=state.coins + outputs[1:]).validate()


def settle(state, ident):
    channel = _channel(state, ident)
    require(channel.phase == 'closing' and state.height(channel.asset.region) > channel.deadline,
            'settlement strictly after deadline')
    reserves = tuple(r for r in state.reserves if r.channel == ident)
    inputs = (channel.asset,) + tuple(r.asset for r in reserves)
    region = channel.asset.region
    specs = [(region, owner, amount, state.height(region))
             for owner, amount in zip(channel.parties, channel.split) if amount]
    specs += [(region, r.asset.owner, r.asset.amount, state.height(region)) for r in reserves]
    next_state, outputs = _node(state, region, 'settle', inputs, specs)
    return replace(next_state, channels=tuple(c for c in state.channels if c.ident != ident),
                   reserves=tuple(r for r in state.reserves if r.channel != ident),
                   coins=state.coins + outputs).validate()


def notify_incident(state, region, left, right, pair_authenticated=True):
    require(pair_authenticated and region in REGIONS and isinstance(left, str)
            and isinstance(right, str) and left and right and left != right,
            'authentic contradictory certificate pair')
    pair = sorted((left, right))
    incident = Incident(region, *pair)
    if incident in state.incidents:
        return state.validate()
    return replace(state, incidents=state.incidents + (incident,)).validate()


def exposure(state):
    """Unavailable value stays in its original mutually exclusive bucket."""
    state.validate()
    return {'U': total(c.amount for c in state.coins if state.quarantined(c)),
            'E': total([c.asset.amount for c in state.channels if state.quarantined(c.asset)] +
                       [r.asset.amount for r in state.reserves if state.quarantined(r.asset)]),
            'T': total(e.asset.amount for e in state.exports
                       if not e.imported and not e.orphaned and state.quarantined(e.asset))}
