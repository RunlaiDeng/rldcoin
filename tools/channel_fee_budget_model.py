"""Independent finite fee-authorization model; never native ledger authority.

Ideal complete state/owner/finality authentication is an explicit premise.
The new policy requires a NEW owner authorization, never legacy reinterpretation.
Conservation includes locked unused budget and exact fee beneficiaries. A funded
budget cannot defeat censorship, missing quorum, data loss or last-block latency.
"""
from dataclasses import dataclass, replace
from collections import deque

CAP = 10**35
U64 = 2**64 - 1
WINDOW = 2016
COMMANDS = 16  # native MAX_COMMANDS, NOT the four companion proposal slots
POLICY = 'RLD-CHANNEL-RETAINED-FEE-BUDGET-MODEL-V1'
LEGACY = 'one-use'


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def amount(value, positive=False):
    require(type(value) is int and int(positive) <= value <= CAP, 'canonical amount')
    return value


def coverage(fee_limit, window=WINDOW, commands=COMMANDS):
    amount(fee_limit, True)
    require(type(window) is int and 0 < window <= U64 and
            type(commands) is int and 0 < commands <= COMMANDS, 'window/slots')
    return amount(fee_limit * window * commands, True)


@dataclass(frozen=True)
class Budget:
    root: str
    channel: str
    owner: str
    policy: str
    original: int
    ceiling: int
    fee_limit: int
    spent: int = 0
    generation: int = 0
    mature: bool = True  # ideal native maturity oracle, not a signed boolean

    def audit(self):
        for value in (self.original, self.ceiling, self.fee_limit, self.spent):
            amount(value)
        require(0 < self.fee_limit <= self.ceiling <= self.original and
                self.spent <= self.ceiling and 0 <= self.generation <= U64,
                'fee ceiling or original conservation')
        require(self.policy in (POLICY, LEGACY), 'unknown authorization')
        require(bool(self.root) and bool(self.owner) and bool(self.channel), 'purpose')
        return self

    @property
    def locked(self):
        self.audit()
        return self.original - self.spent

    @property
    def remaining_authorization(self):
        self.audit()
        return self.ceiling - self.spent

    def receive(self, fee, window=WINDOW, commands=COMMANDS):
        self.audit()
        amount(fee, True)
        require(self.mature and fee <= self.fee_limit, 'maturity/fee cap')
        require(self.policy == POLICY, 'legacy cannot authorize retained budget')
        required = coverage(self.fee_limit, window, commands)
        require(self.locked >= required and self.remaining_authorization >= required,
                'worst-window fee coverage absent')
        return self  # an off-chain receipt neither spends nor creates money

    def challenge(self, channel, generation, fee):
        self.audit()
        amount(fee, True)
        require(channel == self.channel and generation == self.generation and self.mature,
                'channel/current predecessor/maturity')
        require(fee <= self.fee_limit and fee <= self.remaining_authorization,
                'exact per-fee and cumulative owner ceiling')
        require(self.policy == POLICY, 'legacy one-use is not successor authority')
        return replace(self, spent=self.spent + fee, generation=self.generation + 1).audit()


@dataclass(frozen=True)
class Dispute:
    budget: Budget
    capacity: int = 60
    state: int = 0
    close: int = 10
    window: int = WINDOW
    commands: int = COMMANDS
    height: int = 10
    used: int = 0
    paid: int = 0
    returned: int = 0
    quarantined: bool = False
    settled: bool = False

    @property
    def deadline(self):
        require(self.close <= U64 - self.window, 'checked absolute deadline')
        return self.close + self.window

    def audit(self):
        self.budget.audit()
        amount(self.capacity, True)
        require(self.capacity + self.budget.original <= CAP, 'total issued slice')
        require(self.paid == self.budget.spent and 0 <= self.used <= self.commands,
                'fees or block work')
        # Before settlement unused budget and capacity stay in E, fees in U.
        locked = 0 if self.settled else self.capacity + self.budget.locked
        require(locked + self.paid + self.returned == self.capacity + self.budget.original,
                'U/E mutually exclusive conservation')
        return self

    def challenge(self, sequence, fee, height, generation=None):
        self.audit()
        require(not self.settled and not self.quarantined, 'settled/quarantined')
        require(type(sequence) is int and self.state < sequence <= U64, 'higher state')
        require(type(height) is int and max(self.height, self.close + 1) <= height <= self.deadline,
                'absolute challenge successors')
        used = self.used if height == self.height else 0
        require(used < self.commands, 'ordered native block slot bound')
        current = self.budget.generation if generation is None else generation
        budget = self.budget.challenge(self.budget.channel, current, fee)
        return replace(self, budget=budget, state=sequence, height=height,
                       used=used + 1, paid=self.paid + fee).audit()

    def settle(self, height):
        self.audit()
        require(not self.settled and not self.quarantined and height > self.deadline,
                'settlement strictly after absolute deadline')
        return replace(self, settled=True, height=height,
                       returned=self.capacity + self.budget.locked).audit()


def exhaustive(window=2, commands=3, fee_limit=3):
    """Enumerate every distinct bounded prefix, including same-block attacks.

    Deduplication compares complete immutable model states; no native evidence is
    cached or authorized. Increasing state numbers are abstracted to 1 per step:
    their exact numeric gaps cannot change fee consumption, window or work limits.
    """
    ceiling = coverage(fee_limit, window, commands)
    original = ceiling + 2  # retain non-authorized excess and return it only at settle
    initial = Dispute(Budget('root', 'channel', 'owner', POLICY,
                            original, ceiling, fee_limit), window=window, commands=commands).audit()
    initial.budget.receive(fee_limit, window, commands)
    queue = deque([initial])
    seen = {initial}
    edges = 0
    while queue:
        current = queue.popleft()
        consumed_slots = (current.height - current.close - 1) * commands + current.used
        if current.height == current.close:
            consumed_slots = 0
        # For an eligible remaining slot, sufficient fee persists even after
        # every earlier slot spends the maximum allowed fee on stale states.
        remaining_slots = window * commands - max(0, consumed_slots)
        require(current.budget.remaining_authorization >= remaining_slots * fee_limit,
                'coverage lower bound lost')
        for height in range(max(current.close + 1, current.height), current.deadline + 1):
            if current.used == commands and height == current.height:
                continue
            for fee in range(1, fee_limit + 1):
                successor = current.challenge(current.state + 1, fee, height)
                require(successor.deadline == initial.deadline and successor.capacity == initial.capacity,
                        'rebased close or altered payment capacity')
                edges += 1
                if successor not in seen:
                    seen.add(successor)
                    queue.append(successor)
        settled = current.settle(current.deadline + 1)
        require(settled.returned == current.capacity + current.budget.original - current.paid,
                'unused reservation not returned exactly once')
    return {'states': len(seen), 'edges': edges, 'window': window,
            'commands': commands, 'fee_limit': fee_limit}


def legacy_challenge(pots, root, channel, old_sequence, new_sequence, fee):
    """Execute the old channel-wide one-use policy on immutable model inputs."""
    require(root in pots and new_sequence > old_sequence, 'legacy root/higher state')
    selected = pots[root].audit()
    require(selected.policy == LEGACY and selected.channel == channel and selected.mature,
            'legacy complete delegated channel/policy/maturity')
    amount(fee, True)
    require(fee <= selected.fee_limit and fee <= selected.original, 'legacy fee cap')
    remaining = {key: value for key, value in pots.items() if key != root}
    return remaining, {'owner': selected.owner, 'change': selected.original-fee, 'fee': fee}


def checks():
    refusals = []
    def refuse(name, action):
        try:
            action()
        except Refusal:
            refusals.append(name)
        else:
            raise AssertionError('expected refusal: ' + name)

    # Original source counterexample: fee and change both leave E after one use.
    legacy_pot = Budget('root', 'channel', 'owner', LEGACY, 100000, 100000, 3)
    left, output = legacy_challenge({'root': legacy_pot}, 'root', 'channel', 0, 1, 1)
    assert output['fee'] + output['change'] == legacy_pot.original and not left
    legacy = dict(q0=0, q1=1, q2=2, reserve_original=legacy_pot.original,
                  fee=output['fee'], liquid_change=output['change'], locked_after_q1=0,
                  q2_covered='root' in left)
    second_pot = replace(legacy_pot, root='root-q2')
    left, output = legacy_challenge({'root': legacy_pot, 'root-q2': second_pot},
                                   'root-q2', 'channel', 0, 1, 1)
    assert 'root' in left and 'root-q2' not in left
    distinct_legacy = dict(q1_targets_q2_reserve=True, q2_covered_after_one_use='root-q2' in left,
                           actual_selected_root='root-q2', fee=output['fee'], change=output['change'])
    refuse('legacy wrong channel', lambda: legacy_challenge({'root': legacy_pot}, 'root', 'other', 0, 1, 1))
    refuse('legacy repeated root', lambda: legacy_challenge(left, 'root-q2', 'channel', 1, 2, 1))
    small = Budget('root', 'channel', 'owner', POLICY, 100000, 3, 3)
    refuse('small cumulative ceiling cannot support reliable new receipt', lambda: small.receive(3))
    exact = Budget('root', 'channel', 'owner', POLICY, coverage(3), coverage(3), 3)
    exact.receive(3)
    refuse('legacy one-use cannot authorize new receive', lambda: replace(exact, policy=LEGACY).receive(3))
    refuse('legacy cannot authorize successor retention', lambda: replace(exact, policy=LEGACY).challenge('channel', 0, 1))
    refuse('underfunded amount', lambda: replace(exact, original=coverage(3)-1, ceiling=coverage(3)-1).receive(3))
    refuse('immature', lambda: replace(exact, mature=False).receive(3))
    refuse('wrong channel', lambda: exact.challenge('other', 0, 1))
    after = exact.challenge('channel', 0, 1)
    refuse('stale successor', lambda: after.challenge('channel', 0, 1))
    refuse('above per-fee limit', lambda: exact.challenge('channel', 0, 4))
    refuse('canonical bool amount', lambda: coverage(True))
    refuse('amount overflow', lambda: coverage(CAP))
    dispute = Dispute(exact).audit()
    at_deadline = dispute.challenge(1, 3, dispute.deadline)
    refuse('settle at deadline', lambda: at_deadline.settle(at_deadline.deadline))
    refuse('same sequence', lambda: at_deadline.challenge(1, 1, at_deadline.deadline))
    refuse('challenge after deadline', lambda: at_deadline.challenge(2, 1, at_deadline.deadline+1))
    refuse('quarantined dependencies', lambda: replace(dispute, quarantined=True).challenge(1, 1, 11))
    settled = at_deadline.settle(at_deadline.deadline+1)
    refuse('repeat settlement', lambda: settled.settle(settled.deadline+2))
    refuse('settled channel challenge', lambda: settled.challenge(2, 1, settled.deadline+2))
    refuse('deadline overflow', lambda: replace(dispute, close=U64).challenge(1, 1, U64))
    # Separate owner-authorized pots coexist without inventing inherited rights.
    other = replace(exact, root='root-2')
    assert other.receive(3).remaining_authorization == exact.ceiling
    total_before = exact.locked + other.locked
    spent = exact.challenge('channel', 0, 2)
    assert spent.locked + other.locked + 2 == total_before
    # Explicit independent receiver perspectives: a stale cached pot is no
    # present coverage. Recheck the actual current native generation/authority.
    exhausted = replace(exact, spent=exact.ceiling, generation=32)
    refuse('exhausted native successor stops new receive', lambda: exhausted.receive(3))
    refuse('stale receiver cannot spend', lambda: exhausted.challenge('channel', 0, 1))
    results = [exhaustive(w, n, fee) for w in [1, 2] for n in [1, 2, 3] for fee in [1, 2, 3]]
    return dict(policy=POLICY, legacy_counterexample=legacy, distinct_legacy_counterexample=distinct_legacy,
                native_window=WINDOW, native_commands=COMMANDS,
                native_worst_fee_budget_at_limit_3=coverage(3),
                native_maximum_challenge_commands=WINDOW*COMMANDS,
                exhaustive_samples=results, exhaustive_states=sum(r['states'] for r in results),
                exhaustive_edges=sum(r['edges'] for r in results),refusals=refusals,
                original_native_source_modified=False,actual_native_crypto_or_history_qualified=False,
                ideal_owner_state_and_finality_authentication_assumed=True,
                independent_custody_latest_or_liveness_qualified=False,whole_protocol_complete=False)


if __name__ == '__main__':
    import json
    print(json.dumps(checks(), indent=2))
