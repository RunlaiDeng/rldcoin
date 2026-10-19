# Explicit local fee monitor and ordinary background mining

This NO_VALUE_ONLY runtime composes the existing native selector, controlled
caller, durable actor custody, signed fee-wallet policy and operation pool. It
adds no consensus, issuance, reward, dispute-window or native authorization rule.
It is a local service entry, not independent operation, continuous physical-time
qualification or composed G1-G11 performance evidence.

## Activation and custody

The private session CLI exposes monitor_start {head, config, password},
monitor_stop {}, mining_start {head, reward}, mining_stop {} and runtime_status {}.
Config is exactly policy_request, key_file and operation_fee. Start requires the
controlled caller's exact head and a complete retained actual-input-owner policy.
Unlocking also requires an eligible fixed signing horizon; expired policies remain
available for locked observation and keyless handling of existing signatures.
Positive canonical operation_fee cannot exceed
the policy's per-operation limit. Available actor evidence is authenticated before
the encrypted fee-wallet key is opened. If supplied, the password must decrypt an
O13 key belonging to the policy owner. Passwords use bounded zeroized private
native stdin and process memory, never argv, environment, logs, journals, network
messages or response fields. A missing password selects observation/keyless
existing-signature handling; it never permits a new signature.

Starts are explicit private operator requests under existing signed owner scope;
there is no synthetic principal-owner approval. Policy approval alone activates
nothing. Stop drops the in-memory secret without releasing any reservation,
signature liability or evidence. Process exit drops activation and unlock state.
Cold startup defaults to both services stopped; recovery cannot first-sign. A
later explicit unlock can resume only policy-authorized runtime work, with actual
current native checks and unchanged limits. Trusted caller-file integrity, a
reliable clock and the key's wider independent custody remain assumptions.

## Proof protection and bounded work

Each monitor tick selects one of at most eight policy channels, authenticates
actual actor journals and checks the complete current native funding context.
Owner journals supply their last complete payment. Retainer journals supply both
the last acknowledged complete payment and a fully joint-signed pending payment
already durably prepared before acknowledgment. A pending invoice or one owner's
partial signature is not a complete certificate. Reading protection evidence does
not acknowledge a payment or mark it completed. Corrupt, replaced, missing,
wrong-head and changed-context custody refuses rather than authorizing a key.

The service compares authenticated principal sequence and both retained miner-fee
floors with the fully executed native selected state. It prioritizes a newer
principal certificate, then any uncovered fee range, using only existing native
kind3/kind4 actions. Equal-sequence conflicting joint states, including disagreement
with the already selected native principal, refuse. With no
protected custody it reports NO_PROTECTED_CUSTODY rather than automatically
settling. After both strict native window boundaries, any known uncovered
principal or fee range reports MISSED_PROTECTION_WINDOW and forbids automatic
settlement. Otherwise it may prepare the existing kind5 settlement. This cannot
recover an already missed deadline, establish completeness of withheld payments,
or promise that miners will include a claim before its window closes.

Every new action goes through the normal persisted native preparation, exact
policy-authorized signature and durable pool submission. Work is bounded to one
prepare/sign/submit sequence per tick. Only currently mature actual policy roots
or authorized change, remaining signature allowance and original input
reservations can fund it. No new user principal signature, close, transfer or
retainer acknowledgment is generated. Unsigned interrupted preparations can be
re-reviewed with identical reservation bytes; no input is freed or its intent
changed. A still-native-eligible retained signed action is reused and submitted
without a key or another allowance debit. Expiry drops the unlock secret and
prevents new signatures; it does not revoke an existing native signature.

## Observation and mining

The service distinguishes OPEN, LOCKED, missing custody, signed/pool-waiting,
protected-but-waiting-window, missed protection, absent backing and selected
native settlement. A settlement observation requires actual native inclusion of
a complete retained policy-authorized kind5 operation. The current index5 miner
output, if present, supplies its value, maturity height and eligibility for the
next block. Its absence does not establish an unpaid fee: it could already be
spent. Settlement and payout remain conditional on selected history; losing work
never receives replacement issuance or refunded policy allowance.

Status retains the last successful observation with its timestamp and a separate
current diagnostic. Failed or unknown observation cannot manufacture height zero
or mark a stale observation current. Each row identifies the selected tip and
prospective block timestamp. Local clock or resource failure does not grant value.
Full native history, actor evidence, caller heads and all existing capacities are
retained. Runtime activation and observations are not serialized monetary state.

An at-most16-entry process-local actor witness may retain the exact prior fully
authenticated head, native funding context and complete protection certificates.
Only a complete actor/caller audit can construct it. Reuse requires unchanged
actor head and no new caller action targeting or registering that actor since the
last completed audit. Under the actual exclusive actor-file lock it checks private
path/permissions, pinned device/inode and length, and reads/hashes every retained
byte, checking identity/length again afterward. Damage or replacement refuses.
Changed actor history performs complete replay; cold opening starts with no
witnesses. These small in-memory digests never initialize a native ledger or
replace current funding, certificate, fee-policy or monetary action checks.

Independent ordinary background mining needs only a valid public reward key and
controlled local caller. No actor, prior balance, fee policy or spending key is
required. Each tick performs at most4096 own-template PoW trials, considering at
most128 retained pool entries, and uses ordinary full native candidate admission.
Pool or selected-tip changes refresh the template; a cached job grants no native
authority. Timestamps follow native parent/median/future rules. A stale historical
parent can advance through valid nominal timestamps; a current parent requires a
strictly newer permitted timestamp. No timestamp advances a protocol window by
itself, and native work, both fixed window bounds and h+100 fee maturity stay
unchanged. Stop halts work; a reward destination is never a spend authorization.

Standalone workers do not carry their own operations or mined blocks to peers.
The separately enabled [automatic data mode](FAST_NATIVE_AUTOMATIC_CARRIAGE_V1.md)
connects existing signatures, actual native custody and independently verified
ingress under both trusted head files. Explicit carriage and block-only ingress
remain available. Complete service, discovery, multi-hop and resource qualification
are separate compositions, never inferred delivery.
In particular, the peer box's permanent2048-packet and32-MiB bounds cannot be
silently raised or pruned to accommodate a long window and reward maturity.

## Required qualification boundary

Fresh native-funded tests exercise pending joint evidence, exact interrupted
preparations, keyless retained claims, independent ordinary CPU work, actual idle
CLI protection/settlement and native miner payout/spend. Old logical genesis and
block timestamps can cover the actual fixed height/time rules within a bounded
engineering campaign. They do not represent two days of physical monitoring,
network inclusion under attack or independent operators. Power loss, copied/all-
state key rollback, long-history/capacity, multiple-channel contention, hostile
inclusion, service continuity, sovereign consumer approval, safe mass exit and
composed local latency/daily100M remain separate mandatory qualification work.
