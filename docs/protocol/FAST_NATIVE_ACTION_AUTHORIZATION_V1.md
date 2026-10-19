# Native escrow action authorization V1

This local session extension composes the existing
[native escrow executor](NATIVE_FAST_ESCROW_V1.md) and
[payment caller session](FAST_PAYMENT_SESSION_V1.md). It changes no accepted
genesis, work, issuance, transaction, fee recipient, window or maturity rule.
It supplies explicit authorization of ordinary inputs paying for close, principal
challenge, miner-fee claim and settlement. Existing owner/retainer acknowledgments
never authorize those ordinary spends. No monetary activation or migration is
provided; changed implementations use fresh no-value fixtures.

## Native review and exact fee inputs

`kernel::fast::planning` builds an unsigned action from one completely replayed
native selection. Its request specifies kind2..5, channel, ordinary spending
actor, ordered actual input IDs, positive fee, expiry height, nonzero nonce,
existing complete certificate and a prospective block timestamp. Decimal values
in the local interface are canonical strings; hashes and bytes are lowercase hex.
The planner computes input total and actor-owned change, never invents an input
or spends locked escrow to pay the submitter's operation fee.

Before a key can be loaded, the complete shared execution kernel checks input
ownership/maturity/uniqueness, conservation, expiry, channel/close authority,
existing native certificate signatures, fee ranges and exact unchanged windows.
The unsigned parsing entry is private to nonmutating review and returns no ledger
state. Only complete signature-checked decoding admits operations to actual
blocks. A preview uses temporary bytes and discards all resulting state; no
preview hash, unsigned operation or reviewed payout initializes native value.

The review binds the exact native tip, prospective timestamp and complete
unsigned action. It displays operation kind, actual ordinary inputs/value,
positive operation fee, change/expiry, funding miner, authorized principal,
known miner-fee ranges, unused reserves and fixed closing deadlines. A prospective
timestamp is an evaluation context; the existing action signature does not bind
a future block's timestamp. Actual inclusion must reexecute every rule.
For a close review (kind2), the displayed deadlines are prospective values for
that evaluated inclusion. They become fixed only through actual selected native
close execution. Other action reviews describe the existing native close window.

## Persistent caller authorization

Two typed actions use the existing key-free caller journal:

```
onchain_prepare { tip, plan: {
  kind, channel, actor, inputs, fee, expiry, nonce, certificate, timestamp
} }
onchain_sign { tip, prepare_request, review, key_file, approved }
```

Wrap these with the normal local `execute` command, exact current session head
and unique request ID. A successful preparation durably retains its exact review
and reserves only its explicit ordinary inputs. Another intent cannot reuse them.
Timeout, failed signing, process interruption or missing response never releases
that reservation. It is separate from the off-chain principal and miner-fee
reserves, and from inputs held by another private wallet or copied key; independent
custody and concurrent-key exclusion remain necessary qualification.

A changed native selection requires a new explicit preparation and review. The
same complete authorization may be re-reviewed with a new prospective timestamp
and tip only if its actor, channel, exact inputs, nonce, fee, expiry and complete
certificate remain identical. Normal native checks must still succeed. This
retains the same input reservation; it does not change a signature or release
inputs. A different operation against those reserved inputs refuses. An expired
or orphaned authorization cannot be silently rebased onto another input.

Signing requires approved=true, the exact persisted preparation and review, the
unchanged selected tip and fresh complete native validation before encrypted-key
loading. Use the existing purpose/chain-bound O13 encrypted key file and bounded
native stdin password, never argv/environment/HTTP or an uploaded plaintext key.
The signing key must equal the actual ordinary input owner. A miner's retainer
delegation is insufficient. Any valid actor may fund a native claim or settlement
operation; doing so grants no principal or fee-beneficiary authority.

The signed operation is stored in the caller's completed response before any
response releases it. The optional authorization field is omitted when absent;
existing canonical caller records are unchanged. The fixed4096-byte reply budget
covers at most1589-byte complete signed actions. Each execute reserves its own
complete reply before work within unchanged32-MiB/65536-request caller bounds;
preparation does not promise space for arbitrary future operations. Signatures are
public authorization bytes; keys and passwords never enter the journal.

Exact completed-response recovery authenticates the retained signature and returns
the same bytes without a key. If interrupted before response durability, recovery
cannot first-sign: it records no new authorization and leaves the preparation's
reservation intact. A signature that existed only in process memory was never
released. The NativeActionEvaluated observation explicitly precedes durability;
ReplyDurable alone marks retained authorization. A later separately approved signing request is still subject to full
current native validation. No refund, cancellation or signature revocation is
inferred from a timeout.

## Audit, historical evidence and process-local reuse

Cold opening and recovery reexecute native history, verify caller-to-native
selection, rebuild all ordinary-input reservations and authenticate each prepared
review, explicit approval and complete actor signature against its original
native context. Rehashing a caller record cannot replace the signature, consent,
review, exact previous request or ownership. Unrelated caller actions cannot carry
an authorization field. Corrupt/torn/unknown tails refuse unchanged.

Within one audit, the native store holds its exclusive writer lease, compares
the complete actual file prefix before and after a single ordered pass, and
matches every caller native effect to every retained native record. Exact full
block bytes, record index/digest, predecessor/successor heads, original selected
tip and admission time must agree. Missing, extra or reordered steps refuse,
including accepted branches that did not change selection. One bounded complete
block is decoded at a time; returned selected-tip observations remain bounded
by the unchanged caller/native record limits. This avoids repeated reads of the
same immutable full file without skipping native execution or trusting a caller
hash. Cold native opening still executes every retained block from genesis.

Only after complete successful audit and durable caller completion may the
process retain the length of an already audited immutable on-chain prefix.
Every use still checks complete retained caller/native bytes, file identity and
writer lease. New reviews/signatures undergo full native validation; reservation
and signature bindings remain reconstructed. The witness is private, never
serialized, starts at zero on cold opening/recovery, and cannot advance after a
failed completion. It grants no ledger state, current backing or independent
freshness. Full history and all original resource limits remain required.

The keyless local `exit_evidence {head, actor}` command obtains the latest complete
retained owner/retainer certificate, including after close/reorganization. It
checks native/caller storage and full actor custody. It reports historical proof,
not restored backing, current solvency or native inclusion. A pending newer
unsigned owner state is not substituted for the latest complete certificate.
An acknowledged retainer state is not proof that no higher unseen state exists.
Use exact full evidence for native challenge/claim; the native selected ledger
independently revalidates funding and every certificate signature.

## Ordinary CPU candidate construction and inclusion

The key-free local command is:

```
mining_candidate {head, miner, operations, timestamp, attempts}
```

It constructs its own native template from current full execution, accepts at
most128 complete operations of at most4096 bytes each and searches at most4096
header hashes per request. Only a process-local exact tip/miner/ordered operation/
timestamp match retains a nonce cursor; another context rebuilds the template.
Native signatures and all value/window rules are checked before search. No
decoded ledger, remote balance, key/password or signed mining approval is used.
An invalid/stale native context cannot borrow an older cursor.

A discovered block is explicitly a candidate. It changes no caller/native head
and grants no ledger receipt. Submit its complete bytes through the normal
caller-native action, then use the existing authenticated peer queue for carriage.
Actual admission again verifies header work, complete operations, state root,
selection and durable storage. Candidate production, selected inclusion, fee
entitlement and actual mature payout remain distinct events.

First close still fixes2016 blocks AND172800 seconds; both strict inequalities
must pass for settlement. Claims/challenges cannot reset the window. Actual fee
payout is the existing output to the funding block miner, mature at h+100;
ordinary operation fees also go to the containing block miner. Reorganizations
retain only winning-history value. Logical fixture timestamps do not measure
real elapsed-time safety, independent clocks or a continuously available service.

These interfaces do not provide autonomous fee/challenge monitoring, guaranteed
claim inclusion, fee-input liquidity, independent latest-state/key protection,
consumer consent UI, scalable archival/hostile-load mass exit or G1-G11 campaigns.
Ordinary permissionless CPU mining and causal interstellar carriage remain
required. No local check proves seconds-scale service, daily100M payments,
independent operators or a physical interstellar route.

The separate [ordinary transfer authorization](FAST_NATIVE_TRANSFER_AUTHORIZATION_V1.md)
adds `transfer_prepare` for existing kind0 value transfers. Its exact persisted
review can use the same `onchain_sign` control, under the actual spending owner's
approval and encrypted key. Transfer and escrow preparations reserve ordinary
inputs against each other. This can explicitly fund a retainer's own operation
fees; a custody delegation still grants no spending rights or automatic budget.
Existing escrow action bytes, signature domains, windows and maturity remain
unchanged. The original caller reply reservation also accommodates the complete
maximum1639-byte signed ordinary operation without increasing its limit.

The separate [joint opening authorization](FAST_NATIVE_OPENING_AUTHORIZATION_V1.md)
uses `onchain_sign` only to retain the corresponding owner's65-byte partial.
Its response uses `opening_partial_hex`; a lone partial cannot be submitted as a
complete operation. Both actual signatures, their exact retained proposal and a
verified combine are necessary. No owner key is shared or loaded by combination.
All opening/ordinary/escrow preparations compose own-input reservations, while
complete native decoding still authenticates both opening owners on admission.
