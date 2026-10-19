# Bounded native fee-wallet policy

This NO_VALUE_ONLY session authorization profile lets an actual ordinary-input
owner explicitly consent to bounded native challenge, fee-claim and settlement
spending. A retained payment or retainer delegation is not that consent. Native
genesis, monetary work, supply, accepted operations, beneficiaries, fixed dispute
windows and reward maturity remain unchanged. This is a dependency of the required
continuous solvent service, not that service or composed G1-G11 qualification.
This budget pays ordinary native filing fees. It is separate from fast-payment
fee reserves and miner-beneficiary entitlements, whose backing, completeness,
settlement and maturity still require their own full evidence.

## Explicit signed scope

Policy use requires the independently instantiated version2 controlled caller.
Terms are typed canonical JSON in declaration order: chain, caller, owner,
channels, inputs, max_fee, total_fee, max_operations, expiry_height, expiry_time,
nonce. Hashes use Id lowercase hex, amounts/expiries canonical decimal strings,
and max_operations an unsigned16-bit JSON integer. The caller binding is the
complete unique caller-header hash, not an independently fresh ledger root.

One policy names1..8 strictly ordered distinct channel IDs and1..8 strictly
ordered actual34-byte ordinary inputs. Terms are at most1536 bytes; satisfying
array counts does not waive the complete byte limit. Per-operation and total fee
limits are positive integer runlai, bounded by native supply, with max_fee <= total_fee. At most
64 distinct signed operations and8 retained policies exist per caller. Consent
expires at a finite height and local time; its creation-time horizon is at most
31 days. No extension or renewal is implied. Initial inputs must actually exist,
belong to the signer, be mature for the next native block and cover the budget.
Named channels must exist in the fully replayed native selection.

Certificate bytes are RLDFPOL1(8), version:u16=1, suite:u16=1, terms_length:u32,
complete canonical terms, Ed25519 signature64 over
RLD-FAST-FEE-POLICY-1/CONSENT followed by NUL and all preceding frame bytes.
Maximum certificate size is1616 bytes, within the unchanged4096-byte caller reply
after hex encoding and reply fields. Strict verification rejects altered,
unknown, duplicate, noncanonical, cross-chain/caller and trailing encodings.
The [independently assembled public codec vector](fast-fee-policy-v1-vectors.json)
uses a labeled public no-value key and fictitious inputs. The public
FeePolicy::verify_certificate checks exact signature/encoding and supplied scope
only; it cannot establish native funding, spendability, adoption or freshness.

fee_policy_approve binds the exact current tip, terms, encrypted key path and
approved=true. It validates actual native ownership/funding/maturity before the
O13 key loader, then retains the signed certificate before release. This is
separate explicit owner consent; no synthetic approval bit substitutes for it.
The public certificate is a local service policy, not an on-chain covenant or
authority to change Native validation, operate another caller or control a key
outside this journal. Independent/copied-key custody remains a separate gate.

## Exact native preparation and signing

fee_policy_prepare binds tip, policy_request and complete OnchainRequest plan.
It permits only existing native kind3 principal challenge, kind4 miner-fee claim
or kind5 settlement for a named channel, paid by the policy input owner. Close,
ordinary transfer, opening, retainer acknowledgment and principal signing are
outside scope. Actual native certificate signatures, state, ownership, input
maturity, conservation, inclusion conditions and immutable windows still apply.

fee_policy_sign binds the unchanged current tip, signed policy request, exact
persisted policy preparation/review and encrypted fee-wallet key path. It has no
approved field. The independently verified owner certificate supplies this bounded
authority. A normal onchain_sign cannot sign a policy preparation. Full current
native review, policy scope/expiry and remaining allowance are checked before
loading a key. Passwords remain bounded zeroized private native stdin values,
never argv, environment, journal, network or response fields.

Allowed inputs are the exact initial inputs and index0 change outputs of prior
complete policy-authorized native signatures, with their actual current native
existence/maturity independently checked. No arbitrary wallet output, serialized
balance, unmined descendant, hash or retainer receipt supplies a funding right.
Policy roots and authenticated change lineage remain reserved against other
policies and manual opening/transfer/escrow preparations. Earlier explicit input
reservations cannot be captured by a new policy.

Every distinct retained signature consumes its exact positive fee and one
operation from the allowance, and permanently records its input use. An exact
same retained authorization is not charged twice. Signature-time liabilities
remain consumed after missing inclusion, expiry, restart or a losing branch;
timeouts/reorganization never refund allowances or free an input. Only native
inclusion establishes spend/change; an orphaned change pauses further spending.
No automatic retirement, input release, policy rebasing or revocation is supplied.

Time expiry prevents new signatures. Existing native signatures retain their
normal height expiry and execution/window rules; this local policy cannot revoke
them by clock. Native action review timestamps do not bind future block time.
Local time checks assume a reliable monotone observation clock and intact retained
caller state; independent clock/all-state rollback protection is not established.
Signer availability, policy horizon, proof availability, inclusion and mature
miner payout remain distinct. No later block means no promised payout deadline.

## Audit and recovery

The existing exact caller intent precedes key work. Complete certificate or native
signature bytes are retained in the caller reply before response. Cold opening
and recovery reexecute native history, verify policy signatures and original
scope/approval, reconstruct ordinary reservations, every used input/change and
signature-time allowance. An unkeyed rehash cannot replace the actual fee-owner
consent, native signature, persisted preparation or current native context.

Recovery returns only a fully verified existing policy/signature or audited
absence. It never first-signs, adopts a new policy, resets allowance or releases
a reservation. Optional process-local audit reuse never serializes authority or
skips complete retained-byte/file checks. Full history and original resource
limits remain mandatory.

The policy alone starts no background monitor, unlocks no key, submits no pool
entry and promises no successful claim or settlement. Actual unattended proof
selection, bounded key activation, solvent gas scheduling, carriage, native
inclusion, monitoring gaps and miner maturity remain required service work.
Consumer consent, independent latest-state/key custody, power-loss/resources,
long history/mass exit, physical routes and composed latency/daily100M remain open.

Private native execute methods are fee_policy_approve, fee_policy_prepare and
fee_policy_sign with the fields above. The key-free local observation is
fee_policy_status {head, policy_request}. It reports distinct retained signature
liabilities, remaining allowances and policy time eligibility, separately from
current spendability and native inclusion. Exact retained proof reproduction
does not create a new signature, spend or allowance debit.
