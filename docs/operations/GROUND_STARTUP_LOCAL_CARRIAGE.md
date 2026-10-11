# Startup local submission carriage

The complete-origin ground companion can retain already queued local submissions
before its ordinary outgoing worker begins. This applies only to the base origin
runtime with parallel carriage enabled; legacy, joint-epoch and role profiles
keep their existing startup paths.

The runtime first completes its original Native cold authentication, pinned
history checks, caller-head reconciliation, retained response recovery and current
finality observation. Failed or incomplete startup, a pending caller request or
an unresolved outbox refuses priming. The service installs its original intake
fence and ordinary Mesh lease before requesting local carriage.

Priming uses the existing private bounded submission spool and complete Native
retention path. At most 32 queued files retain their original ownership, size,
typed decoding and duplicate rules. Fresh retained inputs use the existing
bounded durable broadcast selection. Empty or duplicate-only queues do not
broadcast. An authentication or publication refusal propagates before the worker
starts; queued input, retained Native responses and caller heads remain subject
to their original recovery rules.

This step cannot sign, propose, finalize, mutate an owner reservation or execute
a consensus unit. A keyless companion may relay authenticated evidence but gains
no signing right. The single outgoing worker, its intervals and neighbor rotation,
four-item carriage selection, receive-class quotas, full retry, FIFO and history
service remain unchanged. Preparation does not establish delivery or receiver
acceptance, and an existing full selection can still defer a submission.

Same-host startup models and no-value payment fixtures do not qualify latency
distributions, sustained faults, independent custody, physical links, long
history or an adopted network. Every incoming complete envelope, source dependency,
Native value execution, quorum, maturity and onward-spend check remains required.
