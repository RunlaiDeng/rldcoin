# Implementation and adoption boundaries

The project has not completed the frozen whitepaper's full acceptance obligations.
All S1–S18, R1–R24, I1–I12, A–G, N1–N10 and P1–P8 remain mandatory.
The [freeze receipt](WHITEPAPER_FREEZE_RECEIPT.json) identifies the canonical paper;
this repository does not change the frozen body, PDF or official website.

The public implementation includes candidate regional ledgers, owner authorization,
local finality, imports, onward/return transfers, channels, authenticated ground
relay and bounded retained histories. These remain signed no-value fixture
profiles. Discovery, byte custody, ledger import, maturity and spendability are
separate states; a transport receipt cannot credit or refund money.

Hybrid dual authorization, fixed quorum, Old/New renewal, complete archive and
manifest verification are separately versioned verification-only candidates.
Python/OpenSSL reference tools provide another implementation of specified
verification paths. Existing Native profiles retain their classical rules and
reject unknown adoption/suite profiles. No candidate result installs ledger state,
consumes a nonce, authorizes a new network or migrates old currency/custody.

Full long-history recovery, permanent deduplication at target scale, arbitrary
multi-source value composition, independent operators and custody, security and
supply-chain review, authenticated suite/epoch adoption, funding/resource models,
cross-device recovery and actual physical routes remain required. Current bounded
Native archives cannot serve the target long history without a new authenticated
archival/proof design. Existing limits are not silently increased.

See the [acceptance contract](WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md),
[master plan](RLDCOIN_MASTER_PLAN.md), [stable verification interfaces](operations/VERIFICATION.md)
and [reference security risks](operations/PQ_REFERENCE_RISKS.md).
Per-run outcomes, timings, source/binary/controller bindings and retained failures
are local engineering records, not public documentation.
