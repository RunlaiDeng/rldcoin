# Original-envelope activation observation candidate

This fixture candidate adds `bft-epoch-activate-observed --file ...` and optional
`--carried-index N`. It changes the native implementation identity and requires
fresh signed no-value genesis/currency, transport and custody directories. Old
fixtures, failed owner requests, journals and separately retained heads remain
unchanged. It is not an adopted-network upgrade or value migration.

The native entry reads at most the existing 3 MiB wire capacity, expands bounded
carried checkpoints, checks the complete logical envelope within 8 MiB, and
authenticates every proof and signed body before selecting anything. Without an
index it requires an EpochActivation body. With an index it selects exactly that
ordered proof from this envelope's EpochSigned/EpochSubmission list, bounded by
the existing sixteen-epoch limit. It never accepts a separate caller proof or
uses Python metadata to supply native authority.

The selected proof takes the existing native activation path, including full
evidence verification, certified dependency synchronization and native local
epoch selection. A different valid certificate variant still takes activation;
original installed journal/proof bytes remain retained. A forged later proof or
signed body refuses before selection or sync even if the first proof is valid.

After activation, the same opened/locked native store streams its ordered local
epoch events and returns exact installed proofs. `RLD-BFT-ACTIVATION-OBSERVATION-V1`
binds the currency, region, current epoch, activated statement ID, exact raw
request SHA-256 and optional index. The response stays within 8 MiB and carries
no signer, wallet, private key or caller-head state. It explicitly grants no
signing authority or independent freshness. The existing activation and standalone
installed-observation commands remain available.

The ordinary companion first authenticates and syncs dependencies as before.
It compares full canonical proof bytes with the native installed observation.
When activation is needed it passes the original complete envelope and ordered
index, then strictly validates the returned request/domain/format/index/flags
and bounds. This removes a separate proof request, envelope pack and subsequent
installed-observation process; it never skips native activation of a variant.
There is no old-binary fallback. Controller authority counters/guards include
the new mutating command, and read-only fault observers refuse it.

At preparation time, native regression, strict lint, process custody and fresh
ordinary cycle/cold qualification are pending. Python source parsing and Rust
formatting do not establish a pass. The older frozen duplicate-role-deferral
sample continues separately; its result cannot qualify this changed native
source. Existing limits/deadlines remain unchanged, and sustained faults,
independent custody, physical contacts and interstellar qualification remain
separate mandatory gates.
