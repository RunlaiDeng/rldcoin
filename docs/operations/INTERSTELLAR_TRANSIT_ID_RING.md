# Durable per-neighbor packet-ID rotation candidate

The private `RLD-CONTACT-TRANSIT-SCHEDULER-V3` replaces each neighbor's numeric
active-pool rank with a nullable exact last-prepared packet ID. Preparing an
exchange starts at that ID's sorted successor and wraps. Receipt completion may
move earlier packets into retained archives, and insertion may shift ranks;
neither changes the identity of the next original waiting successor.

The last actually carried packet ID is durably recorded before socket or spool
I/O. An empty route/byte/suppression batch rotates past one examined starting
packet. An empty pool retains its bounded ID. Other neighbors and ordinary ticks
do not advance it. Removing/readding a contact resets only its own cursor to
null; no packet, receipt, archive or native state is removed or converted.

V2 and older private identities/states refuse unchanged. Use fresh transport
directories and configured identities/pins; retain all failed fixtures. The
on-wire Mesh V3/TCP V4, source/route/hop/receipt authentication, TLS binding,
durable custody, four transits, sixteen receipts, 256 active entries, 64-MiB
combined state, 4,096-file/256-MiB archive and every Native rule remain unchanged.
A cursor is scheduling metadata and grants no custody, ledger or signing rights.

The preceding receive-ID-ring run failed its original third-payment gate with
five Native prefixes at height 11/role 2, conserved 300, two included payments
and one still reserving 20. Its 3,825 transport archives and 108 current-parent
complete Native envelopes passed stopped authentication; all private bytes and
separate heads remained unchanged. Nine destination receipts lacked matching
Native retained bodies. The bounded trace had 10,781 events with no collection
gaps. Stopped log presence does not reconstruct exact selections or prove a
unique cause: three destination packets were absent from carrier 0's published
logs and the six on carrier 2 appeared only in its final eight or fewer status
rows. Console logs omit the private process event ring. This candidate fixes a
reproduced dynamic ordering defect, without claiming it uniquely caused that
failed payment or changing its result.
