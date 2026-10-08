# Lossless directory carriage candidate

The explicit contact adapter `RLD-CONTACT-SPOOL-ZLIB-V1` wraps one complete
ordinary signed mesh exchange. Configure that adapter on both ends of a fresh
directory contact. It supports explicit incoming, outgoing or duplex directory
contacts; socket/TLS contacts retain their existing format. There is no format
negotiation or fallback. Mismatched contacts retain input and refuse it.

The file name remains the original exchange commitment followed by `.json`;
the explicitly selected carrier's file bytes are binary. Its header contains
the ASCII adapter name plus NUL, the unsigned big-endian eight-byte original
length, and the original bytes' SHA256, followed by one RFC1950 zlib stream.
The sender uses level1 with the standard32KiB window and no dictionary. These
fields bind bytes only and cannot authenticate a peer or Native evidence.

Both complete encoded and expanded exchange sizes must fit the original
20MiB mesh exchange bound. Directory admission charges the larger of the
physical file size and declared expanded size against the original64MiB/256-file
spool limits. Complete decoding must match the declared length and hash; an
understated length cannot admit extra expanded bytes. The decoder limits output
to the declared length plus one refusal byte, requires complete stream EOF and
rejects dictionaries, truncation, concatenation, trailing data and corruption.
It releases no partial decoded exchange.

The recovered bytes must be exactly canonical JSON and match the original file
name. All existing exchange, packet, route, receipt and Native authentication
then run unchanged. Every original signature and Native frame byte remains in
the expanded exchange. Directory deletion still follows actual durable receiver
custody; any codec, signature or publication failure retains the incoming file.
Compression grants no receipt, finality, maturity, value, freshness or signing
authority. Packet counts, Native3MiB payload and all archive/state limits remain
unchanged. This candidate does not qualify TCP, physical routes, independent
custody, long history or a complete payment/fault profile.
