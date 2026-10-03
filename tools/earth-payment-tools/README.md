# Earth payment tools

These payment entry points sit outside the signed Earth consensus source set.
They link against the unchanged, signed consensus libraries and retain their
embedded source commitment. The source and destination node binaries are not
modified by these tools.

The receiver and payer open adopted Earth mirrors with the four validator public
keys from the verified adoption so their replay can verify durable signed
finality. In candidate mode they keep the original store path. The tools do not
change chain rules or the genesis identity.

Build from the published Earth source archive with the pinned Rust toolchain:

    cargo build --release --manifest-path tools/earth-payment-tools/Cargo.toml

The original payment binaries inside the captured source tree remain frozen as
part of the signed source archive. Run these Earth entry points for the live
network.
