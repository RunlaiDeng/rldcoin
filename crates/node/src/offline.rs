//! One-way carriage for scheduled or disconnected contacts. These signatures
//! acknowledge retained bytes; only the protocol node can accept monetary state.
use crate::{custody::Vault, runtime::Dispatch, transport::Spool};
use anyhow::{Result, ensure};
use rld_protocol::{
    codec::{Blob, Id, encode, hash, tagged},
    crypto,
    model::Signature,
    record,
};
record!(Bundle{currency:Id => 0,sender:Id => 1,sequence:u64 => 2,objects:Vec<Dispatch> => 3,signature:Signature => 4});
record!(CustodyReceipt{currency:Id => 0,carrier:Id => 1,bundle:Id => 2,retained:Vec<Id> => 3,sequence:u64 => 4,signature:Signature => 5});
fn unsigned() -> Signature {
    Signature {
        key: Id::ZERO,
        bytes: Blob(vec![]),
    }
}
fn bytes(b: &Bundle) -> Vec<u8> {
    tagged(
        "RLD-OFFLINE-CARRIAGE-1",
        b.currency,
        &(b.sender, b.sequence, &b.objects),
    )
}
pub fn export(spool: &Spool, currency: Id, vault: &mut Vault, cursor: usize) -> Result<Bundle> {
    let mut packets = spool.packets()?;
    if !packets.is_empty() {
        let n = packets.len();
        packets.rotate_left(cursor % n);
    }
    let mut objects = Vec::new();
    let mut size = 4096;
    for (_, d) in packets {
        let n = encode(&d).len();
        if size + n <= rld_protocol::MAX_CAPSULE && objects.len() < 16 {
            size += n;
            objects.push(d);
        }
    }
    ensure!(
        !objects.is_empty(),
        "no complete bounded carriage available"
    );
    let mut bundle = Bundle {
        currency,
        sender: vault.binding().identity,
        sequence: vault.next_transport_sequence()?,
        objects,
        signature: unsigned(),
    };
    bundle.signature = vault.sign_identity(&bytes(&bundle))?;
    ensure!(
        encode(&bundle).len() <= rld_protocol::MAX_CAPSULE,
        "offline bundle bound"
    );
    Ok(bundle)
}
pub fn import(
    spool: &Spool,
    currency: Id,
    vault: &mut Vault,
    pinned_sender: Id,
    bundle: &Bundle,
) -> Result<CustodyReceipt> {
    ensure!(
        bundle.currency == currency
            && bundle.sender == pinned_sender
            && bundle.signature.key == pinned_sender
            && !bundle.objects.is_empty()
            && bundle.objects.len() <= 16
            && encode(bundle).len() <= rld_protocol::MAX_CAPSULE,
        "offline contact pin/profile/bounds"
    );
    crypto::verify_signature(&bundle.signature, &bytes(bundle))?;
    let mut retained = Vec::new();
    for object in &bundle.objects {
        let id = spool.retain(object)?;
        ensure!(!retained.contains(&id), "duplicate offline object");
        retained.push(id);
    }
    retained.sort();
    let mut receipt = CustodyReceipt {
        currency,
        carrier: vault.binding().identity,
        bundle: hash("RLD-OFFLINE-BUNDLE", currency, bundle),
        retained,
        sequence: vault.next_transport_sequence()?,
        signature: unsigned(),
    };
    receipt.signature = vault.sign_identity(&tagged(
        "RLD-OFFLINE-CUSTODY-1",
        currency,
        &(
            receipt.carrier,
            receipt.bundle,
            &receipt.retained,
            receipt.sequence,
        ),
    ))?;
    Ok(receipt)
}
