mod fragments;
pub use fragments::Fragment;
// Signed contact carriage. Custody acknowledges bytes, never settlement.
use crate::{
    custody::Vault,
    runtime::Dispatch,
    store::{private_create, read_bounded, sync_dir},
};
use anyhow::{Context, Result, ensure};
use rand::{RngCore, rngs::OsRng};
use rld_protocol::{
    codec::{Blob, Id, decode, encode, hash, tagged},
    crypto,
    model::Signature,
    record,
};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

record!(Peer {identity:Id  =>  0,domain:Id  =>  1,endpoint:String  =>  2,certificate_pem:String  =>  3,certificate_sha256:Id  =>  4});
record!(Advertisement {currency:Id  =>  0,identity:Id  =>  1,sequence:u64  =>  2,domains:Vec<Id>  =>  3,hints:Vec<Id>  =>  4,signature:Signature  =>  5});
record!(Challenge {currency:Id  =>  0,domain:Id  =>  1,identity:Id  =>  2,nonce:Id  =>  3,signature:Signature  =>  4});
record!(Exchange {currency:Id  =>  0,sender:Id  =>  1,challenge:Id  =>  2,nonce:Id  =>  3,sequence:u64  =>  4,items:Vec<Fragment>  =>  5,advertisement:Advertisement  =>  6,signature:Signature  =>  7});
record!(Acknowledgment {currency:Id  =>  0,identity:Id  =>  1,challenge:Id  =>  2,nonce:Id  =>  3,request_digest:Id  =>  4,retained:Vec<Id>  =>  5,signature:Signature  =>  6});
fn empty() -> Signature {
    Signature {
        key: Id::ZERO,
        bytes: Blob(vec![]),
    }
}
pub fn challenge_bytes(c: &Challenge) -> Vec<u8> {
    tagged(
        "RLD-CONTACT-CHALLENGE",
        c.currency,
        &(c.domain, c.identity, c.nonce),
    )
}
pub fn advertisement_bytes(a: &Advertisement) -> Vec<u8> {
    tagged(
        "RLD-CONTACT-ADVERTISEMENT",
        a.currency,
        &(a.identity, a.sequence, &a.domains, &a.hints),
    )
}
pub fn exchange_bytes(e: &Exchange) -> Vec<u8> {
    tagged(
        "RLD-CONTACT-EXCHANGE",
        e.currency,
        &(
            e.sender,
            e.challenge,
            e.nonce,
            e.sequence,
            &e.items,
            &e.advertisement,
        ),
    )
}
pub fn ack_bytes(a: &Acknowledgment) -> Vec<u8> {
    tagged(
        "RLD-CONTACT-ACK",
        a.currency,
        &(
            a.identity,
            a.challenge,
            a.nonce,
            a.request_digest,
            &a.retained,
        ),
    )
}
pub fn dispatch_id(c: Id, d: &Dispatch) -> Id {
    hash("RLD-DISPATCH", c, d)
}
pub fn make_exchange(
    currency: Id,
    domain: Id,
    key: &mut Vault,
    c: &Challenge,
    items: Vec<Fragment>,
    hints: Vec<Id>,
) -> Result<Exchange> {
    ensure!(
        c.currency == currency && c.signature.key == c.identity,
        "challenge identity/currency"
    );
    crypto::verify_signature(&c.signature, &challenge_bytes(c))?;
    let sequence = key.next_transport_sequence()?;
    let identity = key.binding().identity;
    let mut a = Advertisement {
        currency,
        identity,
        sequence,
        domains: vec![domain],
        hints,
        signature: empty(),
    };
    a.signature = key.sign_identity(&advertisement_bytes(&a))?;
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut e = Exchange {
        currency,
        sender: identity,
        challenge: c.nonce,
        nonce: Id(nonce),
        sequence,
        items,
        advertisement: a,
        signature: empty(),
    };
    e.signature = key.sign_identity(&exchange_bytes(&e))?;
    Ok(e)
}
pub fn verify_exchange(currency: Id, e: &Exchange, peer: &Peer) -> Result<()> {
    ensure!(
        e.currency == currency
            && e.sender == peer.identity
            && e.signature.key == peer.identity
            && e.items.len() <= 16
            && encode(e).len() <= rld_protocol::MAX_CAPSULE,
        "exchange scope/count/bytes"
    );
    crypto::verify_signature(&e.signature, &exchange_bytes(e))?;
    let a = &e.advertisement;
    ensure!(
        a.currency == currency
            && a.identity == peer.identity
            && a.sequence == e.sequence
            && a.signature.key == a.identity
            && a.domains.len() <= 16
            && a.hints.len() <= 32,
        "advertisement bounds"
    );
    crypto::verify_signature(&a.signature, &advertisement_bytes(a))?;
    Ok(())
}
pub fn acknowledge(
    currency: Id,
    key: &Vault,
    e: &Exchange,
    mut retained: Vec<Id>,
) -> Result<Acknowledgment> {
    retained.sort();
    retained.dedup();
    let mut a = Acknowledgment {
        currency,
        identity: key.binding().identity,
        challenge: e.challenge,
        nonce: e.nonce,
        request_digest: Id::digest(&exchange_bytes(e)),
        retained,
        signature: empty(),
    };
    a.signature = key.sign_identity(&ack_bytes(&a))?;
    Ok(a)
}
pub fn verify_ack(currency: Id, peer: &Peer, e: &Exchange, a: &Acknowledgment) -> Result<()> {
    ensure!(
        a.currency == currency
            && a.identity == peer.identity
            && a.signature.key == peer.identity
            && a.challenge == e.challenge
            && a.nonce == e.nonce
            && a.request_digest == Id::digest(&exchange_bytes(e))
            && a.retained.len() <= e.items.len()
            && rld_protocol::codec::sorted_unique(&a.retained),
        "ack binding"
    );
    for id in &a.retained {
        ensure!(
            e.items.iter().any(|d| d.object == *id),
            "ack unrelated object"
        );
    }
    crypto::verify_signature(&a.signature, &ack_bytes(a))
}

pub struct Spool {
    root: PathBuf,
    currency: Id,
    max_bytes: u64,
    max_objects: usize,
    _lock: File,
}
impl Spool {
    pub fn open(root: &Path, currency: Id, max_bytes: u64, max_objects: usize) -> Result<Self> {
        ensure!(
            max_objects > 0 && max_objects <= 4096 && max_bytes >= rld_protocol::MAX_CAPSULE as u64,
            "spool bounds"
        );
        for dir in [
            "packets",
            "receipts",
            "receipts/objects",
            "accepted",
            "incoming",
        ] {
            fs::create_dir_all(root.join(dir))?;
        }
        use fs2::FileExt;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("LOCK"))?;
        lock.try_lock_exclusive()?;
        let marker = root.join("CURRENCY");
        if marker.exists() {
            ensure!(
                read_bounded(&marker, 128)? == encode(&currency),
                "spool currency"
            )
        } else {
            private_create(&marker, &encode(&currency))?;
            sync_dir(root)?;
        }
        Ok(Self {
            root: root.into(),
            currency,
            max_bytes,
            max_objects,
            _lock: lock,
        })
    }
    fn packet(&self, id: Id) -> PathBuf {
        self.root.join("packets").join(format!("{id}.cbor"))
    }
    pub fn retain(&self, d: &Dispatch) -> Result<Id> {
        let bytes = encode(d);
        ensure!(
            bytes.len() <= rld_protocol::MAX_CAPSULE,
            "carried object bound"
        );
        let id = dispatch_id(self.currency, d);
        let path = self.packet(id);
        if path.exists() {
            ensure!(
                read_bounded(&path, rld_protocol::MAX_CAPSULE)? == bytes,
                "changed retained object"
            );
            File::open(&path)?.sync_all()?;
            sync_dir(path.parent().context("packet parent")?)?;
            return Ok(id);
        }
        self.capacity(id, bytes.len())?;
        private_create(&path, &bytes)?;
        sync_dir(path.parent().context("packet parent")?)?;
        Ok(id)
    }
    pub fn packets(&self) -> Result<Vec<(Id, Dispatch)>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("packets"))? {
            let path = entry?.path();
            let bytes = read_bounded(&path, rld_protocol::MAX_CAPSULE)?;
            let d: Dispatch = decode(&bytes, rld_protocol::MAX_CAPSULE)?;
            let id = dispatch_id(self.currency, &d);
            ensure!(path == self.packet(id), "spool filename/content mismatch");
            out.push((id, d));
        }
        out.sort_by_key(|(id, _)| *id);
        Ok(out)
    }
    pub fn accepted(&self, id: Id) -> bool {
        self.root.join("accepted").join(id.to_string()).is_file()
    }
    pub fn mark_accepted(&self, id: Id) -> Result<()> {
        ensure!(self.packet(id).is_file(), "accept before custody");
        let path = self.root.join("accepted").join(id.to_string());
        if !path.exists() {
            self.metadata_capacity(32)?;
            private_create(&path, &id.0)?;
        }
        sync_dir(path.parent().context("accepted parent")?)
    }
    pub fn has_receipt(&self, peer: Id, id: Id) -> bool {
        self.root
            .join("receipts")
            .join(format!("{peer}-{id}.cbor"))
            .is_file()
    }
    pub fn retain_ack(&self, peer: &Peer, e: &Exchange, a: &Acknowledgment) -> Result<()> {
        verify_ack(self.currency, peer, e, a)?;
        let bytes = encode(&(e.clone(), a.clone()));
        let digest = Id::digest(&bytes);
        let record = self
            .root
            .join("receipts/objects")
            .join(format!("{digest}.cbor"));
        if !record.exists() {
            self.metadata_capacity(bytes.len())?;
            private_create(&record, &bytes)?;
        } else {
            ensure!(
                read_bounded(&record, rld_protocol::MAX_CAPSULE + 8192)? == bytes,
                "changed retained contact acknowledgment"
            );
            File::open(&record)?.sync_all()?;
        }
        sync_dir(record.parent().context("receipt object parent")?)?;
        for id in &a.retained {
            ensure!(self.packet(*id).is_file(), "receipt without local custody");
            let path = self
                .root
                .join("receipts")
                .join(format!("{}-{id}.cbor", peer.identity));
            if !path.exists() {
                let reference = encode(&digest);
                self.metadata_capacity(reference.len())?;
                private_create(&path, &reference)?;
            }
        }
        sync_dir(&self.root.join("receipts"))
    }
    pub fn pending(&self, peer: Id, cursor: usize) -> Result<Vec<Fragment>> {
        self.pending_fragments(peer, cursor)
    }
}
#[derive(Default)]
pub struct Challenges {
    pending: BTreeMap<Id, Instant>,
}
impl Challenges {
    pub fn issue(&mut self, currency: Id, domain: Id, key: &Vault) -> Result<Challenge> {
        self.pending
            .retain(|_, t| t.elapsed() < Duration::from_secs(60));
        ensure!(self.pending.len() < 1024, "contact challenge queue full");
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut c = Challenge {
            currency,
            domain,
            identity: key.binding().identity,
            nonce: Id(nonce),
            signature: empty(),
        };
        c.signature = key.sign_identity(&challenge_bytes(&c))?;
        self.pending.insert(c.nonce, Instant::now());
        Ok(c)
    }
    pub fn consume(&mut self, nonce: Id) -> Result<()> {
        let t = self
            .pending
            .remove(&nonce)
            .context("unknown/used contact challenge")?;
        ensure!(
            t.elapsed() < Duration::from_secs(60),
            "contact attempt expired"
        );
        Ok(())
    }
}
