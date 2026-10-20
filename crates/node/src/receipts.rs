//! Immutable disk index of already verified local execution receipts. No root is
//! loaded from disk: complete native event replay reconstructs every observation.
use crate::{
    object_store::{Object, ObjectStatus, Objects},
    runtime::Initial,
};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, decode, encode, encode_bounded},
    model::Certified,
    record,
};
use std::{path::Path, sync::Arc};
const FORMAT: &str = "RLD-VERIFIED-RECEIPT-INDEX-1";
const PAGE_BYTES: usize = 4096;
record!(Link {object:Object => 0,first:u64 => 1,last:u64 => 2,count:u64 => 3,depth:u8 => 4});
record!(Page {format:String => 0,currency:Id => 1,domain:Id => 2,sequence:Option<u64> => 3,certificate:Option<Object> => 4,left:Option<Link> => 5,right:Option<Link> => 6});
struct Owner {
    objects: Arc<Objects>,
    currency: Id,
    domain: Id,
}
#[derive(Clone)]
pub struct Receipts {
    owner: Arc<Owner>,
    root: Option<Link>,
}
fn depth(a: u64, b: u64) -> Result<u8> {
    ensure!(a != b, "receipt branch distinct keys");
    Ok((a ^ b).leading_zeros() as u8)
}
fn bit(key: u64, depth: u8) -> bool {
    key & (1u64 << (63 - depth)) != 0
}
impl Receipts {
    pub(crate) fn open(path: &Path, initial: &Initial) -> Result<Self> {
        let currency = initial.currency.id();
        let domain = initial.genesis.configuration.domain;
        let genesis = rld_protocol::state::genesis_id(currency, &initial.genesis);
        Ok(Self {
            owner: Arc::new(Owner {
                objects: Objects::open(path, &encode(&(FORMAT, currency, domain, genesis)))?,
                currency,
                domain,
            }),
            root: None,
        })
    }
    pub fn len(&self) -> u64 {
        self.root.as_ref().map_or(0, |r| r.count)
    }
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
    pub fn last_sequence(&self) -> Option<u64> {
        self.root.as_ref().map(|r| r.last)
    }
    pub(crate) fn status(&self) -> Result<ObjectStatus> {
        self.owner.objects.status()
    }
    fn summary(&self, object: Object, p: &Page) -> Result<Link> {
        ensure!(
            p.format == FORMAT
                && p.currency == self.owner.currency
                && p.domain == self.owner.domain,
            "receipt page context"
        );
        match (&p.sequence, &p.certificate, &p.left, &p.right) {
            (Some(seq), Some(c), None, None) => {
                ensure!(
                    *seq > 0 && c.bytes > 0 && c.bytes <= rld_protocol::MAX_CAPSULE as u64,
                    "receipt leaf bounds"
                );
                Ok(Link {
                    object,
                    first: *seq,
                    last: *seq,
                    count: 1,
                    depth: 64,
                })
            }
            (None, None, Some(l), Some(r)) => {
                ensure!(
                    l.first > 0
                        && l.first <= l.last
                        && r.first <= r.last
                        && l.last < r.first
                        && l.count > 0
                        && r.count > 0
                        && l.count <= l.last - l.first + 1
                        && r.count <= r.last - r.first + 1,
                    "receipt branch order/count"
                );
                let d = depth(l.first, r.last)?;
                ensure!(
                    l.depth <= 64
                        && r.depth <= 64
                        && l.depth > d
                        && r.depth > d
                        && !bit(l.first, d)
                        && !bit(l.last, d)
                        && bit(r.first, d)
                        && bit(r.last, d)
                        && (l.last >> (63 - d)) == (l.first >> (63 - d))
                        && (r.first >> (63 - d)) == (r.last >> (63 - d)),
                    "receipt branch prefix/depth"
                );
                Ok(Link {
                    object,
                    first: l.first,
                    last: r.last,
                    count: l
                        .count
                        .checked_add(r.count)
                        .context("receipt count exhaustion")?,
                    depth: d,
                })
            }
            _ => anyhow::bail!("incomplete receipt page"),
        }
    }
    fn read(&self, l: &Link) -> Result<Page> {
        let bytes = self.owner.objects.read(&l.object, PAGE_BYTES)?;
        let p: Page = decode(bytes.as_slice(), PAGE_BYTES)?;
        ensure!(
            self.summary(l.object.clone(), &p)? == *l,
            "receipt page retained summary"
        );
        Ok(p)
    }
    fn put(&self, p: Page) -> Result<Link> {
        let bytes = encode(&p);
        let object = Object {
            digest: Id::digest(&bytes),
            bytes: bytes.len() as u64,
        };
        let link = self.summary(object.clone(), &p)?;
        ensure!(
            self.owner.objects.put(bytes, PAGE_BYTES)? == object,
            "receipt object publication"
        );
        Ok(link)
    }
    fn leaf(&self, seq: u64, certificate: Object) -> Result<Link> {
        self.put(Page {
            format: FORMAT.into(),
            currency: self.owner.currency,
            domain: self.owner.domain,
            sequence: Some(seq),
            certificate: Some(certificate),
            left: None,
            right: None,
        })
    }
    fn branch(&self, left: Link, right: Link) -> Result<Link> {
        self.put(Page {
            format: FORMAT.into(),
            currency: self.owner.currency,
            domain: self.owner.domain,
            sequence: None,
            certificate: None,
            left: Some(left),
            right: Some(right),
        })
    }
    fn insert_at(&self, root: &Option<Link>, seq: u64, certificate: Object) -> Result<Link> {
        let Some(link) = root else {
            return self.leaf(seq, certificate);
        };
        if seq != link.first && depth(seq, link.first)? < link.depth {
            let new = self.leaf(seq, certificate)?;
            return if seq < link.first {
                self.branch(new, link.clone())
            } else {
                self.branch(link.clone(), new)
            };
        }
        let p = self.read(link)?;
        ensure!(p.sequence.is_none(), "duplicate receipt sequence");
        let l = p.left.context("receipt left")?;
        let r = p.right.context("receipt right")?;
        if bit(seq, link.depth) {
            self.branch(l, self.insert_at(&Some(r), seq, certificate)?)
        } else {
            self.branch(self.insert_at(&Some(l), seq, certificate)?, r)
        }
    }
    // Core calls this only after real receipt verification, exact local history
    // binding and QC checks. Publication precedes the authoritative event append;
    // failure does not install the staged Core/root and never discards residue.
    pub(crate) fn insert_verified(&mut self, c: &Certified) -> Result<()> {
        ensure!(
            c.header.currency == self.owner.currency && c.header.domain == self.owner.domain,
            "receipt insertion context"
        );
        if let Some(old) = self.get(c.header.sequence)? {
            ensure!(old.header == c.header, "conflicting receipt checkpoint");
            return Ok(());
        }
        let object = self.owner.objects.put(
            encode_bounded(c, rld_protocol::MAX_CAPSULE)?,
            rld_protocol::MAX_CAPSULE,
        )?;
        let next = self.insert_at(&self.root, c.header.sequence, object)?;
        ensure!(
            self.len().checked_add(1) == Some(next.count),
            "receipt insertion cardinality"
        );
        self.root = Some(next);
        Ok(())
    }
    fn certificate(&self, l: &Link) -> Result<Arc<Certified>> {
        let page = self.read(l)?;
        let seq = page.sequence.context("receipt leaf required")?;
        let object = page.certificate.context("receipt certificate object")?;
        let bytes = self
            .owner
            .objects
            .read(&object, rld_protocol::MAX_CAPSULE)?;
        let c: Certified = decode(bytes.as_slice(), rld_protocol::MAX_CAPSULE)?;
        ensure!(
            c.header.sequence == seq
                && c.header.currency == self.owner.currency
                && c.header.domain == self.owner.domain,
            "receipt retained identity"
        );
        Ok(Arc::new(c))
    }
    pub fn get(&self, seq: u64) -> Result<Option<Arc<Certified>>> {
        let mut current = self.root.clone();
        for _ in 0..=64 {
            let Some(l) = current else { return Ok(None) };
            if seq < l.first || seq > l.last {
                return Ok(None);
            }
            let page = self.read(&l)?;
            if let Some(n) = page.sequence {
                return if n == seq {
                    Ok(Some(self.certificate(&l)?))
                } else {
                    Ok(None)
                };
            }
            current = if bit(seq, l.depth) {
                page.right
            } else {
                page.left
            };
        }
        anyhow::bail!("receipt lookup depth exhausted")
    }
    pub fn contains(&self, seq: u64) -> Result<bool> {
        Ok(self.get(seq)?.is_some())
    }
    /// Greatest verified receipt height strictly smaller than `seq`.
    pub fn before(&self, seq: u64) -> Result<Option<Arc<Certified>>> {
        self.bound(seq, false)
    }
    /// Least verified receipt height greater than or equal to `seq`.
    pub fn at_or_after(&self, seq: u64) -> Result<Option<Arc<Certified>>> {
        self.bound(seq, true)
    }
    fn bound(&self, seq: u64, lower: bool) -> Result<Option<Arc<Certified>>> {
        let Some(mut link) = self.root.clone() else {
            return Ok(None);
        };
        if (lower && link.last < seq) || (!lower && link.first >= seq) {
            return Ok(None);
        }
        for _ in 0..=64 {
            let p = self.read(&link)?;
            if p.sequence.is_some() {
                return Ok(Some(self.certificate(&link)?));
            }
            let l = p.left.context("receipt bound left")?;
            let r = p.right.context("receipt bound right")?;
            link = if lower {
                if l.last >= seq { l } else { r }
            } else if r.first < seq {
                r
            } else {
                l
            };
        }
        anyhow::bail!("receipt bound depth exhausted")
    }
}
