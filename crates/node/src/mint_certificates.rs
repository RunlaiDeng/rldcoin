//! Only verified native events create this immutable correspondence catalogue.
use crate::{
    object_store::{Object, ObjectStatus, Objects},
    runtime::Initial,
    typed_paths::{Paths, Value},
};
use anyhow::{Result, ensure};
use rld_protocol::{
    codec::{Id, decode, encode, encode_bounded, hash},
    merkle::Entry,
    mints::index::{Certificate, Claim},
    record,
    table::{Key, Record},
};
use std::{path::Path, sync::Arc};
record!(Reference{claim:Claim => 0,object:Object => 1});
impl Record for Reference {
    fn key(&self, _: Id) -> Key {
        Key::Id(self.claim.events)
    }
    fn entry(&self, c: Id) -> Entry {
        Entry {
            key: self.claim.events,
            value: hash("RLD-MINT-INDEX-REFERENCE-1", c, self),
        }
    }
}
impl Value for Reference {
    const FORMAT: &'static str = "RLD-MINT-INDEX-REF-1";
    const NAME: &'static str = "mint-index-certificates";
    fn validate(&self, home: Id) -> Result<()> {
        ensure!(
            self.claim.home == home
                && self.claim.count
                    <= u64::from(rld_protocol::ROOTS) * u64::from(rld_protocol::SLOTS)
                && self.object.bytes > 0
                && self.object.bytes <= rld_protocol::MAX_CAPSULE as u64,
            "Mint certificate reference bounds"
        );
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct Certificates {
    objects: Arc<Objects>,
    paths: Arc<Paths<Reference>>,
    currency: Id,
    home: Id,
    latest: Option<(u64, Id)>,
}
impl Certificates {
    pub(crate) fn open(path: &Path, initial: &Initial) -> Result<Self> {
        let currency = initial.currency.id();
        let home = initial.genesis.configuration.domain;
        let genesis = rld_protocol::state::genesis_id(currency, &initial.genesis);
        let objects = Objects::open(
            path,
            &encode(&("RLD-MINT-INDEX-CERTIFICATES-1", currency, home, genesis)),
        )?;
        Ok(Self {
            paths: Arc::new(Paths::on_objects(objects.clone(), initial)?),
            objects,
            currency,
            home,
            latest: None,
        })
    }
    pub(crate) fn get(&self, root: Id) -> Result<Option<Arc<Certificate>>> {
        let Some(reference) = self.paths.get(root)? else {
            return Ok(None);
        };
        let bytes = self
            .objects
            .read(&reference.object, rld_protocol::MAX_CAPSULE)?;
        let certificate: Certificate = decode(bytes.as_slice(), rld_protocol::MAX_CAPSULE)?;
        ensure!(
            certificate.claim == reference.claim
                && certificate.claim.currency == self.currency
                && certificate.claim.home == self.home,
            "Mint retained correspondence binding"
        );
        Ok(Some(Arc::new(certificate)))
    }
    pub(crate) fn latest(&self) -> Result<Option<(u64, Arc<Certificate>)>> {
        match self.latest {
            Some((sequence, root)) => Ok(Some((
                sequence,
                self.get(root)?
                    .ok_or_else(|| anyhow::anyhow!("latest Mint correspondence missing"))?,
            ))),
            None => Ok(None),
        }
    }
    pub(crate) fn insert_verified(&mut self, at: u64, c: &Certificate) -> Result<()> {
        ensure!(
            c.claim.currency == self.currency && c.claim.home == self.home,
            "Mint correspondence insertion context"
        );
        if let Some(old) = self.get(c.claim.events)? {
            ensure!(
                old.claim == c.claim,
                "conflicting verified Mint correspondence"
            );
        } else {
            let object = self.objects.put(
                encode_bounded(c, rld_protocol::MAX_CAPSULE)?,
                rld_protocol::MAX_CAPSULE,
            )?;
            let paths = self
                .paths
                .insert_path(Reference {
                    claim: c.claim.clone(),
                    object,
                })?
                .seal_path()?;
            self.paths = paths;
        }
        if self.latest.is_none_or(|(old, _)| at >= old) {
            self.latest = Some((at, c.claim.events));
        }
        Ok(())
    }
    pub(crate) fn status(&self) -> Result<ObjectStatus> {
        self.objects.status()
    }
}
