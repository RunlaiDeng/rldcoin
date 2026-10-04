//! Native application boundary for the existing bounded evidence carriage.
//! Mesh identity, advertisements and transport receipts never grant ledger rights.
use super::*;
use crate::{conflict::Conflict, storage::Store};
use base64::{engine::general_purpose::STANDARD, Engine};
pub const FORMAT: &str = "RLD-REGIONAL-CONTACT-V2";
pub const FRAME_FORMAT: &str = "RLD-INTERREGION-EVIDENCE-V1";
pub const MAX_PAYLOAD: usize = 3 * 1024 * 1024;
pub const MAX_FRAME: usize = 4 * 1024 * 1024 + 4096;
pub const MAX_CONTACTS: usize = 256;
pub const MAX_APPLY_PER_TICK: usize = 4;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    pub currency: Hash,
    pub source: Hash,
    pub destination: Hash,
    pub snapshot: Hash,
    pub export: Hash,
    pub evidence: Evidence,
    pub incidents: Vec<Conflict>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBundle {
    format: String,
    currency: Hash,
    source: Hash,
    destination: Hash,
    snapshot: Hash,
    export: Hash,
    evidence: crate::carriage::CarriedEvidence,
    incidents: Vec<Conflict>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub format: String,
    pub kind: String,
    pub source_chain_id: Hash,
    pub destination_chain_id: Hash,
    pub export_id: Hash,
    pub payload_sha256: Hash,
    pub payload_b64: String,
    pub message_id: Hash,
}
fn sha(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
// serde_json's default Map is ordered; the ASCII carriage fields match the
// existing Python canonical sorted-key, compact JSON exactly.
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::to_value(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
impl Frame {
    fn message(&self) -> Result<Hash> {
        let mut body = serde_json::to_value(self).map_err(|e| e.to_string())?;
        body.as_object_mut()
            .ok_or("frame is not an object")?
            .remove("message_id");
        let mut bytes = format!("{FRAME_FORMAT}\0").into_bytes();
        bytes.extend(canonical(&body)?);
        Ok(sha(&bytes))
    }
    pub fn pack(bundle: &Bundle) -> Result<Vec<u8>> {
        require(
            bundle.format == FORMAT,
            "native contact wire format mismatch",
        )?;
        let wire = WireBundle {
            format: bundle.format.clone(),
            currency: bundle.currency,
            source: bundle.source,
            destination: bundle.destination,
            snapshot: bundle.snapshot,
            export: bundle.export,
            evidence: crate::carriage::CarriedEvidence::pack(&bundle.evidence)?,
            incidents: bundle.incidents.clone(),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|e| e.to_string())?;
        require(
            !bytes.is_empty() && bytes.len() <= MAX_PAYLOAD,
            "contact payload capacity reached; retain source proof",
        )?;
        require(
            bundle.source != bundle.destination,
            "same-region contact frame",
        )?;
        let mut frame = Self {
            format: FRAME_FORMAT.into(),
            kind: "finalized-import".into(),
            source_chain_id: bundle.source,
            destination_chain_id: bundle.destination,
            export_id: bundle.export,
            payload_sha256: sha(&bytes),
            payload_b64: STANDARD.encode(bytes),
            message_id: Hash::ZERO,
        };
        frame.message_id = frame.message()?;
        let raw = canonical(&frame)?;
        require(raw.len() <= MAX_FRAME, "contact frame bound")?;
        Ok(raw)
    }
    pub fn unpack(raw: &[u8]) -> Result<(Self, Bundle)> {
        require(
            !raw.is_empty() && raw.len() <= MAX_FRAME,
            "contact frame byte bound",
        )?;
        let frame: Self = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        require(
            frame.format == FRAME_FORMAT
                && frame.kind == "finalized-import"
                && frame.source_chain_id != frame.destination_chain_id,
            "wrong native contact frame format, kind or route",
        )?;
        require(
            raw == canonical(&frame)? && frame.message_id == frame.message()?,
            "noncanonical or changed contact message",
        )?;
        let bytes = STANDARD
            .decode(&frame.payload_b64)
            .map_err(|_| "invalid contact base64")?;
        require(
            !bytes.is_empty()
                && bytes.len() <= MAX_PAYLOAD
                && STANDARD.encode(&bytes) == frame.payload_b64
                && sha(&bytes) == frame.payload_sha256,
            "changed or oversized contact payload",
        )?;
        let wire: WireBundle = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        require(
            wire.format == FORMAT
                && wire.source == frame.source_chain_id
                && wire.destination == frame.destination_chain_id
                && wire.export == frame.export_id,
            "native payload differs from carriage route",
        )?;
        let bundle = Bundle {
            format: wire.format,
            currency: wire.currency,
            source: wire.source,
            destination: wire.destination,
            snapshot: wire.snapshot,
            export: wire.export,
            evidence: wire.evidence.expand()?,
            incidents: wire.incidents,
        };
        Ok((frame, bundle))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub message_id: Hash,
    pub payload_sha256: Hash,
    pub source: Hash,
    pub destination: Hash,
    pub snapshot: Hash,
    pub export: Hash,
}
impl Record {
    pub fn verify(&self, trust: &Trust, evidence: &VerifiedEvidence, region: Hash) -> Result<()> {
        let source = evidence.snapshot(self.snapshot)?;
        let export = evidence.export(self.snapshot, self.export)?;
        require(
            !self.message_id.is_zero()
                && !self.payload_sha256.is_zero()
                && self.source != region
                && self.destination == region
                && source.statement.currency == trust.currency()?
                && source.statement.region == self.source
                && export.source == self.source
                && export.destination == region,
            "contact record lacks exact verified currency/source/destination/export",
        )
    }
}
#[derive(Debug, Serialize)]
pub struct Status {
    pub message_id: Hash,
    pub source: Hash,
    pub destination: Hash,
    pub export: Hash,
    pub evidence_verified: bool,
    pub import_accepted: bool,
    pub import_height: Option<u64>,
    pub recipient_mature_height: Option<u64>,
    pub local_height: u64,
    pub original_recipient_output_remaining: Amount,
    pub original_recipient_output_spendable_now: bool,
    pub quarantined: bool,
    pub transport_receipt_is_payment_authority: bool,
    pub remote_current_state_known: bool,
}
impl Store {
    pub fn contact_export(&self, eid: Hash) -> Result<Vec<u8>> {
        let latest = self
            .chain
            .finalized
            .ok_or("contact export needs installed local finality")?;
        let height = self.evidence.snapshot(latest)?.statement.height;
        let actual = self
            .chain
            .ledger
            .exports
            .get(&eid)
            .ok_or("unknown local export")?;
        // Keep ordinary retries stable as unrelated histories grow. Select the
        // first certified local history covering this exact retained export;
        // include its complete causal proof, not the ever-growing whole archive.
        let sid = self
            .journal
            .evidence
            .snapshots
            .iter()
            .filter(|s| s.statement.region == self.chain.region && s.statement.height <= height)
            .filter_map(|s| {
                let sid = s.statement.id().ok()?;
                (self.evidence.export(sid, eid).ok()? == actual)
                    .then_some((s.statement.height, sid))
            })
            .min_by_key(|(height, _)| *height)
            .map(|(_, sid)| sid)
            .ok_or("export absent from certified local history")?;
        let record = self.evidence.export(sid, eid)?;
        require(
            record.source == self.chain.region,
            "cannot originate a frame for another region's export",
        )?;
        Frame::pack(&Bundle {
            format: FORMAT.into(),
            currency: self.trust.currency()?,
            source: self.chain.region,
            destination: record.destination,
            snapshot: sid,
            export: eid,
            evidence: self.contact_dependency_evidence(sid)?,
            incidents: self.conflicts.clone(),
        })
    }
    fn contact_dependency_evidence(&self, root: Hash) -> Result<Evidence> {
        let mut needed = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(sid) = pending.pop() {
            if !needed.insert(sid) {
                continue;
            }
            require(needed.len() <= MAX_SNAPSHOTS, "contact dependency bound")?;
            let snapshot = self.evidence.snapshot(sid)?;
            pending.extend(snapshot.statement.previous);
            for block in &snapshot.blocks {
                pending.extend(block.header.anchor);
                for command in &block.commands {
                    if let Command::Import { snapshot, .. } = command {
                        pending.push(*snapshot);
                    }
                }
            }
            pending.extend(
                snapshot
                    .epochs
                    .iter()
                    .map(|p| p.statement.closing_checkpoint),
            );
        }
        // Preserve the native validated topological order, including complete
        // parent, import/ancestry and epoch closing dependencies.
        // Legacy finalization can retain an exact checkpoint twice: once as
        // evidence and once when installing local finality. The verified index
        // already authenticates/normalizes these entries. Carry one proof per
        // statement, without rewriting the retained journal or losing a parent.
        let mut included = BTreeSet::new();
        let snapshots = self
            .journal
            .evidence
            .snapshots
            .iter()
            .filter_map(|s| {
                s.statement
                    .id()
                    .ok()
                    .filter(|sid| needed.contains(sid) && included.insert(*sid))
                    .map(|_| s.clone())
            })
            .collect::<Vec<_>>();
        require(
            included == needed,
            "contact dependency missing from retained archive",
        )?;
        let evidence = Evidence { snapshots };
        VerifiedEvidence::verify(&evidence, &self.trust)?;
        Ok(evidence)
    }
    pub fn contact_status(&self, ident: Hash) -> Result<Status> {
        let record = self
            .journal
            .contact_records
            .get(&ident)
            .ok_or("unknown native contact message")?;
        record.verify(&self.trust, &self.evidence, self.chain.region)?;
        let accepted = self.chain.ledger.imports.get(&record.export);
        if let Some(sid) = accepted {
            require(
                self.evidence.export(*sid, record.export)?
                    == self.evidence.export(record.snapshot, record.export)?,
                "replayed export differs from accepted import",
            )?;
        }
        let import_height = self.import_height(record.export)?;
        require(
            accepted.is_some() == import_height.is_some(),
            "import tombstone and local history differ",
        )?;
        let coin = self
            .chain
            .ledger
            .coins
            .get(&id("output", &(record.export, 0u32))?);
        let quarantined = self
            .safety
            .check(
                &self.chain,
                &[Command::Import {
                    snapshot: accepted.copied().unwrap_or(record.snapshot),
                    export: record.export,
                }],
                &self.evidence,
            )
            .is_err();
        Ok(Status {
            message_id: ident,
            source: record.source,
            destination: record.destination,
            export: record.export,
            evidence_verified: true,
            import_accepted: accepted.is_some(),
            import_height,
            recipient_mature_height: import_height.map(|h| h + self.trust.currency.maturity),
            local_height: self.chain.height(),
            original_recipient_output_remaining: coin
                .map(|c| c.payment.amount)
                .unwrap_or(Amount::ZERO),
            original_recipient_output_spendable_now: coin
                .is_some_and(|c| c.mature <= self.chain.height())
                && !quarantined,
            quarantined,
            transport_receipt_is_payment_authority: false,
            remote_current_state_known: false,
        })
    }
    pub fn contact_apply(&mut self, raw: &[u8], miner: Option<String>) -> Result<Status> {
        let (frame, bundle) = Frame::unpack(raw)?;
        require(
            bundle.currency == self.trust.currency()? && bundle.destination == self.chain.region,
            "contact uses wrong currency or destination",
        )?;
        self.trust.region(bundle.source)?;
        require(
            bundle.evidence.snapshots.len() <= MAX_SNAPSHOTS
                && bundle.incidents.len() <= crate::conflict::MAX_INCIDENTS,
            "contact proof count bound",
        )?;
        let source = bundle
            .evidence
            .snapshots
            .iter()
            .find(|s| s.statement.id().ok() == Some(bundle.snapshot))
            .ok_or("contact omits requested source checkpoint")?;
        require(
            source.statement.region == bundle.source,
            "contact source differs from checkpoint identity",
        )?;
        let record = Record {
            message_id: frame.message_id,
            payload_sha256: frame.payload_sha256,
            source: bundle.source,
            destination: bundle.destination,
            snapshot: bundle.snapshot,
            export: bundle.export,
        };
        if let Some(old) = self.journal.contact_records.get(&frame.message_id) {
            require(
                old == &record,
                "contact message conflicts with retained record",
            )?;
            // Exact retries use retained value evidence. They cannot bypass new
            // incidents or native import tombstones and never mine twice.
        } else {
            require(
                self.journal.contact_records.len() < MAX_CONTACTS,
                "native contact record capacity full; retain received frame",
            )?;
        }
        // Independently authenticated incidents remain worth preserving even
        // if the accompanying value archive cannot be installed.
        for proof in &bundle.incidents {
            proof.verify(&self.trust)?;
        }
        for proof in bundle.incidents {
            self.observe_conflict(proof)?;
        }
        let mut journal = self.stage_evidence(bundle.evidence)?;
        journal
            .contact_records
            .entry(frame.message_id)
            .or_insert(record);
        // Full archive replay and exact export binding are checked together
        // before writing either the new evidence or its pending application.
        self.commit(journal)?;
        if let Some(miner) = miner {
            self.contact_fulfill(frame.message_id, miner)?;
        }
        self.contact_status(frame.message_id)
    }
    pub fn contact_fulfill(&mut self, ident: Hash, miner: String) -> Result<Status> {
        let status = self.contact_status(ident)?;
        if status.import_accepted {
            return Ok(status);
        }
        let record = self
            .journal
            .contact_records
            .get(&ident)
            .ok_or("missing native contact record")?;
        let mut block = self.template(
            vec![Command::Import {
                snapshot: record.snapshot,
                export: record.export,
            }],
            miner,
        )?;
        mine(&mut block)?;
        self.accept(block)?;
        self.contact_status(ident)
    }
}
