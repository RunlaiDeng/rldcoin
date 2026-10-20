use crate::{
    codec::{Blob, Id, hash, tagged},
    crypto, merkle,
    model::*,
    record,
};
use anyhow::{Result, ensure};
use bincode::Options;
use risc0_zkvm::{
    InnerReceipt, Receipt,
    sha::{Digest, Digestible},
};

pub struct Verifier<'a> {
    pub currency: &'a Currency,
}
pub fn default_parameters() -> (Id, Id) {
    let p = risc0_zkvm::SuccinctReceiptVerifierParameters::default();
    (Id(p.control_root.into()), Id(p.digest().into()))
}
pub fn native_journal(h: &Checkpoint) -> Vec<u8> {
    tagged("RLD-CHECKPOINT", h.currency, h)
}
pub fn terminal_journal(t: &Terminal) -> Vec<u8> {
    tagged("RLD-TERMINAL", t.currency, t)
}
impl Verifier<'_> {
    pub fn admission(&self, config: &Configuration, p: &InventoryAdmission) -> Result<()> {
        ensure!(
            p.configuration == config.id() && config.currency == self.currency.id(),
            "inventory admission binding"
        );
        self.receipt(
            self.currency.proof.native_image,
            &admission_journal(config),
            &p.receipt,
        )
    }
    pub fn receipt(&self, image: Id, journal: &[u8], seal: &Blob) -> Result<()> {
        let (root, params) = default_parameters();
        ensure!(
            self.currency.proof.control_root == root
                && self.currency.proof.verifier_parameters == params,
            "unsupported verifier/control parameters"
        );
        ensure!(
            seal.0.len() <= self.currency.limits.receipt_bytes as usize,
            "receipt bytes"
        );
        #[cfg(target_os = "zkvm")]
        {
            risc0_zkvm::guest::env::verify(Digest::from(image.0), journal)
                .map_err(|e| anyhow::anyhow!("recursive verification: {e:?}"))?;
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            let receipt: Receipt = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(crate::MAX_RECEIPT as u64)
                .reject_trailing_bytes()
                .deserialize(&seal.0)?;
            ensure!(
                matches!(&receipt.inner,InnerReceipt::Succinct(s) if Id(s.verifier_parameters.into())==params),
                "only pinned unconditional succinct receipts accepted"
            );
            ensure!(receipt.journal.bytes == journal, "receipt journal mismatch");
            receipt.verify(Digest::from(image.0))?;
        }
        Ok(())
    }
    pub fn native(&self, p: &Certified) -> Result<()> {
        ensure!(
            p.header.currency == self.currency.id()
                && p.configuration.currency == p.header.currency
                && p.configuration.domain == p.header.domain
                && p.header.configuration == p.configuration.id()
                && p.header.profile == "RLD-NATIVE-RELATION-1",
            "native binding"
        );
        self.receipt(
            self.currency.proof.native_image,
            &native_journal(&p.header),
            &p.receipt,
        )?;
        crypto::verify_quorum(
            &p.configuration,
            p.header.domain,
            None,
            &p.qc,
            3,
            p.header.id(),
        )?;
        ensure!(
            p.qc.votes[0].sequence == p.header.sequence,
            "checkpoint sequence"
        );
        Ok(())
    }
    pub fn witness(
        &self,
        header: &Checkpoint,
        collection: &str,
        key: Id,
        value: Id,
        w: &StateWitness,
    ) -> Result<()> {
        ensure!(
            w.collection == collection && w.entry.entry.key == key && w.entry.entry.value == value,
            "state leaf binding"
        );
        let tag = format!("{}/{}", header.domain, collection);
        merkle::verify(header.currency, &tag, w.top.entry.value, &w.entry)?;
        ensure!(
            w.top.entry.key
                == hash(
                    "RLD-COLLECTION",
                    header.currency,
                    &(header.domain, collection)
                ),
            "state collection"
        );
        merkle::verify(
            header.currency,
            &format!("{}/state", header.domain),
            header.new_root,
            &w.top,
        )
    }
    pub fn creation(&self, p: &Creation) -> Result<()> {
        self.native(&p.source)?;
        let c = &p.controller;
        ensure!(
            p.source.header.domain == c.source
                && c.configuration == p.source.configuration
                && c.configuration.currency == self.currency.id(),
            "creation home/configuration"
        );
        self.witness(
            &p.source.header,
            "controllers",
            c.id,
            hash("RLD-CONTROLLER", self.currency.id(), c),
            &p.delegation,
        )?;
        let use_record = Delegation {
            coupon: c.ticket.coupon,
            controller: Some(c.id),
            closed: false,
        };
        self.witness(
            &p.source.header,
            "coupon_uses",
            c.ticket.coupon,
            hash("RLD-DELEGATION", self.currency.id(), &use_record),
            &p.coupon_use,
        )?;
        validate_controller(c)?;
        Ok(())
    }
    pub fn release(&self, r: &Release) -> Result<()> {
        ensure!(
            crate::codec::encode(r).len() + crate::MAX_RECEIPT + 256 * 1024
                <= self.currency.limits.capsule_bytes as usize,
            "complete release carriage limit"
        );
        self.creation(&r.creation)?;
        let c = &r.creation.controller;
        ensure!(
            crate::codec::encode(r).len() + crate::MAX_RECEIPT + 256 * 1024
                <= c.limits.capsule_bytes as usize
                && r.receipt.0.len() <= c.limits.receipt_bytes as usize
                && r.creation.source.receipt.0.len() <= c.limits.receipt_bytes as usize,
            "original receiving proof/material bounds"
        );
        validate_terminal(c, r.creation.source.header.id(), &r.terminal, 1)?;
        ensure!(
            r.material.0.len() <= c.limits.capsule_bytes as usize
                && Id::digest(&r.material.0) == c.material_root
                && r.terminal.material_root == c.material_root,
            "current material commitment"
        );
        let material: Material =
            crate::codec::decode(&r.material.0, c.limits.capsule_bytes as usize)?;
        ensure!(
            material.ticket == c.ticket
                && material.coupon == c.coupon
                && material.covers == r.covers
                && material.outputs == material_outputs(c),
            "current material terms"
        );
        self.receipt(
            self.currency.proof.controller_image,
            &terminal_journal(&r.terminal),
            &r.receipt,
        )?;
        crypto::verify_quorum(
            &c.configuration,
            c.id,
            Some(c.pool_index),
            &r.qc,
            3,
            r.terminal.id(),
        )?;
        Ok(())
    }
    pub fn rejected(&self, r: &Rejected) -> Result<()> {
        self.release(&r.release)?;
        self.native(&r.destination)?;
        let c = &r.release.creation.controller;
        ensure!(
            r.destination.header.domain == c.ticket.destination
                && crate::codec::encode(r).len() + 128 * 1024
                    <= self.currency.limits.capsule_bytes as usize,
            "rejection destination/carriage"
        );
        for part in c.escrow.iter() {
            let cover = r
                .release
                .covers
                .iter()
                .find(|v| v.id(self.currency.id()) == part.cover)
                .ok_or_else(|| anyhow::anyhow!("rejection cover absent"))?;
            r.destination.configuration.accepts(cover)?;
        }
        if let Some(range) = &c.ticket.range {
            let cover = r
                .release
                .covers
                .iter()
                .find(|v| v.id(self.currency.id()) == range.cover)
                .ok_or_else(|| anyhow::anyhow!("rejection range cover absent"))?;
            r.destination.configuration.accepts(cover)?;
        }
        let decision = Decision {
            object: c.id,
            coupon: c.ticket.coupon,
            outcome: 2,
            digest: c.ticket.digest(self.currency.id()),
        };
        self.witness(
            &r.destination.header,
            "decisions",
            c.id,
            hash("RLD-DECISION", self.currency.id(), &decision),
            &r.decision,
        )?;
        let closed = Delegation {
            coupon: c.ticket.coupon,
            controller: Some(c.id),
            closed: true,
        };
        self.witness(
            &r.destination.header,
            "coupon_uses",
            closed.coupon,
            hash("RLD-DELEGATION", self.currency.id(), &closed),
            &r.leaf_decision,
        )?;
        Ok(())
    }
    pub fn coupon(&self, p: &CouponEvidence) -> Result<()> {
        self.native(&p.certified)?;
        let c = self.currency.id();
        let f = &p.family;
        let coupon = &p.coupon;
        ensure!(
            f.id == hash(
                "RLD-COUPON-FAMILY-ID",
                c,
                &(f.source, f.destination, f.nonce, &f.issuer)
            ) && f.destination == p.certified.header.domain
                && coupon.family == f.id
                && coupon.source == f.source
                && coupon.destination == f.destination
                && coupon.index < f.count
                && f.count > 0
                && f.count <= 4096
                && f.units >= f.count as u64,
            "coupon family"
        );
        ensure!(
            p.leaf.entry.key == hash("RLD-COUPON-INDEX", c, &coupon.index)
                && p.leaf.entry.value == coupon.digest(c)
                && p.leaf.path.count == f.count as u64,
            "coupon leaf"
        );
        merkle::verify(c, &format!("{}/coupons", f.id), f.leaf_root, &p.leaf)?;
        self.witness(
            &p.certified.header,
            "families",
            f.id,
            hash("RLD-FAMILY", c, f),
            &p.reservation,
        )?;
        ensure!(
            coupon.proof == self.currency.proof && coupon.kind <= 1,
            "coupon proof/kind"
        );
        coupon.source_fee_policy.validate()?;
        coupon.destination_fee_policy.validate()?;
        ensure!(
            coupon.source_sponsor == f.source_funding,
            "source sponsorship terms"
        );
        coupon.limits.validate()?;
        coupon.recipient.validate()?;
        validate_use_policy(&coupon.use_policy)?;
        coupon.close_policy.validate()?;
        if coupon.kind == 1 {
            validate_use_policy(&coupon.cancel_policy)?;
            validate_use_policy(&coupon.recovery_policy)?;
        } else {
            coupon.cancel_policy.validate()?;
            coupon.recovery_policy.validate()?;
        }
        ensure!(
            !coupon.covers.is_empty()
                && coupon.covers.len() <= 64
                && crate::codec::sorted_unique(&coupon.covers),
            "coupon covers"
        );
        Ok(())
    }
}
pub fn admission_journal(config: &Configuration) -> Vec<u8> {
    tagged(
        "RLD-PUBLIC-INVENTORY-ADMISSION",
        config.currency,
        &(config.domain, config.id()),
    )
}
pub fn execute_admission(w: &AdmissionWitness) -> Result<Vec<u8>> {
    w.currency.validate()?;
    let config = &w.configuration;
    config.validate()?;
    ensure!(
        config.currency == w.currency.id()
            && w.inventories.len() == config.validators.len()
            && w.inventories
                .windows(2)
                .all(|a| a[0].validator < a[1].validator),
        "admission inventory binding"
    );
    let mut all: std::collections::BTreeSet<_> =
        config.validators.iter().map(|v| v.identity).collect();
    for inv in &w.inventories {
        let v = config
            .validators
            .iter()
            .find(|v| v.identity == inv.validator)
            .ok_or_else(|| anyhow::anyhow!("inventory validator"))?;
        ensure!(
            crypto::validate_inventory(config, v.identity, false, &inv.native)? == v.native_root
                && crypto::validate_inventory(config, v.identity, true, &inv.controller)?
                    == v.controller_root,
            "inventory root"
        );
        for key in inv.native.iter().chain(&inv.controller) {
            ensure!(all.insert(*key), "shared public signing key");
        }
    }
    Ok(admission_journal(config))
}
pub fn validate_controller(c: &Controller) -> Result<()> {
    ensure!(
        c.id == c.ticket.identity(c.configuration.currency)
            && c.id == c.ticket.id
            && c.ticket.source == c.source
            && c.ticket.coupon == c.coupon.id(c.configuration.currency)
            && c.ticket.destination == c.coupon.destination
            && c.configuration.domain == c.source
            && c.ticket.kind == c.coupon.kind
            && c.limits == c.coupon.limits,
        "controller identity/ticket"
    );
    ensure!(
        c.pool_index < crate::KEY_COUNT
            && c.keys.len() == c.configuration.validators.len()
            && c.keys.windows(2).all(|w| w[0].validator < w[1].validator),
        "controller key count"
    );
    for leaf in &c.keys {
        crypto::verify_leaf(&c.configuration, leaf, true, c.pool_index)?;
    }
    ensure!(
        c.keys
            .iter()
            .map(|k| k.key)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == c.keys.len(),
        "shared controller keys"
    );
    c.limits.validate()?;
    Ok(())
}
pub fn material_outputs(c: &Controller) -> Vec<Allocation> {
    if c.ticket.kind == 0 {
        vec![c.ticket.recipient.clone(), c.ticket.destination_fee.clone()]
    } else {
        vec![]
    }
}
pub fn cancellation_digest(c: &Controller) -> Id {
    hash(
        "RLD-CANCEL-RETURN",
        c.configuration.currency,
        &(
            c.id,
            hash("RLD-CONTROLLER", c.configuration.currency, c),
            &c.escrow,
            &c.ticket.range,
            &c.ticket.cancel_policy,
            &c.ticket.recovery_policy,
            c.ticket.cancel_fee,
            &c.ticket.cancel_fee_payout,
        ),
    )
}

pub fn cancellation_bytes(c: &Controller) -> Vec<u8> {
    tagged(
        "RLD-CANCEL-AUTHORIZATION",
        c.configuration.currency,
        &(c.id, cancellation_digest(c)),
    )
}
pub fn validate_terminal(c: &Controller, birth: Id, t: &Terminal, decision: u8) -> Result<()> {
    ensure!(
        t.currency == c.configuration.currency
            && t.controller == c.id
            && t.initial == hash("RLD-CONTROLLER", t.currency, c)
            && t.source_checkpoint == birth
            && t.decision == decision,
        "terminal binding"
    );
    ensure!(
        t.ticket_or_return
            == if decision == 1 {
                c.ticket.digest(t.currency)
            } else {
                cancellation_digest(c)
            },
        "terminal outcome"
    );
    ensure!(
        t.material_root
            == if decision == 1 {
                c.material_root
            } else {
                Id::ZERO
            },
        "terminal material"
    );
    Ok(())
}

// Guest input is canonical bytes; imported receipt assumptions are discharged
// by the authenticated relation, never by a host boolean.
record!(NativeStep {batch:Batch  =>  0,header:Checkpoint  =>  1,qc:Quorum  =>  2});
record!(NativeWitness {currency:Currency  =>  0,genesis:Option<DomainGenesis>  =>  1,predecessor:Option<Certified>  =>  2,state:crate::state::State  =>  3,steps:Vec<NativeStep>  =>  4});
record!(ControllerWitness {currency:Currency  =>  0,creation:Creation  =>  1,terminal:Terminal  =>  2,material:Blob  =>  3,covers:Vec<Cover>  =>  4,cancellation_authorization:Option<Authorization>  =>  5});

pub fn execute_native(w: &NativeWitness) -> Result<Checkpoint> {
    w.currency.validate()?;
    ensure!(
        !w.steps.is_empty() && w.steps.len() <= 4096,
        "native proof step count"
    );
    let v = Verifier {
        currency: &w.currency,
    };
    let mut state = w.state.clone();
    let mut previous;
    match (&w.genesis, &w.predecessor) {
        (Some(g), None) => {
            let derived = crate::state::State::genesis(&w.currency, g)?;
            ensure!(state == derived, "genesis state");
            previous = crate::state::genesis_id(w.currency.id(), g);
        }
        (None, Some(p)) => {
            v.native(p)?;
            ensure!(
                state.currency == w.currency.id()
                    && state.configuration.currency == state.currency
                    && state.configuration.domain == state.domain
                    && state.root()? == p.header.new_root
                    && state.sequence == p.header.sequence
                    && state.domain == p.header.domain,
                "predecessor state"
            );
            previous = p.header.id();
        }
        _ => anyhow::bail!("one proof base required"),
    }
    let mut last = None;
    for (i, step) in w.steps.iter().enumerate() {
        let (next, header) = state.execute_batch(&w.currency, previous, &step.batch)?;
        ensure!(header == step.header, "native transition header");
        if i + 1 < w.steps.len() {
            crypto::verify_quorum(
                &state.configuration,
                state.domain,
                None,
                &step.qc,
                3,
                header.id(),
            )?;
            ensure!(
                step.qc.votes[0].sequence == header.sequence,
                "intermediate QC sequence"
            );
        }
        previous = header.id();
        state = next;
        last = Some(header);
    }
    Ok(last.expect("nonempty"))
}
pub fn execute_controller(w: &ControllerWitness) -> Result<Terminal> {
    w.currency.validate()?;
    let v = Verifier {
        currency: &w.currency,
    };
    v.creation(&w.creation)?;
    let c = &w.creation.controller;
    validate_terminal(
        c,
        w.creation.source.header.id(),
        &w.terminal,
        w.terminal.decision,
    )?;
    match w.terminal.decision {
        1 => {
            ensure!(
                Id::digest(&w.material.0) == c.material_root
                    && w.material.0.len() <= c.limits.capsule_bytes as usize,
                "release current data"
            );
            let m: Material = crate::codec::decode(&w.material.0, c.limits.capsule_bytes as usize)?;
            ensure!(
                m.ticket == c.ticket
                    && m.coupon == c.coupon
                    && m.covers == w.covers
                    && m.outputs == material_outputs(c),
                "release material"
            );
            let prospective = Release {
                creation: w.creation.clone(),
                terminal: w.terminal.clone(),
                receipt: Blob(vec![]),
                qc: Quorum {
                    votes: c
                        .keys
                        .iter()
                        .map(|key| Vote {
                            currency: w.currency.id(),
                            namespace: c.id,
                            configuration: c.configuration.id(),
                            sequence: 0,
                            view: u64::MAX,
                            phase: 3,
                            statement: w.terminal.id(),
                            validator: key.validator,
                            key: key.clone(),
                            signature: Signature {
                                key: key.key,
                                bytes: Blob(vec![0; 64]),
                            },
                        })
                        .collect(),
                },
                covers: w.covers.clone(),
                material: w.material.clone(),
            };
            ensure!(
                crate::codec::encode(&prospective).len() + 2 * crate::MAX_RECEIPT + 256 * 1024
                    <= c.limits.capsule_bytes as usize,
                "complete export cannot fit funded carriage profile"
            );
            crate::state::validate_ticket_covers(c, &w.covers)?;
        }
        2 => {
            let a = w
                .cancellation_authorization
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("cancellation authorization"))?;
            crypto::authorize(
                &c.ticket.cancel_policy,
                std::slice::from_ref(a),
                &cancellation_bytes(c),
            )?;
        }
        _ => anyhow::bail!("unknown controller decision"),
    }
    Ok(w.terminal.clone())
}

pub fn encode_receipt(receipt: &Receipt) -> Result<Blob> {
    ensure!(
        matches!(receipt.inner, InnerReceipt::Succinct(_)),
        "succinct required"
    );
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(receipt)?;
    ensure!(
        bytes.len() <= crate::MAX_RECEIPT,
        "receipt exceeds monetary profile"
    );
    Ok(Blob(bytes))
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    minicbor::Encode,
    minicbor::Decode,
)]
pub enum NativeInput {
    #[n(0)]
    Execution(#[n(0)] NativeWitness),
    #[n(1)]
    Admission(#[n(0)] AdmissionWitness),
}
