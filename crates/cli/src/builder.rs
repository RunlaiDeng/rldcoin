//! Offline construction against a fully replayed native store. Construction
//! never signs, reserves inputs, or substitutes for native validation.
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Amount, Blob, Id, encode, hash, sorted_unique},
    merkle,
    model::*,
    state::{State, sum},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fees {
    pub mint_event: Id,
    pub service: Amount,
    pub work_author: Amount,
    pub archive: Amount,
    pub archive_horizon: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    LocalPayment {
        inputs: Vec<Id>,
        cover: Id,
        recipient: Owner,
        amount: Amount,
        change: Owner,
        fees: Fees,
    },
    PreparePayment {
        inputs: Vec<Id>,
        cover: Id,
        creator: Owner,
        amount: Amount,
        change: Owner,
        fees: Fees,
        destination_fee: Amount,
        cancel_fee: Amount,
        recovery_fee: Amount,
        cancel_fee_payout: Owner,
        recovery_fee_payout: Owner,
        coupon: CouponEvidence,
        inventories: Vec<PublicInventory>,
    },
    PrepareClaim {
        creator: Owner,
        coupon: CouponEvidence,
        work: PlacementWork,
        inventories: Vec<PublicInventory>,
    },
    FundService {
        inputs: Vec<Id>,
        cover: Id,
        change: Owner,
        owner: Owner,
        beneficiary: Id,
        family: Id,
        amount: Amount,
        capacity: u64,
        renewal_payer: Owner,
        custodians: Owner,
        horizon: u64,
        fee_policy: Id,
    },
    Family {
        source: Id,
        issuer: Owner,
        family_nonce: Id,
        funding: Funding,
        source_funding: Funding,
        coupons: Vec<Coupon>,
        covers: Vec<Cover>,
    },
    // Full protocol commands cover renewal, handoff, rejection/recovery,
    // retirement and explicit closure without a permissive RPC signing API.
    NativeCommand {
        command: Command,
        covers: Vec<Cover>,
    },
}
fn allocation(owner: Owner, cover: Id, amount: Amount) -> Allocation {
    Allocation {
        owner,
        components: if amount.0 == 0 {
            vec![]
        } else {
            vec![Component { cover, amount }]
        },
    }
}
fn selected(s: &State, ids: &[Id], cover: Id) -> Result<Amount> {
    ensure!(
        !ids.is_empty() && ids.len() <= 64 && sorted_unique(ids),
        "ordered unique actual input IDs required"
    );
    ids.iter().try_fold(Amount(0), |total, id| {
        let out = s.outputs.get(*id)?.context("input not locally available")?;
        ensure!(
            out.components.len() == 1 && out.components[0].cover == cover,
            "builder requires one exact cover; use explicit native command for mixed covers"
        );
        total.add(sum(&out.components)?)
    })
}
fn fees(s: &State, nonce: Id, cover: Id, f: &Fees, p: &FeePolicy) -> Result<Vec<Fee>> {
    ensure!(
        f.service >= p.minimum_service
            && f.work_author >= p.minimum_work_author
            && f.archive >= p.minimum_archive
            && f.archive_horizon > 0,
        "fee policy minima/retention horizon"
    );
    let mint = s
        .mints
        .get(f.mint_event)?
        .context("prior Mint event not retained")?
        .clone();
    let archival = allocation(p.archive_owner.clone(), cover, f.archive);
    Ok(vec![
        Fee {
            kind: 0,
            payout: allocation(p.service_owner.clone(), cover, f.service),
            mint: None,
            reserve: None,
        },
        Fee {
            kind: 1,
            payout: allocation(mint.owner.clone(), cover, f.work_author),
            mint: Some(MintEvidence {
                record: mint,
                certified: None,
                inclusion: None,
            }),
            reserve: None,
        },
        Fee {
            kind: 2,
            payout: archival.clone(),
            mint: None,
            reserve: Some(Service {
                id: hash("RLD-ARCHIVE-RESERVE", s.currency, &(s.domain, nonce)),
                owner: archival.owner,
                beneficiary: s.domain,
                family: Id::ZERO,
                balance: archival.components,
                capacity: 1,
                reserved: 1,
                renewal_payer: p.archive_owner.clone(),
                custodians: p.archive_custodians.clone(),
                horizon: f.archive_horizon,
                fee_policy: p.id(s.currency),
            }),
        },
    ])
}
fn leaves(s: &State, inventories: &[PublicInventory]) -> Result<Vec<KeyLeaf>> {
    let cfg = &s.configuration;
    cfg.validators
        .iter()
        .map(|validator| {
            let inventory = inventories
                .iter()
                .find(|i| i.validator == validator.identity)
                .context("missing public controller inventory")?;
            ensure!(
                rld_protocol::crypto::validate_inventory(
                    cfg,
                    validator.identity,
                    true,
                    &inventory.controller
                )? == validator.controller_root,
                "controller inventory root"
            );
            let mut level: Vec<_> = inventory
                .controller
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    rld_protocol::crypto::key_leaf(cfg, validator.identity, true, i as u32, *k)
                })
                .collect();
            let mut index = s.pool_next as usize;
            ensure!(index < level.len(), "controller pool exhausted");
            let key = inventory.controller[index];
            let mut path = vec![];
            while level.len() > 1 {
                path.push(level[index ^ 1]);
                level = level
                    .chunks_exact(2)
                    .map(|p| rld_protocol::crypto::key_node(s.currency, p[0], p[1]))
                    .collect();
                index /= 2;
            }
            Ok(KeyLeaf {
                validator: validator.identity,
                key,
                path,
            })
        })
        .collect()
}
pub fn family_id(c: Id, source: Id, destination: Id, nonce: Id, issuer: &Owner) -> Id {
    hash(
        "RLD-COUPON-FAMILY-ID",
        c,
        &(source, destination, nonce, issuer),
    )
}
pub fn build(s: &State, nonce: Id, request: Request) -> Result<Operation> {
    let mut covers = Vec::new();
    let command = match request {
        Request::LocalPayment {
            inputs,
            cover,
            recipient,
            amount,
            change,
            fees: f,
        } => {
            let total = selected(s, &inputs, cover)?;
            ensure!(amount.0 > 0, "positive recipient amount");
            let fees = fees(s, nonce, cover, &f, &s.configuration.fee_policy)?;
            let cost = fees
                .iter()
                .try_fold(amount, |n, f| n.add(sum(&f.payout.components)?))?;
            let remainder = total.sub(cost)?;
            let mut outputs = vec![allocation(recipient, cover, amount)];
            if remainder.0 > 0 {
                outputs.push(allocation(change, cover, remainder));
            }
            Command::LocalTransfer {
                inputs,
                outputs,
                fees,
                lifts: vec![],
            }
        }
        Request::PreparePayment {
            inputs,
            cover,
            creator,
            amount,
            change,
            fees: f,
            destination_fee,
            cancel_fee,
            recovery_fee,
            cancel_fee_payout,
            recovery_fee_payout,
            coupon,
            inventories,
        } => {
            let total = selected(s, &inputs, cover)?;
            ensure!(
                amount.0 > 0
                    && amount <= coupon.coupon.max_amount
                    && coupon.coupon.covers.contains(&cover),
                "coupon principal/cover"
            );
            let fees = fees(s, nonce, cover, &f, &coupon.coupon.source_fee_policy)?;
            let cost = fees.iter().try_fold(amount.add(destination_fee)?, |n, f| {
                n.add(sum(&f.payout.components)?)
            })?;
            let remainder = total.sub(cost)?;
            let mut ticket = Ticket {
                id: Id::ZERO,
                coupon: coupon.coupon.id(s.currency),
                source: s.domain,
                destination: coupon.coupon.destination,
                creator,
                kind: 0,
                inputs,
                range: None,
                recipient: allocation(coupon.coupon.recipient.clone(), cover, amount),
                destination_fee: allocation(
                    coupon.coupon.destination_fee_policy.service_owner.clone(),
                    cover,
                    destination_fee,
                ),
                fees,
                change: if remainder.0 > 0 {
                    vec![allocation(change, cover, remainder)]
                } else {
                    vec![]
                },
                lifts: vec![],
                cancel_policy: coupon.coupon.cancel_policy.clone(),
                recovery_policy: coupon.coupon.recovery_policy.clone(),
                cancel_fee,
                recovery_fee,
                nonce,
                cancel_fee_payout,
                recovery_fee_payout,
            };
            ticket.id = ticket.identity(s.currency);
            let definition = s.covers.get(cover)?.context("cover definition")?;
            covers.push(definition.clone());
            let material = Material {
                outputs: vec![ticket.recipient.clone(), ticket.destination_fee.clone()],
                ticket: ticket.clone(),
                coupon: coupon.coupon.clone(),
                covers: vec![definition],
            };
            Command::PreparePayment {
                ticket,
                coupon,
                keys: leaves(s, &inventories)?,
                material: Blob(encode(&material)),
            }
        }
        Request::PrepareClaim {
            creator,
            coupon,
            work,
            inventories,
        } => {
            ensure!(work.claimant == creator, "claim author");
            rld_protocol::work::verify_claim(s.currency, &work)?;
            let mut ticket = Ticket {
                id: Id::ZERO,
                coupon: coupon.coupon.id(s.currency),
                source: s.domain,
                destination: coupon.coupon.destination,
                creator: creator.clone(),
                kind: 1,
                inputs: vec![],
                range: Some(work.range.clone()),
                recipient: allocation(coupon.coupon.recipient.clone(), work.range.cover, Amount(0)),
                destination_fee: allocation(
                    coupon.coupon.destination_fee_policy.service_owner.clone(),
                    work.range.cover,
                    Amount(0),
                ),
                fees: vec![],
                change: vec![],
                lifts: vec![],
                cancel_policy: bound_claim_policy(&coupon.coupon.cancel_policy, &creator, 1),
                recovery_policy: bound_claim_policy(&coupon.coupon.recovery_policy, &creator, 1),
                cancel_fee: Amount(0),
                recovery_fee: Amount(0),
                nonce,
                cancel_fee_payout: creator.clone(),
                recovery_fee_payout: creator,
            };
            ticket.id = ticket.identity(s.currency);
            let definition = s
                .covers
                .get(work.range.cover)?
                .context("cover definition")?;
            covers.push(definition.clone());
            let material = Material {
                ticket: ticket.clone(),
                coupon: coupon.coupon.clone(),
                covers: vec![definition],
                outputs: vec![],
            };
            Command::PrepareClaim {
                ticket,
                coupon,
                work,
                keys: leaves(s, &inventories)?,
                material: Blob(encode(&material)),
            }
        }
        Request::FundService {
            inputs,
            cover,
            change,
            owner,
            beneficiary,
            family,
            amount,
            capacity,
            renewal_payer,
            custodians,
            horizon,
            fee_policy,
        } => {
            let remainder = selected(s, &inputs, cover)?.sub(amount)?;
            ensure!(
                amount.0 > 0 && capacity > 0 && horizon > 0,
                "funded service amount/capacity/horizon"
            );
            Command::FundService {
                inputs,
                change: if remainder.0 > 0 {
                    vec![allocation(change, cover, remainder)]
                } else {
                    vec![]
                },
                service: Service {
                    id: hash("RLD-SERVICE-ID", s.currency, &(s.domain, nonce, &owner)),
                    owner,
                    beneficiary,
                    family,
                    balance: vec![Component { cover, amount }],
                    capacity,
                    reserved: capacity,
                    renewal_payer,
                    custodians,
                    horizon,
                    fee_policy,
                },
            }
        }
        Request::Family {
            source,
            issuer,
            family_nonce,
            funding,
            source_funding,
            mut coupons,
            covers: definitions,
        } => {
            ensure!(
                !coupons.is_empty() && coupons.len() <= 4096,
                "finite coupon inventory"
            );
            let id = family_id(s.currency, source, s.domain, family_nonce, &issuer);
            let cfg = &source_funding.source.configuration;
            for (index, coupon) in coupons.iter_mut().enumerate() {
                coupon.family = id;
                coupon.index = index as u32;
                coupon.source = source;
                coupon.destination = s.domain;
                coupon.source_sponsor = source_funding.service.id;
                coupon.destination_fee_policy = s.configuration.fee_policy.clone();
                coupon.source_family = FamilyRule {
                    family: source,
                    anchor: cfg.initial_anchor,
                    succession: vec![cfg.succession],
                    signatures: vec![cfg.signature_profile],
                    custody: cfg.custody_profile,
                };
            }
            let mut entries: Vec<_> = coupons
                .iter()
                .map(|c| merkle::Entry {
                    key: hash("RLD-COUPON-INDEX", s.currency, &c.index),
                    value: c.digest(s.currency),
                })
                .collect();
            entries.sort_by_key(|e| e.key);
            let family = Family {
                id,
                source,
                destination: s.domain,
                nonce: family_nonce,
                issuer,
                leaf_root: merkle::root(s.currency, &format!("{id}/coupons"), &entries)?,
                count: coupons.len() as u32,
                funding: funding.service.id,
                units: coupons.len() as u64,
                source_funding: source_funding.service.id,
            };
            covers = definitions.clone();
            Command::CreateFamily(FamilyFunding {
                family,
                funding,
                source_funding,
                coupons,
                covers: definitions,
            })
        }
        Request::NativeCommand {
            command,
            covers: definitions,
        } => {
            covers = definitions;
            command
        }
    };
    covers.sort_by_key(|c| c.id(s.currency));
    covers.dedup();
    let op = Operation {
        currency: s.currency,
        home: s.domain,
        nonce,
        command,
        covers,
        authorizations: vec![],
    };
    ensure!(
        encode(&op).len() + 256 * 1024 < rld_protocol::MAX_CAPSULE,
        "complete operation carriage limit"
    );
    Ok(op)
}
