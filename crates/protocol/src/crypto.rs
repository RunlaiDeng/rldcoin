use crate::{
    codec::{Id, hash, sorted_unique, tagged},
    model::*,
};
use anyhow::{Result, ensure};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};

pub fn validate_public_key(id: Id) -> Result<()> {
    let key = VerifyingKey::from_bytes(&id.0)?;
    ensure!(!key.is_weak(), "weak Ed25519 key");
    Ok(())
}
pub fn verify_signature(signature: &Signature, message: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(&signature.key.0)?;
    let sig = EdSignature::from_slice(&signature.bytes.0)?;
    key.verify_strict(message, &sig)?;
    Ok(())
}
pub fn authorize_use(policy: &Owner, all: &[Authorization], message: &[u8]) -> Result<()> {
    if is_public_policy(policy) {
        Ok(())
    } else {
        authorize(policy, all, message)
    }
}
pub fn authorize(policy: &Owner, all: &[Authorization], message: &[u8]) -> Result<()> {
    policy.validate()?;
    let auth = all
        .iter()
        .find(|a| a.owner == *policy)
        .ok_or_else(|| anyhow::anyhow!("missing owner authorization"))?;
    ensure!(
        auth.signatures.len() <= policy.keys.len()
            && auth.signatures.windows(2).all(|w| w[0].key < w[1].key),
        "duplicate/unsorted owner signatures"
    );
    for sig in &auth.signatures {
        ensure!(policy.keys.contains(&sig.key), "foreign owner key");
        verify_signature(sig, message)?;
    }
    ensure!(
        auth.signatures.len() >= policy.threshold as usize,
        "owner threshold"
    );
    Ok(())
}
pub fn identity_attestations(
    config: &Configuration,
    signatures: &[Signature],
    message: &[u8],
) -> Result<()> {
    let q = config.quorum()?;
    ensure!(
        signatures.len() >= q
            && signatures.len() <= config.validators.len()
            && signatures.windows(2).all(|w| w[0].key < w[1].key),
        "configuration attestations"
    );
    for s in signatures {
        ensure!(
            config.validators.iter().any(|v| v.identity == s.key),
            "unknown identity attestation"
        );
        verify_signature(s, message)?;
    }
    Ok(())
}
pub fn key_leaf(config: &Configuration, validator: Id, pool: bool, index: u32, key: Id) -> Id {
    hash(
        if pool {
            "RLD-CONTROLLER-KEY"
        } else {
            "RLD-NATIVE-KEY"
        },
        config.currency,
        &(
            config.domain,
            validator,
            if pool {
                config.pool_epoch
            } else {
                config.epoch
            },
            index,
            key,
        ),
    )
}
pub fn key_node(c: Id, a: Id, b: Id) -> Id {
    hash("RLD-KEY-NODE", c, &(a, b))
}
pub fn verify_leaf(config: &Configuration, leaf: &KeyLeaf, pool: bool, index: u32) -> Result<()> {
    ensure!(
        index < crate::KEY_COUNT && leaf.path.len() == 16,
        "key path bound"
    );
    let v = config
        .validators
        .iter()
        .find(|v| v.identity == leaf.validator)
        .ok_or_else(|| anyhow::anyhow!("validator identity"))?;
    let mut digest = key_leaf(config, leaf.validator, pool, index, leaf.key);
    let mut pos = index;
    for sibling in &leaf.path {
        digest = if pos & 1 == 0 {
            key_node(config.currency, digest, *sibling)
        } else {
            key_node(config.currency, *sibling, digest)
        };
        pos >>= 1;
    }
    ensure!(
        digest
            == if pool {
                v.controller_root
            } else {
                v.native_root
            },
        "key membership"
    );
    Ok(())
}
pub fn vote_bytes(v: &Vote) -> Vec<u8> {
    tagged(
        "RLD-PBFT-VOTE",
        v.currency,
        &(
            v.namespace,
            v.configuration,
            v.sequence,
            v.view,
            v.phase,
            v.statement,
            v.validator,
            &v.key,
        ),
    )
}
pub fn verify_vote(
    config: &Configuration,
    namespace: Id,
    pool_index: Option<u32>,
    v: &Vote,
) -> Result<()> {
    ensure!(
        v.currency == config.currency
            && v.configuration == config.id()
            && v.namespace == namespace
            && v.validator == v.key.validator
            && v.signature.key == v.key.key,
        "vote binding"
    );
    let offset = match pool_index {
        Some(i) => {
            ensure!(v.sequence == 0, "controller sequence");
            i
        }
        None => {
            let n = v
                .sequence
                .checked_sub(config.first_sequence)
                .ok_or_else(|| anyhow::anyhow!("epoch sequence"))?;
            u32::try_from(n)?
        }
    };
    verify_leaf(config, &v.key, pool_index.is_some(), offset)?;
    ensure!((1..=5).contains(&v.phase), "vote phase");
    verify_signature(&v.signature, &vote_bytes(v))
}
pub fn verify_quorum(
    config: &Configuration,
    namespace: Id,
    pool: Option<u32>,
    qc: &Quorum,
    phase: u8,
    statement: Id,
) -> Result<()> {
    ensure!(
        qc.votes.len() >= config.quorum()?
            && qc.votes.len() <= config.validators.len()
            && qc.votes.windows(2).all(|w| w[0].validator < w[1].validator),
        "quorum membership/count"
    );
    let first = qc
        .votes
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty QC"))?;
    for v in &qc.votes {
        ensure!(
            v.phase == phase
                && v.statement == statement
                && v.sequence == first.sequence
                && v.view == first.view,
            "mixed QC intent"
        );
        verify_vote(config, namespace, pool, v)?;
    }
    Ok(())
}
pub fn validate_inventory(
    config: &Configuration,
    validator: Id,
    pool: bool,
    keys: &[Id],
) -> Result<Id> {
    ensure!(
        keys.len() == crate::KEY_COUNT as usize,
        "public inventory size"
    );
    validate_public_key(validator)?;
    for k in keys {
        validate_public_key(*k)?;
    }
    let mut unique = keys.to_vec();
    unique.sort();
    ensure!(sorted_unique(&unique), "duplicate pool keys");
    let mut level: Vec<Id> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| key_leaf(config, validator, pool, i as u32, *k))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|p| key_node(config.currency, p[0], p[1]))
            .collect();
    }
    Ok(level[0])
}
