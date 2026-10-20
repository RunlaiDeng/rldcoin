use crate::{
    codec::{Id, hash, tagged},
    model::*,
};
use anyhow::{Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};

pub fn profile_id() -> Id {
    Id::digest(b"Argon2id/v19/m65536/t3/p1/out32/target(2^240-1)/Mint1/ClaimSlots")
}
pub fn mint_bytes(c: Id, w: &Work) -> Vec<u8> {
    tagged(
        "RLD-MINT",
        c,
        &(
            w.grant, w.slot, w.home, w.anchor, &w.payout, w.cover, w.nonce,
        ),
    )
}
pub fn claim_bytes(c: Id, w: &PlacementWork) -> Vec<u8> {
    tagged(
        "RLD-CLAIM",
        c,
        &(
            w.range.grant,
            w.range.lo,
            w.range.hi,
            w.source,
            w.destination,
            w.coupon,
            &w.claimant,
            w.range.cover,
            w.nonce,
        ),
    )
}
pub fn evaluate(c: Id, z: &[u8]) -> Result<[u8; 32]> {
    let p = hash("RLD-WORK-PASSWORD", c, &crate::codec::Blob(z.to_vec()));
    let salt = hash("RLD-WORK-SALT", c, &crate::codec::Blob(z.to_vec()));
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0; 32];
    a.hash_password_into(&p.0, &salt.0[..16], &mut out)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(out)
}
pub fn meets(hash: [u8; 32], weight: u32) -> bool {
    if weight == 0 || weight > 256 {
        return false;
    }
    let mut target = [255u8; 32];
    target[0] = 0;
    target[1] = 0;
    let mut carry = 0u32;
    for b in &mut target {
        let v = (carry << 8) | *b as u32;
        *b = (v / weight) as u8;
        carry = v % weight;
    }
    hash <= target
}
pub fn verify_mint(c: Id, w: &Work) -> Result<()> {
    w.payout.validate()?;
    ensure!(
        w.payout.threshold == 1 && w.payout.keys == vec![w.signature.key],
        "Mint author/payout binding"
    );
    let z = mint_bytes(c, w);
    crate::crypto::verify_signature(&w.signature, &z)?;
    ensure!(meets(evaluate(c, &z)?, 1), "insufficient Mint work");
    Ok(())
}
pub fn verify_claim(c: Id, w: &PlacementWork) -> Result<()> {
    let n = w
        .range
        .hi
        .checked_sub(w.range.lo)
        .ok_or_else(|| anyhow::anyhow!("range order"))?;
    ensure!((1..=256).contains(&n), "claim size");
    let z = claim_bytes(c, w);
    crate::crypto::authorize(&w.claimant, std::slice::from_ref(&w.authorization), &z)?;
    ensure!(meets(evaluate(c, &z)?, n), "insufficient placement work");
    Ok(())
}
