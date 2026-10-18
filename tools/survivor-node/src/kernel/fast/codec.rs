use super::*;

#[derive(Clone)]
pub(super) struct Open {
    pub owners: [Hash; 2],
    pub principal: [u128; 2],
    pub limits: [u64; 2],
    pub rates: [u128; 2],
    pub fees: [u128; 2],
    pub change: [u128; 2],
    pub expiry: u128,
    pub inputs: [Vec<Vec<u8>>; 2],
}
pub(super) struct Action {
    pub kind: u8,
    pub channel: Hash,
    pub actor: Hash,
    pub fee: u128,
    pub change: u128,
    pub expiry: u128,
    pub inputs: Vec<Vec<u8>>,
    pub certificate: Vec<u8>,
}
pub(super) enum Operation {
    Ordinary(Tx),
    Open(Open),
    Action(Action),
}
fn inputs(r: &mut Reader<'_>) -> Result<Vec<Vec<u8>>> {
    let n = r.u16()?;
    require((1..=32).contains(&n), "INVALID fast input count")?;
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(r.take(34)?.to_vec());
    }
    require(
        v.windows(2).all(|w| w[0] < w[1]),
        "INVALID fast input ordering",
    )?;
    Ok(v)
}
pub(super) fn decode(raw: &[u8], chain: Hash) -> Result<Operation> {
    require(
        (1..=4096).contains(&raw.len()),
        "INVALID fast operation length",
    )?;
    if raw[0] == 0 {
        return Ok(Operation::Ordinary(decode_tx(&raw[1..], chain)?));
    }
    let kind = raw[0];
    require((1..=5).contains(&kind), "UNSUPPORTED fast operation")?;
    let signature_bytes = if kind == 1 { 128 } else { 64 };
    require(
        raw.len() > signature_bytes + 1,
        "INVALID fast operation signatures",
    )?;
    let unsigned = &raw[1..raw.len() - signature_bytes];
    let signatures = &raw[raw.len() - signature_bytes..];
    let mut r = Reader::new(unsigned);
    require(
        r.u16()? == 1 && r.u16()? == 1,
        "UNSUPPORTED fast operation version/suite",
    )?;
    require(r.fixed::<32>()? == chain, "INVALID fast operation chain")?;
    require(r.fixed::<32>()? != [0; 32], "INVALID fast operation nonce")?;
    if kind == 1 {
        let owners = [r.fixed()?, r.fixed()?];
        require(
            owners[0] < owners[1] && owners.iter().copied().all(valid_point),
            "INVALID fast owners",
        )?;
        let principal = [r.u128()?, r.u128()?];
        let p = principal[0]
            .checked_add(principal[1])
            .ok_or("INVALID fast principal overflow")?;
        require(p > 0 && p <= CAP, "INVALID fast principal")?;
        let (na, fa, nb, fb) = (r.u64()?, r.u128()?, r.u64()?, r.u128()?);
        let limits = [na, nb];
        let rates = [fa, fb];
        require(
            limits.iter().all(|n| (1..=MAX_SLOTS).contains(n))
                && rates.iter().all(|f| *f > 0 && *f <= CAP),
            "INVALID fast fee terms",
        )?;
        let fees = [r.u128()?, r.u128()?];
        let change = [r.u128()?, r.u128()?];
        let expiry = r.u128()?;
        let inputs = [inputs(&mut r)?, inputs(&mut r)?];
        r.end()?;
        require(
            !inputs[0].iter().any(|x| inputs[1].contains(x)),
            "INVALID fast overlapping inputs",
        )?;
        let budget = na as u128 + nb as u128 + 2;
        require(
            fees.iter().all(|f| *f > 0 && *f <= CAP)
                && change.iter().all(|v| *v >= budget && *v <= CAP),
            "INVALID fast operation fee/exit budget",
        )?;
        let mut total = p;
        for i in 0..2 {
            total = total
                .checked_add(
                    rates[i]
                        .checked_mul(limits[i] as u128)
                        .ok_or("INVALID fast reserve overflow")?,
                )
                .ok_or("INVALID fast reserve overflow")?;
        }
        require(total <= CAP, "INVALID fast reserve cap")?;
        let message = [ftag("OPEN"), unsigned.to_vec()].concat();
        verify(owners[0], &message, &signatures[..64])?;
        verify(owners[1], &message, &signatures[64..])?;
        Ok(Operation::Open(Open {
            owners,
            principal,
            limits,
            rates,
            fees,
            change,
            expiry,
            inputs,
        }))
    } else {
        let channel = r.fixed()?;
        let actor = r.fixed()?;
        require(valid_point(actor), "INVALID fast actor")?;
        let fee = r.u128()?;
        let change = r.u128()?;
        let expiry = r.u128()?;
        require(
            fee > 0 && fee <= CAP && change <= CAP,
            "INVALID fast action fee",
        )?;
        let inputs = inputs(&mut r)?;
        let n = r.u16()? as usize;
        require(
            match kind {
                2 => n == 0 || n == 252,
                3 | 4 => n == 252,
                5 => n == 0,
                _ => false,
            },
            "INVALID fast certificate length",
        )?;
        let certificate = r.take(n)?.to_vec();
        r.end()?;
        verify(
            actor,
            &[ftag("ACTION"), vec![kind], unsigned.to_vec()].concat(),
            signatures,
        )?;
        Ok(Operation::Action(Action {
            kind,
            channel,
            actor,
            fee,
            change,
            expiry,
            inputs,
            certificate,
        }))
    }
}
