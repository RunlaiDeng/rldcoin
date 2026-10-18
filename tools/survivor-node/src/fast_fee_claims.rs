//! Prospective verification component only. No native funding, principal-state
//! validity, custody, freshness, ledger mutation or payout authority is granted.
use crate::kernel::{valid_point, verify, Hash, Result, CAP};
use sha2::{Digest, Sha256};

fn require(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn number(bytes: &[u8]) -> u128 {
    u128::from_be_bytes(bytes.try_into().unwrap())
}
fn counter(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}

/// Canonical prospective terms, not a proof that any escrow exists.
pub struct Contract {
    bytes: Vec<u8>,
    commitment: Hash,
    chain: Hash,
    funding: Hash,
    owners: [Hash; 2],
    principal: u128,
    limits: [u64; 2],
    rates: [u128; 2],
    reserved: [u128; 2],
}
impl Contract {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        require(
            raw.len() == 228,
            "INVALID_ENCODING prospective fee context size",
        )?;
        require(
            raw[..4] == [0, 1, 0, 1],
            "UNSUPPORTED_VERSION prospective fee context",
        )?;
        let chain = raw[4..36].try_into().unwrap();
        let funding = raw[36..68].try_into().unwrap();
        let owners = [
            raw[68..100].try_into().unwrap(),
            raw[100..132].try_into().unwrap(),
        ];
        let miner = raw[132..164].try_into().unwrap();
        require(
            owners[0] != owners[1] && owners.iter().copied().all(valid_point) && valid_point(miner),
            "INVALID_CRYPTO prospective fee keys",
        )?;
        let principal = number(&raw[164..180]);
        let limits = [counter(&raw[180..188]), counter(&raw[204..212])];
        let rates = [number(&raw[188..204]), number(&raw[212..228])];
        require(
            principal > 0
                && principal <= CAP
                && limits.iter().all(|n| *n > 0)
                && rates.iter().all(|f| *f > 0 && *f <= CAP),
            "INVALID_VALUE prospective fee terms",
        )?;
        let mut reserved = [0; 2];
        let mut total = principal;
        for i in 0..2 {
            reserved[i] = rates[i]
                .checked_mul(limits[i] as u128)
                .ok_or("INVALID_VALUE fee reserve overflow")?;
            total = total
                .checked_add(reserved[i])
                .ok_or("INVALID_VALUE fee reserve overflow")?;
            require(total <= CAP, "INVALID_VALUE fee reserve cap")?;
        }
        let mut hash = Sha256::new();
        hash.update(b"RLD-FAST-FEE-CLAIM-1/CONTEXT\0");
        hash.update(raw);
        Ok(Self {
            bytes: raw.to_vec(),
            commitment: hash.finalize().into(),
            chain,
            funding,
            owners,
            principal,
            limits,
            rates,
            reserved,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn commitment(&self) -> Hash {
        self.commitment
    }
    /// Authenticate an owner-authorized range statement, never the underlying
    /// funding, complete payment transition, receipt or selected-history status.
    pub fn verify(&self, raw: &[u8]) -> Result<Claim> {
        require(raw.len() == 252, "INVALID_ENCODING fee certificate size")?;
        require(
            raw[..4] == [0, 1, 0, 1],
            "UNSUPPORTED_VERSION fee certificate",
        )?;
        require(
            raw[4..36] == self.chain && raw[36..68] == self.funding,
            "WRONG_CHAIN fee certificate context",
        )?;
        let balances = [number(&raw[76..92]), number(&raw[92..108])];
        require(
            balances[0].checked_add(balances[1]) == Some(self.principal),
            "INVALID_VALUE fee certificate principal",
        )?;
        let slots = [counter(&raw[108..116]), counter(&raw[116..124])];
        require(
            (0..2).all(|i| slots[i] <= self.limits[i]),
            "INVALID_VALUE fee certificate slot bound",
        )?;
        let mut message = b"RLD-FAST-FEE-CLAIM-1/STATE\0".to_vec();
        message.extend(self.commitment);
        message.extend(&raw[..124]);
        verify(self.owners[0], &message, &raw[124..188])?;
        verify(self.owners[1], &message, &raw[188..252])?;
        Ok(Claim {
            sequence: counter(&raw[68..76]),
            balances,
            slots,
        })
    }
}

/// Signatures prove these statements under one supplied context. They do not
/// prove that the context is funded, current or an enforceable channel state.
#[derive(Debug, PartialEq, Eq)]
pub struct Claim {
    pub sequence: u64,
    pub balances: [u128; 2],
    pub slots: [u64; 2],
}

#[derive(Debug, PartialEq, Eq)]
pub struct NumericalAccounting {
    pub principal: u128,
    pub reserved: [u128; 2],
    pub fee_ranges: [u128; 2],
    pub unused: [u128; 2],
}

/// Bounded process-local numerical component, not a serialized/native ledger.
/// Each maximum retains one complete authenticated supporting certificate.
pub struct FeeFloors {
    contract: Contract,
    slots: [u64; 2],
    proofs: [Option<Vec<u8>>; 2],
}
impl FeeFloors {
    pub fn new(contract: Contract) -> Self {
        Self {
            contract,
            slots: [0; 2],
            proofs: [None, None],
        }
    }
    pub fn observe(&mut self, raw: &[u8]) -> Result<()> {
        let claim = self.contract.verify(raw)?;
        // All fallible authentication/arithmetic is complete before mutation.
        // Principal sequence never overrides a fee entitlement.
        for i in 0..2 {
            if claim.slots[i] > self.slots[i] {
                self.slots[i] = claim.slots[i];
                self.proofs[i] = Some(raw.to_vec());
            }
        }
        Ok(())
    }
    pub fn slots(&self) -> [u64; 2] {
        self.slots
    }
    pub fn proofs(&self) -> [Option<&[u8]>; 2] {
        [self.proofs[0].as_deref(), self.proofs[1].as_deref()]
    }
    pub fn accounting(&self) -> NumericalAccounting {
        // Terms are checked, and each authenticated range is <= its signed limit.
        let fee_ranges = [
            self.slots[0] as u128 * self.contract.rates[0],
            self.slots[1] as u128 * self.contract.rates[1],
        ];
        NumericalAccounting {
            principal: self.contract.principal,
            reserved: self.contract.reserved,
            fee_ranges,
            unused: [
                self.contract.reserved[0] - fee_ranges[0],
                self.contract.reserved[1] - fee_ranges[1],
            ],
        }
    }
}
