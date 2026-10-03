//! A candidate monitor whose challenge action needs no private signing key.
//! Its separate acknowledgment key cannot spend channel value.
//! A package is useful only against the exact selected candidate chain; it
//! cannot turn a local model receipt into live RLD.

use crate::{
    chain::{CandidateChain, CandidateEscrowObservation, Command},
    hash, signed_state_hash, ActionFee, DisputeAction, Result,
};
use rld_core::{sign_bytes, verify_bytes, AdmissionHash32 as Hash};
use rld_fast_payments::{successor::Escrow, Funding, PaymentReceipt, Phase, SignedState};
use serde::{Deserialize, Serialize};

pub mod storage;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WatchPackage {
    pub funding: Funding,
    pub state: SignedState,
    pub fee: ActionFee,
}

pub const CANDIDATE_STATUS: &str = "UNADOPTED_LOCAL_CANDIDATE_ONLY";
pub const EARTH_STATUS: &str = "ADOPTED_EARTH_SUCCESSOR_V1";

/// Proof that this exact package was saved by a separately identified watcher.
/// Its signature cannot make unadopted candidate value live RLD.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WatchAck {
    pub status: String,
    pub live_rld: bool,
    pub chain_id: Hash,
    pub channel: Hash,
    pub sequence: u64,
    pub package_hash: Hash,
    pub watcher: String,
    pub signature: String,
}

impl WatchAck {
    fn package_hash(package: &WatchPackage) -> Result<Hash> {
        package.validate()?;
        let mut bytes = b"RLD-EARTH-WATCH-PACKAGE\0".to_vec();
        bytes.extend(serde_json::to_vec(package).map_err(|error| error.to_string())?);
        Ok(hash(&bytes))
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = if self.live_rld {
            b"RLD-EARTH-WATCH-ACK\0".to_vec()
        } else {
            b"RLD-LOCAL-WATCH-ACK\0".to_vec()
        };
        bytes.extend(self.chain_id.0);
        bytes.extend(self.channel.0);
        bytes.extend(self.sequence.to_be_bytes());
        bytes.extend(self.package_hash.0);
        bytes
    }

    /// Call only after the watcher's own store has durably accepted `package`.
    pub fn sign_saved(
        package: &WatchPackage,
        watcher_public: &str,
        watcher_secret: &str,
    ) -> Result<Self> {
        Self::sign_saved_for_mode(package, watcher_public, watcher_secret, false)
    }

    pub fn sign_saved_for_mode(
        package: &WatchPackage,
        watcher_public: &str,
        watcher_secret: &str,
        adopted: bool,
    ) -> Result<Self> {
        let mut ack = Self {
            status: if adopted {
                EARTH_STATUS
            } else {
                CANDIDATE_STATUS
            }
            .into(),
            live_rld: adopted,
            chain_id: package.funding.chain_id,
            channel: package.validate()?,
            sequence: package.state.state.sequence,
            package_hash: Self::package_hash(package)?,
            watcher: watcher_public.into(),
            signature: String::new(),
        };
        ack.signature = sign_bytes(watcher_secret, &ack.signing_bytes())?;
        ack.verify(package, watcher_public)?;
        Ok(ack)
    }

    pub fn verify(&self, package: &WatchPackage, expected_watcher: &str) -> Result<()> {
        if self.status
            != (if self.live_rld {
                EARTH_STATUS
            } else {
                CANDIDATE_STATUS
            })
            || self.chain_id != package.funding.chain_id
            || self.channel != package.validate()?
            || self.sequence != package.state.state.sequence
            || self.package_hash != Self::package_hash(package)?
            || self.watcher != expected_watcher
        {
            return Err("watch acknowledgment does not bind the saved package".into());
        }
        verify_bytes(&self.watcher, &self.signing_bytes(), &self.signature)
    }
}

/// The complete candidate delivery a payer needs to verify without access to
/// either the merchant wallet or the watcher's local files.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WatchedReceipt {
    pub status: String,
    pub live_rld: bool,
    pub receipt: PaymentReceipt,
    pub watch_package: WatchPackage,
    pub watch_ack: WatchAck,
}

impl WatchedReceipt {
    pub fn verify(
        &self,
        funding: &Funding,
        expected_payer: &str,
        expected_watcher: &str,
    ) -> Result<()> {
        if self.status
            != (if self.live_rld {
                EARTH_STATUS
            } else {
                CANDIDATE_STATUS
            })
            || self.status != self.watch_ack.status
            || self.live_rld != self.watch_ack.live_rld
            || self.watch_package.funding != *funding
            || self.watch_package.state != self.receipt.updated
            || self.receipt.sender != expected_payer
        {
            return Err("candidate delivery does not bind the payment".into());
        }
        let receiver = if expected_payer == funding.party_a {
            &funding.party_b
        } else if expected_payer == funding.party_b {
            &funding.party_a
        } else {
            return Err("candidate payer is not a channel party".into());
        };
        if self.watch_package.fee.intent.owner != *receiver {
            return Err("watch package fee is not owned by the receiver".into());
        }
        self.receipt.verify(funding, receiver)?;
        self.watch_ack.verify(&self.watch_package, expected_watcher)
    }

    /// Point-in-time check against the payer's own replayed candidate branch.
    /// This cannot reserve a fee coin or make the candidate escrow live RLD.
    pub fn verify_on_chain(
        &self,
        funding: &Funding,
        expected_payer: &str,
        expected_watcher: &str,
        chain: &CandidateChain,
    ) -> Result<()> {
        self.verify(funding, expected_payer, expected_watcher)?;
        let fee = &self.watch_package.fee.intent;
        let input_amount = fee
            .fee
            .checked_add(fee.change)
            .map_err(|error| error.to_string())?;
        CandidateEscrowObservation::new(chain, 2)?.verify_payment_readiness(
            funding,
            &fee.owner,
            &fee.input,
            input_amount,
            fee.fee,
            fee.valid_through_height,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchDecision {
    FundingMissing,
    WaitingForClose,
    CurrentOrNewer,
    Challenge(Box<Command>),
    ContestExpired,
    FeeExpired,
    Settled,
}

impl WatchPackage {
    pub fn validate(&self) -> Result<Hash> {
        let channel = self.funding.id()?;
        self.state.verify(&self.funding)?;
        let intent = &self.fee.intent;
        if intent.chain_id != self.funding.chain_id
            || intent.action != DisputeAction::Challenge
            || intent.channel != channel
            || intent.signed_state != signed_state_hash(&self.state)?
        {
            return Err("watch package fee does not bind the challenge".into());
        }
        verify_bytes(
            &intent.owner,
            &intent.signing_bytes()?,
            &self.fee.owner_signature,
        )?;
        Ok(channel)
    }

    /// Evaluate one coherent selected-chain observation. The caller must
    /// recheck the branch and retry after a reorganization or failed submit.
    pub fn decide(
        &self,
        chain_id: Hash,
        height: u128,
        escrow: Option<&Escrow>,
    ) -> Result<WatchDecision> {
        let channel = self.validate()?;
        if chain_id != self.funding.chain_id {
            return Err("watch package belongs to another chain".into());
        }
        let Some(escrow) = escrow else {
            return Ok(WatchDecision::FundingMissing);
        };
        if escrow.funding != self.funding || escrow.opened_height > height {
            return Err("watch observation does not match confirmed funding".into());
        }
        escrow.initial.verify(&self.funding)?;
        match &escrow.phase {
            Phase::Open => Ok(WatchDecision::WaitingForClose),
            Phase::Settled => Ok(WatchDecision::Settled),
            Phase::Closing {
                best,
                close_height,
                deadline_height,
            } => {
                best.verify(&self.funding)?;
                if *close_height <= escrow.opened_height || *close_height > height {
                    return Err("watch observation has inconsistent close height".into());
                }
                if best.state.sequence >= self.state.state.sequence {
                    return Ok(WatchDecision::CurrentOrNewer);
                }
                let next_height = height
                    .checked_add(1)
                    .ok_or("watch observation height overflow")?;
                if next_height > *deadline_height {
                    return Ok(WatchDecision::ContestExpired);
                }
                if next_height > self.fee.intent.valid_through_height {
                    return Ok(WatchDecision::FeeExpired);
                }
                Ok(WatchDecision::Challenge(Box::new(Command::Challenge {
                    channel,
                    state: self.state.clone(),
                    fee: self.fee.clone(),
                })))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionFeeIntent, DisputeAction};
    use rld_core::{generate_identity, sign_bytes, Amount};
    use rld_fast_payments::{ChannelState, FundingOutpoint, PaymentReceipt};
    use rld_pow::OutPoint;

    #[test]
    fn only_newer_signed_state_with_valid_challenge_fee_is_submitted() {
        let a = generate_identity();
        let b = generate_identity();
        let funding = Funding {
            chain_id: Hash([1; 32]),
            outpoint: FundingOutpoint {
                transaction: Hash([2; 32]),
                index: 0,
            },
            party_a: a.public_key.clone(),
            party_b: b.public_key.clone(),
            capacity: Amount(1_000),
            close_fee: Amount(1),
        };
        let signed = |state: ChannelState| {
            let bytes = state.signing_bytes(&funding).unwrap();
            SignedState {
                state,
                signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
                signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
            }
        };
        let old = signed(ChannelState::initial(&funding).unwrap());
        let latest = signed(
            old.state
                .propose_payment(&funding, &a.public_key, Amount(10), Hash([3; 32]))
                .unwrap(),
        );
        let fee_intent = ActionFeeIntent {
            chain_id: funding.chain_id,
            action: DisputeAction::Challenge,
            channel: funding.id().unwrap(),
            signed_state: signed_state_hash(&latest).unwrap(),
            input: OutPoint {
                transaction: Hash([4; 32]),
                index: 0,
            },
            owner: b.public_key.clone(),
            fee: Amount(1),
            change: Amount(9),
            valid_through_height: 20,
        };
        let package = WatchPackage {
            funding: funding.clone(),
            state: latest.clone(),
            fee: ActionFee {
                owner_signature: sign_bytes(&b.secret_key, &fee_intent.signing_bytes().unwrap())
                    .unwrap(),
                intent: fee_intent,
            },
        };
        package.validate().unwrap();
        let watcher = generate_identity();
        let ack = WatchAck::sign_saved(&package, &watcher.public_key, &watcher.secret_key).unwrap();
        ack.verify(&package, &watcher.public_key).unwrap();
        assert!(ack.verify(&package, &a.public_key).is_err());
        let mut changed_ack = ack.clone();
        changed_ack.sequence += 1;
        assert!(changed_ack.verify(&package, &watcher.public_key).is_err());
        let delivered = WatchedReceipt {
            status: CANDIDATE_STATUS.into(),
            live_rld: false,
            receipt: PaymentReceipt {
                previous: old.clone(),
                updated: latest.clone(),
                sender: a.public_key.clone(),
                amount: Amount(10),
                payment_id: Hash([3; 32]),
            },
            watch_package: package.clone(),
            watch_ack: ack.clone(),
        };
        delivered
            .verify(&funding, &a.public_key, &watcher.public_key)
            .unwrap();
        let adopted_ack =
            WatchAck::sign_saved_for_mode(&package, &watcher.public_key, &watcher.secret_key, true)
                .unwrap();
        let mut adopted_delivery = delivered.clone();
        adopted_delivery.status = EARTH_STATUS.into();
        adopted_delivery.live_rld = true;
        adopted_delivery.watch_ack = adopted_ack.clone();
        adopted_delivery
            .verify(&funding, &a.public_key, &watcher.public_key)
            .unwrap();
        let mut relabeled_candidate = delivered.clone();
        relabeled_candidate.status = EARTH_STATUS.into();
        relabeled_candidate.live_rld = true;
        assert!(relabeled_candidate
            .verify(&funding, &a.public_key, &watcher.public_key)
            .is_err());
        let mut relabeled_ack = adopted_ack;
        relabeled_ack.live_rld = false;
        relabeled_ack.status = CANDIDATE_STATUS.into();
        assert!(relabeled_ack.verify(&package, &watcher.public_key).is_err());
        let mut forged_delivery = delivered.clone();
        forged_delivery.watch_ack.signature = "00".into();
        assert!(forged_delivery
            .verify(&funding, &a.public_key, &watcher.public_key)
            .is_err());
        let mut wrong_package = delivered.clone();
        wrong_package.watch_package.state = old.clone();
        assert!(wrong_package
            .verify(&funding, &a.public_key, &watcher.public_key)
            .is_err());
        assert!(delivered
            .verify(&funding, &a.public_key, &b.public_key)
            .is_err());
        let mut escrow = Escrow {
            funding,
            initial: old.clone(),
            opened_height: 10,
            phase: Phase::Open,
        };
        assert_eq!(
            package.decide(Hash([1; 32]), 11, Some(&escrow)).unwrap(),
            WatchDecision::WaitingForClose
        );
        escrow.phase = Phase::Closing {
            best: old,
            close_height: 12,
            deadline_height: 15,
        };
        let mut forged = escrow.clone();
        if let Phase::Closing { best, .. } = &mut forged.phase {
            best.signature_a = "00".into();
        }
        assert!(package.decide(Hash([1; 32]), 12, Some(&forged)).is_err());
        let WatchDecision::Challenge(command) =
            package.decide(Hash([1; 32]), 12, Some(&escrow)).unwrap()
        else {
            panic!("newer state needs challenge");
        };
        assert!(
            matches!(*command, Command::Challenge { channel, state, fee }
            if channel == package.funding.id().unwrap() && state == latest && fee == package.fee)
        );
        assert_eq!(
            package.decide(Hash([1; 32]), 15, Some(&escrow)).unwrap(),
            WatchDecision::ContestExpired
        );
        escrow.phase = Phase::Closing {
            best: latest,
            close_height: 12,
            deadline_height: 15,
        };
        assert_eq!(
            package.decide(Hash([1; 32]), 13, Some(&escrow)).unwrap(),
            WatchDecision::CurrentOrNewer
        );
        let mut wrong = package.clone();
        wrong.fee.intent.action = DisputeAction::Close;
        assert!(wrong.validate().is_err());
        wrong = package.clone();
        wrong.fee.owner_signature = "00".into();
        assert!(wrong.validate().is_err());
        assert!(package.decide(Hash([9; 32]), 13, Some(&escrow)).is_err());
    }
}
