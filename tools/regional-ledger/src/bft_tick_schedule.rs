//! Read-only ordinary tick policy. Caller clocks and plans grant no signing rights.
use crate::{
    bft, bft_phase_schedule as phase, bft_proposal_schedule as proposal, require, storage::Store,
    Hash, Result, Snapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Begin,
    Commit,
    Committed,
    AfterProposal,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposed {
    pub round: u64,
    pub snapshot: Box<Snapshot>,
    pub timeout: Option<bft::TimeoutCertificate>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub context: bft::Context,
    pub order: Vec<Hash>,
    pub stage: Stage,
    pub proposed: Option<Proposed>,
    pub entered_at: f64,
    pub interval: f64,
    pub timeout: f64,
    pub stopped: bool,
    pub initial_wait: bool,
    pub timeout_refresh: bool,
}
impl Input {
    pub fn read(path: &std::path::Path) -> Result<Self> {
        let raw = crate::wallet_client::private_read(path)?;
        let value = crate::wallet_http::decode_unique(&raw)?;
        let input: Self = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        require(
            serde_json::to_value(&input).map_err(|e| e.to_string())? == value
                && crate::wallet_client::canonical(&input)? == raw
                && input.order.len() <= 512,
            "BFT tick typed/canonical input bound",
        )?;
        require(
            (input.stage == Stage::AfterProposal) == input.proposed.is_some(),
            "BFT tick proposal hint stage differs",
        )?;
        Ok(input)
    }
}
#[derive(Debug, Serialize)]
pub enum Decision {
    Phase(phase::Action),
    Propose {
        round: u64,
        timeout: Option<bft::TimeoutCertificate>,
        high: Option<Hash>,
    },
    WaitInitial {
        deadline: f64,
    },
    RefreshTimeout,
    Timeout {
        context: bft::Context,
        round: u64,
    },
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub format: &'static str,
    pub context: bft::Context,
    pub round: u64,
    pub key: String,
    pub caller_head: Hash,
    pub archive_sha256: Hash,
    pub request_sha256: Hash,
    pub authenticated_messages: usize,
    pub monotonic_now: f64,
    pub action: Decision,
    pub ledger_changed: bool,
    pub signing_authority: bool,
    pub independent_freshness_qualified: bool,
}
// Same OS monotonic domain as Python time.monotonic, with no wall-clock conversion.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn monotonic() -> Result<f64> {
    let mut base = libc::mach_timebase_info { numer: 0, denom: 0 };
    require(
        unsafe { libc::mach_timebase_info(&mut base) } == 0 && base.denom != 0,
        "BFT monotonic clock unavailable",
    )?;
    let nanos = u128::from(unsafe { libc::mach_absolute_time() }) * u128::from(base.numer)
        / u128::from(base.denom);
    Ok(nanos as f64 / 1_000_000_000.0)
}
#[cfg(not(target_os = "macos"))]
fn monotonic() -> Result<f64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    require(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } == 0,
        "BFT monotonic clock unavailable",
    )?;
    Ok(value.tv_sec as f64 + value.tv_nsec as f64 / 1_000_000_000.0)
}
fn ages(input: &Input, now: f64, round: u64) -> Result<(bool, bool)> {
    require(
        input.entered_at.is_finite()
            && input.entered_at >= 0.0
            && now.is_finite()
            && now >= input.entered_at
            && input.interval.is_finite()
            && (0.5..=3600.0).contains(&input.interval)
            && input.timeout.is_finite()
            && (2.0..=3600.0).contains(&input.timeout)
            && round < bft::MAX_ROUNDS,
        "BFT tick monotonic timer bounds",
    )?;
    let age = now - input.entered_at;
    Ok((
        age >= input.interval,
        age >= (input.timeout * (round + 1) as f64).min(3600.0),
    ))
}
pub fn observe(node: &Store, pins: proposal::Pins<'_>, input: Input) -> Result<Observation> {
    require(
        pins.context == input.context,
        "BFT tick input context differs",
    )?;
    // No implicit adoption by joint/role profiles or unrecognised runtime formats.
    require(
        matches!(
            pins.runtime_format.as_str(),
            "RLD-REGIONAL-BFT-NODE-V1" | "RLD-REGIONAL-BFT-ORIGIN-NODE-V8"
        ),
        "BFT tick ordinary runtime profile differs",
    )?;
    let origin = pins.runtime_format == "RLD-REGIONAL-BFT-ORIGIN-NODE-V8";
    let request_sha256 = Hash(Sha256::digest(crate::wallet_client::canonical(&input)?).into());
    let inspected = proposal::inspect(node, &pins)?;
    let messages = inspected.client.scheduling_messages(
        node,
        pins.archive_head,
        &inspected.context,
        true,
        Some(&input.order),
    )?;
    let (proposals, votes) = phase::retained(&messages)?;
    let select = |mode| {
        phase::select(
            mode,
            &inspected.active,
            &inspected.signer_state,
            &proposals,
            &votes,
            &pins.key,
            node,
        )
    };
    let now = monotonic()?;
    let (proposal_due, timeout_due) = ages(&input, now, pins.round)?;
    let action = if input.stopped {
        Decision::Phase(select(phase::Mode::Finalize)?)
    } else {
        match input.stage {
            Stage::Commit => Decision::Phase(select(phase::Mode::Commit)?),
            Stage::Committed => Decision::Phase(select(phase::Mode::Committed)?),
            Stage::AfterProposal => {
                let hint = input
                    .proposed
                    .as_ref()
                    .ok_or("BFT tick proposal hint missing")?;
                require(
                    origin && hint.round == pins.round,
                    "BFT tick post-Propose profile/round differs",
                )?;
                let mut action = phase::Action::Idle;
                if inspected.active.proposed
                    && inspected.active.prepared.is_none()
                    && inspected.active.committed.is_none()
                {
                    for (p, value) in &proposals {
                        if p.round == hint.round
                            && p.leader.key == pins.key
                            && p.snapshot == hint.snapshot
                            && p.timeout == hint.timeout
                            && phase::prepare(&inspected.signer_state, p, &pins.key, node)?
                        {
                            action = phase::Action::Prepare {
                                proposal: Box::new(p.clone()),
                                prepared: None,
                                value: *value,
                            };
                            break;
                        }
                    }
                }
                Decision::Phase(action)
            }
            Stage::Begin => {
                let current = select(phase::Mode::Start)?;
                if !matches!(current, phase::Action::Idle) {
                    Decision::Phase(current)
                } else {
                    let opportunity = proposal::opportunity(
                        node,
                        &pins,
                        &inspected.context,
                        &inspected.keys,
                        &inspected.active,
                        &messages,
                    )?;
                    if opportunity.can_propose && proposal_due {
                        Decision::Propose {
                            round: opportunity.proposed_round,
                            timeout: opportunity.timeout,
                            high: opportunity.high,
                        }
                    } else if opportunity.can_propose
                        && origin
                        && opportunity.proposed_round == 0
                        && pins.round == 0
                        && inspected.active.prepared.is_none()
                        && inspected.active.committed.is_none()
                        && input.initial_wait
                    {
                        Decision::WaitInitial {
                            deadline: input.entered_at + input.interval,
                        }
                    } else {
                        let future = select(phase::Mode::Future)?;
                        if !matches!(future, phase::Action::Idle) {
                            Decision::Phase(future)
                        } else if timeout_due && origin && input.timeout_refresh {
                            Decision::RefreshTimeout
                        } else if timeout_due {
                            Decision::Timeout {
                                context: inspected.context.clone(),
                                round: pins.round,
                            }
                        } else {
                            Decision::Phase(phase::Action::Idle)
                        }
                    }
                }
            }
        }
    };
    Ok(Observation {
        format: "RLD-NATIVE-BFT-TICK-OBSERVATION-V1",
        context: inspected.context.clone(),
        round: pins.round,
        key: pins.key,
        caller_head: pins.head,
        archive_sha256: pins.archive_head,
        request_sha256,
        authenticated_messages: messages.len(),
        monotonic_now: now,
        action,
        ledger_changed: false,
        signing_authority: false,
        independent_freshness_qualified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_due_and_capped_timeout_preserve_original_start() {
        let input = Input {
            context: bft::Context {
                currency: Hash::ZERO,
                region: Hash::ZERO,
                epoch: Hash::ZERO,
                previous: None,
                parent_height: 0,
                parent_block: Hash::ZERO,
                parent_state: Hash::ZERO,
            },
            order: vec![],
            stage: Stage::Begin,
            proposed: None,
            entered_at: 7.0,
            interval: 1.0,
            timeout: 200.0,
            stopped: false,
            initial_wait: false,
            timeout_refresh: false,
        };
        assert_eq!(ages(&input, 7.999, 0).unwrap(), (false, false));
        assert_eq!(ages(&input, 8.0, 0).unwrap(), (true, false));
        assert_eq!(ages(&input, 207.0, 0).unwrap(), (true, true));
        assert_eq!(ages(&input, 3607.0, 31).unwrap(), (true, true));
        assert!(ages(&input, 6.0, 0).is_err());
        assert!(ages(&input, 8.0, 32).is_err());
    }
}
