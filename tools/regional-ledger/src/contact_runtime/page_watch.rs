//! Test-only metadata observer. No clock, I/O, verification or scheduling authority.
//! `complete` covers known registrations across observed windows, never all rounds.
//! Only the current window retains packet mappings. Exited summaries cannot backfill pages.
use crate::{bft::Context, Hash};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    marker::PhantomData,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, TryLockError,
    },
};

const BUSY: u32 = 1;
const POISONED: u32 = 2;
const REENTRY: u32 = 4;
const MALFORMED: u32 = 8;
const ARM_CONFLICT: u32 = 16;
const PROPOSAL_CONFLICT: u32 = 32;
const VOTE_CONFLICT: u32 = 64;
const CAPACITY: u32 = 128;
const MAPPING: u32 = 256;
const GENERATION: u32 = 512;
const MAX_WINDOWS: usize = 32;
#[derive(Clone, PartialEq)]
struct Arm {
    intent: Hash,
    input: Hash,
    submitted: f64,
}
#[derive(Clone, PartialEq)]
struct Binding {
    context: Context,
    value: Hash,
    round: u64,
    proposal: Hash,
}
#[derive(Clone, PartialEq)]
enum Mapping {
    Pending,
    NotDestined(Hash),
    Target { frame: Hash, packet: Hash },
}
struct Vote {
    kind: &'static str,
    signer: Hash,
    body: Hash,
    at: f64,
    mapping: Mapping,
}
struct WindowSummary {
    binding: Binding,
    window_generation: u64,
    entered_from_event_at: f64,
    exited_by_event_at: f64,
    known_votes: usize,
    mapped_targets: usize,
    not_destined: usize,
    unmapped: usize,
    integrity_gap_bits: u32,
}
#[derive(Default)]
struct Coverage {
    before_binding_votes: u64,
    late_proposals: u64,
    late_votes: u64,
    future_votes: u64,
    other_value_votes: u64,
    other_context_proposals: u64,
    skipped_rounds: u64,
}
#[derive(Default)]
struct State {
    arm: Option<Arm>,
    binding: Option<Binding>,
    votes: Vec<Vote>,
    generation: u64,
    window_generation: u64,
    entered_from_event_at: Option<f64>,
    exited: Vec<WindowSummary>,
    coverage: Coverage,
}
pub(super) struct Watch {
    destination: Hash,
    armed: AtomicBool,
    state: Mutex<State>,
    gaps: AtomicU32,
}
pub(super) type Shared = Arc<Watch>;
thread_local! { static ACTIVE: RefCell<Option<Shared>> = const { RefCell::new(None) }; }
pub(super) struct Guard {
    scope: Option<Shared>,
    _thread: PhantomData<Rc<()>>,
}
pub(super) fn shared(destination: Hash) -> Shared {
    Arc::new(Watch {
        destination,
        armed: AtomicBool::new(false),
        state: Mutex::new(State::default()),
        gaps: AtomicU32::new(0),
    })
}
fn mark(scope: &Shared, flag: u32) {
    scope.gaps.fetch_or(flag, Ordering::AcqRel);
}
pub(super) fn install(scope: Shared) -> Guard {
    let installed = ACTIVE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(old) = slot.as_ref() {
            mark(old, REENTRY);
            mark(&scope, REENTRY);
            false
        } else {
            *slot = Some(scope.clone());
            true
        }
    });
    Guard {
        scope: installed.then_some(scope),
        _thread: PhantomData,
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(scope) = &self.scope {
            ACTIVE.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.as_ref().is_some_and(|old| Arc::ptr_eq(old, scope)) {
                    *slot = None;
                } else {
                    mark(scope, REENTRY);
                }
            });
        }
    }
}
fn active() -> Option<Shared> {
    ACTIVE.with(|slot| slot.borrow().clone())
}
fn update(f: impl FnOnce(&Shared, &mut State) -> bool) {
    let Some(scope) = active() else {
        return;
    };
    match scope.state.try_lock() {
        Ok(mut state) => {
            if f(&scope, &mut state) {
                if let Some(next) = state.generation.checked_add(1) {
                    state.generation = next;
                } else {
                    mark(&scope, GENERATION);
                }
            }
        }
        Err(TryLockError::WouldBlock) => mark(&scope, BUSY),
        Err(TryLockError::Poisoned(_)) => mark(&scope, POISONED),
    };
}
fn hash(value: &Value) -> Option<Hash> {
    let raw = value.as_str()?;
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Hash::from_hex(raw).ok()
}
pub(super) fn arm_second(intent: Hash, input: Option<Hash>, submitted: f64) {
    let Some(input) = input else {
        return;
    }; // Ordinary first payment cannot arm this observer.
    let mut armed = false;
    update(|scope, state| {
        if !submitted.is_finite() || submitted < 0.0 {
            mark(scope, MALFORMED);
            return false;
        }
        let next = Arm {
            intent,
            input,
            submitted,
        };
        match &state.arm {
            None => {
                state.arm = Some(next);
                armed = true;
                true
            }
            Some(old) => {
                armed = true;
                if old != &next {
                    mark(scope, ARM_CONFLICT);
                }
                false
            }
        }
    });
    // Publish the opt-in only after releasing the registry lock. Unrelated
    // first-payment events cannot make an unarmed watch incomplete.
    if armed {
        if let Some(scope) = active() {
            scope.armed.store(true, Ordering::Release);
        }
    }
}
fn enabled() -> bool {
    active().is_some_and(|scope| scope.armed.load(Ordering::Acquire))
}
fn count(scope: &Shared, value: &mut u64, amount: u64) -> bool {
    if let Some(next) = value.checked_add(amount) {
        *value = next;
        amount != 0
    } else {
        mark(scope, GENERATION);
        false
    }
}
fn open_window(scope: &Shared, state: &mut State, next: Binding, at: f64) -> bool {
    // Includes the current window. No old body, frame or packet registry is retained.
    if state.exited.len() + usize::from(state.binding.is_some()) >= MAX_WINDOWS {
        mark(scope, CAPACITY);
        return false;
    }
    let Some(generation) = state.window_generation.checked_add(1) else {
        mark(scope, GENERATION);
        return false;
    };
    let skipped = match state.binding.as_ref() {
        Some(old) => {
            let Some(skipped) = next
                .round
                .checked_sub(old.round)
                .and_then(|n| n.checked_sub(1))
            else {
                mark(scope, MALFORMED);
                return false;
            };
            skipped
        }
        None => 0,
    };
    if let Some(old) = state.binding.take() {
        let known_votes = state.votes.len();
        let mapped_targets = state
            .votes
            .iter()
            .filter(|v| matches!(v.mapping, Mapping::Target { .. }))
            .count();
        let not_destined = state
            .votes
            .iter()
            .filter(|v| matches!(v.mapping, Mapping::NotDestined(_)))
            .count();
        let unmapped = known_votes - mapped_targets - not_destined;
        count(scope, &mut state.coverage.skipped_rounds, skipped);
        state.exited.push(WindowSummary {
            binding: old,
            window_generation: state.window_generation,
            entered_from_event_at: state
                .entered_from_event_at
                .expect("bound window has provenance"),
            exited_by_event_at: at,
            known_votes,
            mapped_targets,
            not_destined,
            unmapped,
            integrity_gap_bits: scope.gaps.load(Ordering::Acquire),
        });
    }
    state.votes.clear();
    state.binding = Some(next);
    state.window_generation = generation;
    state.entered_from_event_at = Some(at);
    true
}
/// Called on the existing event after its original `at` was assigned, after durable retention.
pub(super) fn observe_retained(event: &Value) {
    if !enabled() || event["phase"] != "payment-body-retained" || event["local"] != true {
        return;
    }
    update(|scope, state| {
        let Some(arm) = state.arm.as_ref() else {
            return false;
        };
        let body = &event["body"];
        let kind = match body["kind"].as_str() {
            Some("proposal") => "proposal",
            Some("prepare") => "prepare",
            Some("commit") => "commit",
            _ => return false,
        };
        if kind == "proposal" {
            let Some(intents) = body["snapshot"]["intents"].as_array() else {
                mark(scope, MALFORMED);
                return false;
            };
            if !intents.iter().any(|value| hash(value) == Some(arm.intent)) {
                return false;
            }
        }
        let fields = (
            hash(&event["body_id"]),
            serde_json::from_value::<Context>(body["context"].clone()).ok(),
            body["round"].as_u64(),
            event["at"].as_f64(),
        );
        let (Some(id), Some(context), Some(round), Some(at)) = fields else {
            mark(scope, MALFORMED);
            return false;
        };
        if round >= crate::bft::MAX_ROUNDS || !at.is_finite() || at < arm.submitted {
            mark(scope, MALFORMED);
            return false;
        }
        let Some(value) = hash(if kind == "proposal" {
            &body["snapshot"]["value"]
        } else {
            &body["value"]
        }) else {
            mark(scope, MALFORMED);
            return false;
        };
        if kind == "proposal" {
            let next = Binding {
                context,
                value,
                round,
                proposal: id,
            };
            return match &state.binding {
                None => open_window(scope, state, next, at),
                Some(old) if old.context != next.context => {
                    count(scope, &mut state.coverage.other_context_proposals, 1)
                }
                Some(old) if next.round < old.round => {
                    count(scope, &mut state.coverage.late_proposals, 1)
                }
                Some(old) if next.round == old.round => {
                    if old != &next {
                        mark(scope, PROPOSAL_CONFLICT);
                    }
                    false
                }
                Some(_) => open_window(scope, state, next, at),
            };
        }
        let Some(signer) = hash(&body["signer"]) else {
            mark(scope, MALFORMED);
            return false;
        };
        let Some(binding) = state.binding.as_ref() else {
            return count(scope, &mut state.coverage.before_binding_votes, 1);
        };
        if context != binding.context {
            return false; // A vote alone cannot bind another context to the armed intent.
        }
        if round < binding.round {
            return count(scope, &mut state.coverage.late_votes, 1);
        }
        if round > binding.round {
            return count(scope, &mut state.coverage.future_votes, 1);
        }
        if value != binding.value {
            if state
                .votes
                .iter()
                .any(|v| v.kind == kind && v.signer == signer)
            {
                mark(scope, VOTE_CONFLICT);
            }
            return count(scope, &mut state.coverage.other_value_votes, 1);
        }
        if let Some(old) = state
            .votes
            .iter()
            .find(|v| v.kind == kind && v.signer == signer)
        {
            if old.body != id {
                mark(scope, VOTE_CONFLICT);
            }
            return false;
        }
        if state.votes.len() == 8 {
            mark(scope, CAPACITY);
            return false;
        }
        state.votes.push(Vote {
            kind,
            signer,
            body: id,
            at,
            mapping: Mapping::Pending,
        });
        true
    });
}
/// Zip the actual batch return before consuming it; this includes reused packets.
pub(super) fn observe_enqueued(
    selected: &[Hash],
    frames: &[Hash],
    destinations: &[String],
    packets: &[Vec<String>],
) {
    if !enabled() {
        return;
    }
    update(|scope, state| {
        if state.binding.is_none() {
            return false;
        }
        let valid = !selected.is_empty()
            && selected.len() <= 4
            && selected.len() == frames.len()
            && selected.len() == packets.len()
            && !destinations.is_empty()
            && destinations.len() <= 16
            && destinations.iter().all(|d| hash(&json!(d)).is_some())
            && destinations
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == destinations.len()
            && selected
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == selected.len()
            && packets.iter().all(|batch| {
                batch.len() == destinations.len() && batch.iter().all(|p| hash(&json!(p)).is_some())
            });
        if !valid {
            mark(scope, MAPPING);
            return false;
        }
        let target = destinations
            .iter()
            .position(|d| d == &scope.destination.to_hex());
        let mut changed = false;
        for (row, id) in selected.iter().enumerate() {
            let Some(index) = state.votes.iter().position(|vote| vote.body == *id) else {
                continue;
            };
            let next = match target {
                Some(column) => Mapping::Target {
                    frame: frames[row],
                    packet: hash(&json!(packets[row][column])).expect("batch checked"),
                },
                None => Mapping::NotDestined(frames[row]),
            };
            if state.votes.iter().enumerate().any(|(i, other)| {
                i != index
                    && match (&other.mapping, &next) {
                        (
                            Mapping::Target {
                                frame: a,
                                packet: p,
                            },
                            Mapping::Target {
                                frame: b,
                                packet: q,
                            },
                        ) => a == b || p == q,
                        _ => false,
                    }
            }) {
                mark(scope, MAPPING);
                continue;
            }
            match &state.votes[index].mapping {
                Mapping::Pending => {
                    state.votes[index].mapping = next;
                    changed = true;
                }
                old => {
                    if old != &next {
                        mark(scope, MAPPING);
                    }
                }
            }
        }
        changed
    });
}
fn gap_names(bits: u32) -> Vec<&'static str> {
    [
        (BUSY, "busy"),
        (POISONED, "poisoned"),
        (REENTRY, "reentry"),
        (MALFORMED, "malformed"),
        (ARM_CONFLICT, "arm-conflict"),
        (PROPOSAL_CONFLICT, "proposal-conflict"),
        (VOTE_CONFLICT, "vote-conflict"),
        (CAPACITY, "capacity"),
        (MAPPING, "mapping-conflict"),
        (GENERATION, "generation-overflow"),
    ]
    .into_iter()
    .filter_map(|(flag, name)| (bits & flag != 0).then_some(name))
    .collect()
}
fn binding_value(binding: &Binding) -> Value {
    json!({"context":binding.context,"value":binding.value,"round":binding.round,"proposal_body_id":binding.proposal})
}
fn coverage_value(state: &State, include_exited: bool) -> (Value, bool) {
    let c = &state.coverage;
    let exited_unmapped: usize = state.exited.iter().map(|w| w.unmapped).sum();
    let mut gaps = Vec::new();
    for (present, name) in [
        (exited_unmapped != 0, "exited-unmapped"),
        (c.before_binding_votes != 0, "before-binding-votes"),
        (c.late_proposals != 0, "late-proposals"),
        (c.late_votes != 0, "late-votes"),
        (c.future_votes != 0, "future-votes"),
        (c.other_value_votes != 0, "other-value-votes"),
        (c.other_context_proposals != 0, "other-context-proposals"),
        (c.skipped_rounds != 0, "skipped-rounds"),
    ] {
        if present {
            gaps.push(name);
        }
    }
    let complete = gaps.is_empty();
    let exited = include_exited.then(|| state.exited.iter().map(|w| json!({
            "binding":binding_value(&w.binding),"window_generation":w.window_generation,
            "entered_from_event_at":w.entered_from_event_at,"exited_by_event_at":w.exited_by_event_at,
            "known_votes":w.known_votes,"mapped_targets":w.mapped_targets,
            "not_destined":w.not_destined,"unmapped":w.unmapped,
            "integrity_gaps_at_exit":gap_names(w.integrity_gap_bits),
            "packet_registry_retained":false,"historical_pages_backfilled":false
        })).collect::<Vec<_>>());
    (
        json!({"gaps":gaps,"exited_windows":exited,"exited_window_count":state.exited.len(),
        "exited_summaries_included":include_exited,"exited_unmapped":exited_unmapped,
        "before_binding_votes":c.before_binding_votes,"late_proposals":c.late_proposals,
        "late_votes":c.late_votes,"future_votes":c.future_votes,
        "other_value_votes":c.other_value_votes,"other_context_proposals":c.other_context_proposals,
        "skipped_rounds":c.skipped_rounds,"max_windows_including_current":MAX_WINDOWS,
        "older_final_certificate_coverage":"unknown; inspect only original matching-window pages"}),
        complete,
    )
}
fn view(scope: &Shared, include_exited: bool) -> Value {
    match scope.state.try_lock() {
        Ok(state) => {
            let mut targets = Vec::new();
            let mut pending = Vec::new();
            for vote in &state.votes {
                let mut value = json!({"kind":vote.kind,"signer":vote.signer,"body_id":vote.body,"body_observed_at":vote.at});
                match vote.mapping {
                    Mapping::Target { frame, packet } => {
                        value["packet_id"] = json!(packet);
                        value["frame_id"] = json!(frame);
                        value["destination"] = json!(scope.destination);
                        targets.push(value);
                    }
                    Mapping::Pending => {
                        value["reason"] = json!("unmapped");
                        pending.push(value);
                    }
                    Mapping::NotDestined(frame) => {
                        value["reason"] = json!("no_target_destination");
                        value["frame_id"] = json!(frame);
                        value["applicable"] = json!(false);
                        pending.push(value);
                    }
                }
            }
            let bits = scope.gaps.load(Ordering::Acquire);
            let current_complete = bits == 0
                && state.arm.is_some()
                && state.binding.is_some()
                && state.votes.iter().all(|v| v.mapping != Mapping::Pending);
            let (coverage, coverage_complete) = coverage_value(&state, include_exited);
            json!({"format":"RLD-PAGE-WATCH-OBSERVATION-V2","destination":scope.destination,
                "complete":current_complete && coverage_complete,
                "complete_scope":"known registrations across observed windows only; never future votes or all rounds",
                "current_window_complete":current_complete,"integrity_complete":bits==0,"all_rounds_complete":false,
                "window_generation":state.window_generation,"entered_from_event_at":state.entered_from_event_at,
                "coverage":coverage,
                "generation":state.generation,"gaps":gap_names(bits),"targets":targets,"pending":pending,"snapshot_available":true,
                "armed":state.arm.as_ref().map(|a|json!({"intent":a.intent,"input":a.input,"submitted":a.submitted})),
                "binding":state.binding.as_ref().map(binding_value),
                "registration_clock":null,"clock_semantics":"event times are original provenance; generations order observer mutations, not a wall-clock interval",
                "native_authority":false,"qc_membership":false})
        }
        Err(error) => {
            mark(
                scope,
                match error {
                    TryLockError::WouldBlock => BUSY,
                    TryLockError::Poisoned(_) => POISONED,
                },
            );
            json!({"format":"RLD-PAGE-WATCH-OBSERVATION-V2","destination":scope.destination,"complete":false,
                "complete_scope":"known registrations across observed windows only; never future votes or all rounds",
                "current_window_complete":false,"integrity_complete":false,"all_rounds_complete":false,
                "generation":null,"window_generation":null,"coverage":null,
                "gaps":gap_names(scope.gaps.load(Ordering::Acquire)),"targets":[],"pending":null,
                "snapshot_available":false,"native_authority":false,"qc_membership":false})
        }
    }
}
pub(super) fn snapshot_before_page(node_id: &str) -> Option<Value> {
    let scope = active()?;
    (scope.armed.load(Ordering::Acquire) && node_id == scope.destination.to_hex())
        .then(|| view(&scope, false))
}
/// Caller must first stop and join every actor. Sticky gaps never reset during a scope.
pub(super) fn final_after_join(scope: &Shared) -> Value {
    view(scope, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash {
        Hash([n; 32])
    }
    fn context() -> Value {
        json!({"currency":h(1),"region":h(2),"epoch":h(3),"previous":null,"parent_height":6,"parent_block":h(4),"parent_state":h(5)})
    }
    fn proposal(value: Hash) -> Value {
        json!({"phase":"payment-body-retained","local":true,"at":2.0,"body_id":h(10),"body":{"kind":"proposal","context":context(),"round":0,"snapshot":{"value":value,"intents":[h(20)]}}})
    }
    fn vote(kind: &str, signer: Hash, body: Hash) -> Value {
        json!({"phase":"payment-body-retained","local":true,"at":3.0,"body_id":body,"body":{"kind":kind,"context":context(),"round":0,"value":h(21),"signer":signer}})
    }
    fn ready(scope: Shared) -> Guard {
        let guard = install(scope);
        arm_second(h(20), Some(h(22)), 1.0);
        observe_retained(&proposal(h(21)));
        guard
    }
    fn proposal_round(round: u64, value: Hash) -> Value {
        let mut event = proposal(value);
        event["body"]["round"] = json!(round);
        event["body_id"] = json!(h(100 + round as u8));
        event["at"] = json!(2.0 + round as f64);
        event
    }
    fn vote_round(kind: &str, signer: Hash, body: Hash, round: u64, value: Hash) -> Value {
        let mut event = vote(kind, signer, body);
        event["body"]["round"] = json!(round);
        event["body"]["value"] = json!(value);
        event["at"] = json!(3.0 + round as f64);
        event
    }
    fn bind(body: Hash, frame: Hash, packet: Hash) {
        observe_enqueued(
            &[body],
            &[frame],
            &[h(9).to_hex()],
            &[vec![packet.to_hex()]],
        );
    }
    #[test]
    fn higher_round_new_value_has_fresh_slots_and_late_votes_cannot_backfill() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        observe_retained(&vote("commit", h(30), h(31)));
        bind(h(31), h(32), h(33));
        let old = snapshot_before_page(&h(9).to_hex()).unwrap();
        observe_retained(&proposal_round(1, h(23)));
        let fresh = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(fresh["window_generation"], 2);
        assert_eq!(fresh["binding"]["round"], 1);
        assert_eq!(fresh["binding"]["value"], json!(h(23)));
        assert_eq!(fresh["targets"], json!([]));
        assert_eq!(fresh["pending"], json!([]));
        assert_eq!(fresh["complete"], true);
        observe_retained(&vote("commit", h(30), h(31)));
        bind(h(31), h(32), h(33));
        let late = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(late["binding"], fresh["binding"]);
        assert_eq!(late["targets"], json!([]));
        assert_eq!(late["coverage"]["late_votes"], 1);
        assert_eq!(late["gaps"], json!([]));
        assert_eq!(late["current_window_complete"], true);
        assert_eq!(late["complete"], false);
        observe_retained(&vote_round("commit", h(30), h(34), 1, h(23)));
        bind(h(34), h(35), h(36));
        let current = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(current["targets"].as_array().unwrap().len(), 1);
        assert_eq!(current["targets"][0]["packet_id"], json!(h(36)));
        assert_eq!(old["targets"][0]["packet_id"], json!(h(33)));
        assert_eq!(old["window_generation"], 1);
        assert_eq!(current["coverage"]["exited_window_count"], 1);
        assert!(current["coverage"]["exited_windows"].is_null());
        assert_eq!(
            final_after_join(&scope)["coverage"]["exited_windows"][0]["mapped_targets"],
            1
        );
        assert_eq!(current["all_rounds_complete"], false);
    }
    #[test]
    fn exited_unmapped_votes_remain_coverage_gaps_without_old_registries() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        observe_retained(&vote("prepare", h(30), h(31)));
        observe_retained(&proposal_round(1, h(21)));
        let before = final_after_join(&scope);
        assert_eq!(before["coverage"]["exited_unmapped"], 1);
        assert_eq!(before["coverage"]["exited_windows"][0]["unmapped"], 1);
        assert_eq!(before["current_window_complete"], true);
        assert_eq!(before["complete"], false);
        bind(h(31), h(32), h(33));
        let after = final_after_join(&scope);
        assert_eq!(before, after);
        assert!(!serde_json::to_string(&after["coverage"])
            .unwrap()
            .contains(&h(31).to_hex()));
        observe_retained(&proposal_round(2, h(21)));
        assert_eq!(final_after_join(&scope)["coverage"]["exited_unmapped"], 1);
    }
    #[test]
    fn same_window_vote_conflict_is_sticky_across_valid_transitions() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        observe_retained(&vote("prepare", h(30), h(31)));
        observe_retained(&vote("prepare", h(30), h(34)));
        assert_eq!(
            final_after_join(&scope)["pending"][0]["body_id"],
            json!(h(31))
        );
        observe_retained(&vote_round("prepare", h(30), h(35), 0, h(23)));
        assert_eq!(final_after_join(&scope)["coverage"]["other_value_votes"], 1);
        observe_retained(&proposal_round(1, h(23)));
        let image = final_after_join(&scope);
        assert!(image["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("vote-conflict")));
        assert_eq!(image["current_window_complete"], false);
        assert_eq!(image["binding"]["round"], 1);
        assert_eq!(image["targets"], json!([]));
    }
    #[test]
    fn future_votes_context_changes_and_round_jumps_are_coverage_not_rollbacks() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        observe_retained(&vote_round("prepare", h(30), h(31), 1, h(21)));
        let mut foreign = proposal_round(1, h(21));
        foreign["body"]["context"]["parent_state"] = json!(h(99));
        observe_retained(&foreign);
        observe_retained(&proposal_round(2, h(21)));
        observe_retained(&proposal(h(21)));
        let image = final_after_join(&scope);
        assert_eq!(image["binding"]["round"], 2);
        assert_eq!(image["window_generation"], 2);
        assert_eq!(image["coverage"]["future_votes"], 1);
        assert_eq!(image["coverage"]["other_context_proposals"], 1);
        assert_eq!(image["coverage"]["skipped_rounds"], 1);
        assert_eq!(image["coverage"]["late_proposals"], 1);
        assert_eq!(image["gaps"], json!([]));
        assert_eq!(image["current_window_complete"], true);
        assert_eq!(image["complete"], false);
        assert_eq!(image["targets"], json!([]));
    }
    #[test]
    fn every_window_has_at_most_eight_targets() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        for n in 0..8 {
            let kind = if n < 4 { "prepare" } else { "commit" };
            observe_retained(&vote(kind, h(40 + n % 4), h(60 + n)));
            bind(h(60 + n), h(80 + n), h(90 + n));
        }
        let before = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(before["targets"].as_array().unwrap().len(), 8);
        assert_eq!(before["current_window_complete"], true);
        observe_retained(&vote("prepare", h(50), h(70)));
        bind(h(70), h(88), h(98));
        let capped = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(capped["targets"], before["targets"]);
        assert!(capped["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("capacity")));
        observe_retained(&proposal_round(1, h(23)));
        assert_eq!(
            snapshot_before_page(&h(9).to_hex()).unwrap()["targets"],
            json!([])
        );
    }
    #[test]
    fn thirty_two_windows_include_current_and_never_grow_on_invalid_round() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        assert_eq!(crate::bft::MAX_ROUNDS, MAX_WINDOWS as u64);
        for round in 1..crate::bft::MAX_ROUNDS {
            observe_retained(&proposal_round(round, h(21)));
        }
        let before = final_after_join(&scope);
        assert_eq!(before["window_generation"], 32);
        assert_eq!(
            before["coverage"]["exited_windows"]
                .as_array()
                .unwrap()
                .len(),
            31
        );
        observe_retained(&proposal_round(crate::bft::MAX_ROUNDS, h(21)));
        let after = final_after_join(&scope);
        assert_eq!(after["window_generation"], 32);
        assert_eq!(after["binding"], before["binding"]);
        assert_eq!(after["coverage"], before["coverage"]);
        assert!(after["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("malformed")));
        // Exercise the independent storage cap, not a valid Native proposal.
        let mut state = scope.state.try_lock().unwrap();
        let next = state.binding.as_ref().unwrap().clone();
        assert!(!open_window(&scope, &mut state, next, 40.0));
        assert_eq!(state.exited.len(), 31);
        assert_eq!(state.window_generation, 32);
        drop(state);
        assert!(final_after_join(&scope)["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("capacity")));
    }
    #[test]
    fn disabled_and_first_payment_do_not_register() {
        arm_second(h(20), Some(h(22)), 1.0);
        observe_retained(&Value::Null);
        assert!(snapshot_before_page(&h(9).to_hex()).is_none());
        let scope = shared(h(9));
        let guard = install(scope.clone());
        arm_second(h(20), None, 1.0);
        assert_eq!(final_after_join(&scope)["generation"], 0);
        drop(guard);
        assert!(snapshot_before_page(&h(9).to_hex()).is_none());
    }
    #[test]
    fn exact_arm_and_proposal_conflict_are_sticky() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        arm_second(h(20), Some(h(22)), 1.0);
        assert_eq!(final_after_join(&scope)["generation"], 2);
        observe_retained(&proposal(h(23)));
        let image = final_after_join(&scope);
        assert_eq!(image["binding"]["value"], json!(h(21)));
        assert_eq!(image["complete"], false);
        assert!(image["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("proposal-conflict")));
    }
    #[test]
    fn busy_is_nonblocking_and_preserved_after_join() {
        let scope = shared(h(9));
        let guard = ready(scope.clone());
        let lock = scope.state.try_lock().unwrap();
        let image = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(image["complete"], false);
        drop(lock);
        observe_retained(&proposal_round(1, h(23)));
        assert_eq!(final_after_join(&scope)["window_generation"], 2);
        assert_eq!(final_after_join(&scope)["current_window_complete"], false);
        drop(guard);
        assert!(final_after_join(&scope)["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("busy")));
    }
    #[test]
    fn reused_packet_is_idempotent_and_old_snapshot_is_immutable() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        observe_retained(&vote("commit", h(30), h(31)));
        let before = snapshot_before_page(&h(9).to_hex()).unwrap();
        assert_eq!(before["complete"], false);
        let bind = || {
            observe_enqueued(
                &[h(31)],
                &[h(32)],
                &[h(9).to_hex()],
                &[vec![h(33).to_hex()]],
            )
        };
        bind();
        let image = snapshot_before_page(&h(9).to_hex()).unwrap();
        bind();
        assert_eq!(image, snapshot_before_page(&h(9).to_hex()).unwrap());
        assert_eq!(image["complete"], true);
        assert_eq!(image["targets"][0]["packet_id"], json!(h(33)));
        assert_eq!(before["targets"], json!([]));
        observe_enqueued(
            &[h(31)],
            &[h(32)],
            &[h(9).to_hex()],
            &[vec![h(34).to_hex()]],
        );
        assert_eq!(final_after_join(&scope)["complete"], false);
    }
    #[test]
    fn no_target_destination_is_explicitly_not_applicable() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        observe_retained(&vote("prepare", h(30), h(31)));
        observe_enqueued(
            &[h(31)],
            &[h(32)],
            &[h(8).to_hex()],
            &[vec![h(33).to_hex()]],
        );
        let image = final_after_join(&scope);
        assert_eq!(image["complete"], true);
        assert_eq!(image["targets"], json!([]));
        assert_eq!(image["pending"][0]["reason"], "no_target_destination");
    }
    #[test]
    fn eight_slots_and_mapping_conflicts_never_replace_retained_identity() {
        let scope = shared(h(9));
        let _guard = ready(scope.clone());
        for n in 0..9 {
            observe_retained(&vote("prepare", h(40 + n), h(60 + n)));
        }
        let image = final_after_join(&scope);
        assert_eq!(image["pending"].as_array().unwrap().len(), 8);
        assert!(image["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("capacity")));
        observe_enqueued(
            &[h(60)],
            &[h(80)],
            &[h(9).to_hex()],
            &[vec![h(81).to_hex()]],
        );
        observe_enqueued(
            &[h(60)],
            &[h(82)],
            &[h(9).to_hex()],
            &[vec![h(81).to_hex()]],
        );
        assert_eq!(
            final_after_join(&scope)["targets"][0]["frame_id"],
            json!(h(80))
        );
        arm_second(h(99), Some(h(22)), 1.0);
        assert!(final_after_join(&scope)["gaps"]
            .as_array()
            .unwrap()
            .contains(&json!("arm-conflict")));
    }
    #[test]
    fn reentry_never_replaces_or_leaks_scope() {
        let first = shared(h(9));
        let second = shared(h(8));
        let outer = install(first.clone());
        arm_second(h(20), Some(h(22)), 1.0);
        let inner = install(second.clone());
        drop(inner);
        assert!(snapshot_before_page(&h(9).to_hex()).is_some());
        assert!(snapshot_before_page(&h(8).to_hex()).is_none());
        drop(outer);
        assert!(snapshot_before_page(&h(9).to_hex()).is_none());
        assert_eq!(final_after_join(&second)["complete"], false);
    }
    #[test]
    fn unarmed_callbacks_do_not_contend_or_poison_later_observation() {
        let scope = shared(h(9));
        let guard = install(scope.clone());
        let lock = scope.state.try_lock().unwrap();
        observe_retained(&proposal(h(21)));
        observe_enqueued(&[], &[], &[], &[]);
        assert!(snapshot_before_page(&h(9).to_hex()).is_none());
        drop(lock);
        arm_second(h(20), Some(h(22)), 1.0);
        observe_retained(&proposal(h(21)));
        drop(guard);
        assert_eq!(final_after_join(&scope)["gaps"], json!([]));
        assert_eq!(final_after_join(&scope)["complete"], true);
    }
}
