//! Test-only metadata observer. No clock, I/O, verification or scheduling authority.
//! `complete` covers known registrations only; it never predicts future votes.
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
#[derive(Default)]
struct State {
    arm: Option<Arm>,
    binding: Option<Binding>,
    votes: Vec<Vote>,
    generation: u64,
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
        } else if state.binding.is_none() {
            return false;
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
                None => {
                    state.binding = Some(next);
                    true
                }
                Some(old) => {
                    if old != &next {
                        mark(scope, PROPOSAL_CONFLICT);
                    }
                    false
                }
            };
        }
        let binding = state.binding.as_ref().expect("binding checked above");
        if context != binding.context || value != binding.value {
            return false;
        }
        if round != binding.round {
            mark(scope, VOTE_CONFLICT);
            return false;
        }
        let Some(signer) = hash(&body["signer"]) else {
            mark(scope, MALFORMED);
            return false;
        };
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
fn view(scope: &Shared) -> Value {
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
            json!({"format":"RLD-PAGE-WATCH-OBSERVATION-V1","destination":scope.destination,
                "complete":bits==0 && state.arm.is_some() && state.binding.is_some()
                    && state.votes.iter().all(|v| v.mapping != Mapping::Pending),
                "generation":state.generation,"gaps":gap_names(bits),"targets":targets,"pending":pending,"snapshot_available":true,
                "armed":state.arm.as_ref().map(|a|json!({"intent":a.intent,"input":a.input,"submitted":a.submitted})),
                "binding":state.binding.as_ref().map(|b|json!({"context":b.context,"value":b.value,"round":b.round,"proposal_body_id":b.proposal})),
                "registration_clock":null,"clock_semantics":"body_observed_at is original event provenance; generation binds the copied observer state, not a wall-clock instant",
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
            json!({"format":"RLD-PAGE-WATCH-OBSERVATION-V1","destination":scope.destination,"complete":false,
                "generation":null,"gaps":gap_names(scope.gaps.load(Ordering::Acquire)),"targets":[],"pending":null,"snapshot_available":false,"native_authority":false})
        }
    }
}
pub(super) fn snapshot_before_page(node_id: &str) -> Option<Value> {
    let scope = active()?;
    (scope.armed.load(Ordering::Acquire) && node_id == scope.destination.to_hex())
        .then(|| view(&scope))
}
/// Caller must first stop and join every actor. Sticky gaps never reset during a scope.
pub(super) fn final_after_join(scope: &Shared) -> Value {
    view(scope)
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
