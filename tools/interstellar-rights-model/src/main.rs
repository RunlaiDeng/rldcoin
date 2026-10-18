//! Isolated finite research model. No node, store, monetary adoption or hardware.
//! Signing inputs are deliberately public NO-VALUE fixtures, never custody keys.
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};

const DOMAINS: usize = 3;
const MAX_LOCAL: usize = 3;
const MAX_HANDOFFS: usize = 2;
const MAX_STATES: usize = 100_000;
const MAX_DEPTH: usize = 12;
const CAP: u128 = 10u128.pow(35);
const ERA: u128 = 200_000;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Action {
    Pay { source: u8, owner: u8 },
    Export { source: u8, target: u8, owner: u8 },
}
type History = Vec<Action>;

// A history is an exact symbolic certificate bundle for one indivisible unit.
// Authentication and persistent non-equivocation are assumptions here; the
// separate real-signature witness deliberately removes non-equivocation.
fn replay(history: &History) -> Result<(usize, u8), &'static str> {
    let (mut domain, mut owner) = (0usize, 0u8);
    for action in history {
        match *action {
            Action::Pay {
                source,
                owner: next,
            } => {
                if usize::from(source) != domain || next > 1 {
                    return Err("invalid local predecessor");
                }
                owner = next;
            }
            Action::Export {
                source,
                target,
                owner: next,
            } => {
                if usize::from(source) != domain
                    || usize::from(target) >= DOMAINS
                    || source == target
                    || next > 1
                {
                    return Err("invalid destination or predecessor");
                }
                domain = usize::from(target);
                owner = next;
            }
        }
    }
    Ok((domain, owner))
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
struct Local {
    active: BTreeSet<History>,
    consumed: BTreeSet<History>,
    imported: BTreeSet<History>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct State {
    nodes: [Local; DOMAINS],
    // Retained source certificates. A lost receipt never destroys these bytes.
    exports: BTreeSet<History>,
    acknowledgments: BTreeSet<History>,
    completed: BTreeSet<History>,
}

impl State {
    fn initial() -> Self {
        let mut s = Self {
            nodes: std::array::from_fn(|_| Local::default()),
            exports: BTreeSet::new(),
            acknowledgments: BTreeSet::new(),
            completed: BTreeSet::new(),
        };
        // Existing test input, not issuance or an allocated monetary genesis.
        s.nodes[0].active.insert(vec![]);
        s
    }

    fn consume(&mut self, domain: usize, history: &History) -> bool {
        if !self.nodes[domain].active.contains(history)
            || self.nodes[domain].consumed.contains(history)
        {
            return false;
        }
        self.nodes[domain].active.remove(history);
        self.nodes[domain].consumed.insert(history.clone());
        true
    }

    fn pay(&mut self, domain: usize, history: &History, owner: u8) -> bool {
        if owner > 1 || replay(history).map(|x| x.0) != Ok(domain) {
            return false;
        }
        if !self.consume(domain, history) {
            return false;
        }
        let mut next = history.clone();
        next.push(Action::Pay {
            source: domain as u8,
            owner,
        });
        self.nodes[domain].active.insert(next.clone());
        self.completed.insert(next);
        true
    }

    fn export(&mut self, domain: usize, history: &History, target: u8, owner: u8) -> bool {
        if usize::from(target) >= DOMAINS
            || usize::from(target) == domain
            || owner > 1
            || replay(history).map(|x| x.0) != Ok(domain)
        {
            return false;
        }
        if !self.consume(domain, history) {
            return false;
        }
        let mut next = history.clone();
        next.push(Action::Export {
            source: domain as u8,
            target,
            owner,
        });
        self.exports.insert(next);
        true
    }

    fn deliver(&mut self, history: &History) -> bool {
        // Exact membership abstracts an authenticated complete certificate, not
        // recipient access to any source's live spent set or current balance.
        if !self.exports.contains(history) {
            return false;
        }
        let Ok((target, _)) = replay(history) else {
            return false;
        };
        if !matches!(history.last(), Some(Action::Export { .. }))
            || self.nodes[target].imported.contains(history)
        {
            return false;
        }
        self.nodes[target].imported.insert(history.clone());
        self.nodes[target].active.insert(history.clone());
        true
    }

    fn acknowledge(&mut self, history: &History) -> bool {
        let Ok((target, _)) = replay(history) else {
            return false;
        };
        if !self.nodes[target].imported.contains(history) {
            return false;
        }
        self.acknowledgments.insert(history.clone())
    }

    fn invariant(&self) -> Result<(), &'static str> {
        let active: usize = self.nodes.iter().map(|n| n.active.len()).sum();
        let pending = self
            .exports
            .iter()
            .filter(|h| {
                let target = replay(h).expect("model authored certificate").0;
                !self.nodes[target].imported.contains(*h)
            })
            .count();
        if active + pending != 1 {
            return Err("existing value duplicated or lost");
        }
        let mut lineages = BTreeSet::new();
        for (domain, node) in self.nodes.iter().enumerate() {
            for h in &node.active {
                if replay(h)?.0 != domain || node.consumed.contains(h) {
                    return Err("active wrong-domain or already-consumed input");
                }
                lineages.insert(h.clone());
            }
            for h in &node.imported {
                if !self.exports.contains(h) || replay(h)?.0 != domain {
                    return Err("unrooted import");
                }
            }
        }
        for h in &self.completed {
            if !matches!(h.last(), Some(Action::Pay { .. })) {
                return Err("non-payment completion");
            }
            lineages.insert(h.clone());
        }
        for h in &self.exports {
            lineages.insert(h.clone());
        }
        for a in &lineages {
            for b in &lineages {
                if !a.starts_with(b) && !b.starts_with(a) {
                    return Err("conflicting completed ancestry");
                }
            }
        }
        Ok(())
    }
}

fn model() -> Result<Value, String> {
    let start = State::initial();
    let mut seen = BTreeSet::from([start.clone()]);
    let mut queue = VecDeque::from([(start, 0usize)]);
    let (mut edges, mut duplicate_refusals, mut spent_refusals) = (0u64, 0u64, 0u64);
    let (mut lost_receipt_states, mut max_depth) = (0u64, 0usize);
    let mut observed_onward = false;
    while let Some((s, depth)) = queue.pop_front() {
        s.invariant().map_err(str::to_owned)?;
        max_depth = max_depth.max(depth);
        if s.exports.len() > s.acknowledgments.len() {
            lost_receipt_states += 1;
        }
        observed_onward |= s.completed.iter().any(|h| {
            let route: Vec<u8> = h
                .iter()
                .filter_map(|a| match a {
                    Action::Export { target, .. } => Some(*target),
                    _ => None,
                })
                .collect();
            route == [1, 2] && matches!(h.last(), Some(Action::Pay { source: 2, .. }))
        });
        let mut successors = Vec::new();
        for (domain, node) in s.nodes.iter().enumerate() {
            for h in &node.consumed {
                let mut attempt = s.clone();
                if attempt.pay(domain, h, 1) || attempt != s {
                    return Err("spent source accepted or refusal mutated state".into());
                }
                spent_refusals += 1;
            }
            for h in &node.active {
                let local = h.iter().filter(|a| matches!(a, Action::Pay { .. })).count();
                let hops = h.len() - local;
                for owner in 0..=1 {
                    if local < MAX_LOCAL {
                        let mut next = s.clone();
                        if !next.pay(domain, h, owner) {
                            return Err("authored pay refused".into());
                        }
                        successors.push(next);
                    }
                    if hops < MAX_HANDOFFS {
                        for target in 0..DOMAINS {
                            if target != domain {
                                let mut next = s.clone();
                                if !next.export(domain, h, target as u8, owner) {
                                    return Err("authored export refused".into());
                                }
                                successors.push(next);
                            }
                        }
                    }
                }
            }
        }
        for h in &s.exports {
            let mut next = s.clone();
            if next.deliver(h) {
                successors.push(next);
            } else {
                if next != s {
                    return Err("duplicate import mutated state".into());
                }
                duplicate_refusals += 1;
            }
            let mut next = s.clone();
            if next.acknowledge(h) {
                successors.push(next);
            }
        }
        for next in successors {
            edges += 1;
            if !s.completed.is_subset(&next.completed) {
                return Err("completed payment revoked".into());
            }
            next.invariant().map_err(str::to_owned)?;
            if seen.insert(next.clone()) {
                if depth >= MAX_DEPTH || seen.len() > MAX_STATES {
                    return Err("declared exploration bound exhausted; inconclusive".into());
                }
                queue.push_back((next, depth + 1));
            }
        }
    }
    if !observed_onward
        || lost_receipt_states == 0
        || duplicate_refusals == 0
        || spent_refusals == 0
    {
        return Err("required discriminating coverage absent".into());
    }
    Ok(json!({
        "status":"COMPLETE_FINITE_STATE_SPACE_UNDER_IDEAL_CERTIFIER",
        "states":seen.len(),"edges":edges,"maximum_depth":max_depth,
        "limits":{"domains":DOMAINS,"owners":2,"existing_indivisible_units":1,
            "local_transfers":MAX_LOCAL,"handoffs":MAX_HANDOFFS,
            "state_ceiling":MAX_STATES,"depth_ceiling":MAX_DEPTH},
        "lost_receipt_states":lost_receipt_states,"source_respend_refusals":spent_refusals,
        "duplicate_import_refusals":duplicate_refusals,
        "earth_proxima_andromeda_then_payment":observed_onward,
        "loss_semantics":"Every finite non-delivery prefix is retained. Self-loop duplicate deliveries do not create states. No receipt fairness, eventual delivery or elapsed-time bound is assumed.",
        "not_modeled":["native node","real signing in handoff transitions","Byzantine certifiers","membership changes","amount splitting or combining","crash/disk persistence","physical routes","issuance allocation"]
    }))
}

fn fixture_key() -> SigningKey {
    // Deliberately public NO-VALUE constant; no generated or user secret is read.
    SigningKey::from_bytes(&[0x42; 32])
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn work_digest(message: &[u8], nonce: u64) -> [u8; 32] {
    let mut first = Sha256::new();
    first.update(message);
    first.update(nonce.to_be_bytes());
    Sha256::digest(first.finalize()).into()
}

fn public_fixture_work(message: &[u8]) -> Result<(u64, [u8; 32]), String> {
    // Same success fraction as target 2^248-1, over an explicitly NON-NATIVE
    // research header. This is not a valid Survivor block or a mining benchmark.
    for nonce in 0..65_536 {
        let digest = work_digest(message, nonce);
        if digest[0] == 0 {
            return Ok((nonce, digest));
        }
    }
    Err("declared fixed work-search bound exhausted".into())
}

fn cloned_key_witness() -> Result<Value, String> {
    let original = fixture_key();
    let copy = SigningKey::from_bytes(&original.to_bytes());
    let left =
        b"NO-VALUE|currency=fixture|coin=0|version=0|counter=1|head=initial|to=Alice|amount=1";
    let right =
        b"NO-VALUE|currency=fixture|coin=0|version=0|counter=1|head=initial|to=Bob|amount=1";
    let a = original.sign(left);
    let b = copy.sign(right);
    let key = original.verifying_key();
    let (left_nonce, left_work) = public_fixture_work(left)?;
    let (right_nonce, right_work) = public_fixture_work(right)?;
    if key.verify_strict(left, &a).is_err()
        || key.verify_strict(right, &b).is_err()
        || key.verify_strict(left, &b).is_ok()
        || left.as_slice() == right.as_slice()
    {
        return Err("real signature witness did not discriminate".into());
    }
    Ok(json!({
        "status":"TWO_CONFLICTING_TRANSFERS_HAVE_VALID_ED25519_SIGNATURES",
        "public_fixture_only":true,"same_input_version_counter_and_prior_head":true,
        "public_key":hex(key.as_bytes()),
        "left_message":String::from_utf8_lossy(left),"right_message":String::from_utf8_lossy(right),
        "left_signature":hex(&a.to_bytes()),"right_signature":hex(&b.to_bytes()),
        "cross_message_signature_refuses":true,
        "both_conflicts_have_actual_double_sha256_work":true,
        "left_work":{"nonce":left_nonce,"digest":hex(&left_work)},
        "right_work":{"nonce":right_nonce,"digest":hex(&right_work)},
        "work_scope":"Non-native research headers with leading-zero-byte target and 65536 trials per message. Independent work does not supply an exclusive resource-use decision.",
        "trace":["Clone the entire software authority state before spending.",
            "Partition the copies and both recipients.",
            "Each copy signs a different successor at the same counter/head.",
            "Each recipient verifies a genuine owner signature; neither sees the other transfer."],
        "scope":"Cryptographic counterexample to signature/counter-only prevention, not an exploit of the current native wallet or its selected-history validation."
    }))
}

fn reward(reserve: u128, slot: u128) -> Option<u128> {
    if reserve > CAP || slot >= ERA {
        return None;
    }
    let budget = if reserve < 2 { reserve } else { reserve / 2 };
    Some(budget / ERA + u128::from(slot < budget % ERA))
}

fn issuance() -> Result<Value, String> {
    // A trusted test assignment of future slots grants no coins at genesis.
    // It deliberately DOES NOT solve open assignment or sole-custodian forks.
    let grants = [0u8, 1, 2];
    let mut reachable = BTreeSet::from([[[None; 3]; 3]]);
    let mut queue = VecDeque::from([[[None; 3]; 3]]);
    let (mut edges, mut denied) = (0u64, 0u64);
    let unit = reward(CAP, 0).ok_or("reward boundary")?;
    while let Some(s) = queue.pop_front() {
        for domain in 0..3u8 {
            for slot in 0..3 {
                for owner in 0..2u8 {
                    if grants[slot] != domain || s[usize::from(domain)][slot].is_some() {
                        denied += 1;
                        continue;
                    }
                    let mut next = s;
                    next[usize::from(domain)][slot] = Some(owner);
                    edges += 1;
                    let issued =
                        next.iter().flatten().filter(|v| v.is_some()).count() as u128 * unit;
                    if issued > 3 * unit || issued > CAP {
                        return Err("issuance overflow".into());
                    }
                    if reachable.insert(next) {
                        queue.push_back(next);
                    }
                }
            }
        }
    }
    let key = fixture_key();
    let a = b"NO-VALUE|issuance-slot=1|amount=250000RLD|owner=Alice";
    let b = b"NO-VALUE|issuance-slot=1|amount=250000RLD|owner=Bob";
    let sa = key.sign(a);
    let sb = key.sign(b);
    if key.verifying_key().verify_strict(a, &sa).is_err()
        || key.verifying_key().verify_strict(b, &sb).is_err()
    {
        return Err("issuance copy witness refused".into());
    }
    for r in [0, 1, 2, 3, 400_003, CAP] {
        let total: u128 = (0..ERA).map(|k| reward(r, k).expect("valid slot")).sum();
        let budget = if r < 2 { r } else { r / 2 };
        if total != budget {
            return Err("exact-era recurrence differs".into());
        }
    }
    Ok(json!({
        "status":"EXCLUSIVE_SLOTS_SAFE_ONLY_UNDER_TRUSTED_ALLOCATION_AND_NON_EQUIVOCATION",
        "finite_assignment_states":reachable.len(),"edges":edges,"refused_attempts":denied,
        "slot_amount_runlai":unit.to_string(),"fixture_slots":3,"genesis_issued":"0",
        "exact_era_recurrence_checked_reserves":["0","1","2","3","400003",CAP.to_string()],
        "naive_region_namespace_counterexample":{
            "trace":["Both disconnected regions start at global issuance slot 1.",
                "Each finalizes the full slot reward under a different local region ID."],
            "allowed_global_slot_amount_runlai":unit.to_string(),
            "combined_claimed_amount_runlai":(2 * unit).to_string(),
            "observation":"Unique local transaction IDs do not preserve the one-global-slot schedule."},
        "same_global_slot_id_counterexample":{
            "both_owner_assignments_have_valid_signatures":true,
            "observation":"A global slot ID makes the conflict detectable after delivery, but signatures alone do not choose an irreversible winner while recipients are partitioned."},
        "remaining_blockers":["Who safely assigns or transfers exclusive future issuance rights to newly arriving disconnected miners?",
            "An isolated miner without assigned rights can hash but cannot immediately finalize a subsidy.",
            "Cloning the assigned certifier still creates two valid conflicting slot certificates unless a separate non-equivocation mechanism holds."]
    }))
}

fn quorum_boundary() -> Value {
    let mut schedules = 0;
    let mut double_certificates = 0;
    // Three honest signers choose none, A or B. One Byzantine chooses either/both.
    for a in 0..3 {
        for b in 0..3 {
            for c in 0..3 {
                for faulty in 0..4 {
                    schedules += 1;
                    let honest = [a, b, c];
                    let left =
                        honest.iter().filter(|&&x| x == 1).count() + usize::from(faulty & 1 != 0);
                    let right =
                        honest.iter().filter(|&&x| x == 2).count() + usize::from(faulty & 2 != 0);
                    double_certificates += usize::from(left >= 3 && right >= 3);
                }
            }
        }
    }
    assert_eq!(double_certificates, 0);
    json!({"fixed_four_voter_assignments":schedules,"conflicting_three_vote_certificates":double_certificates,
        "assumptions":["fixed independently authenticated roster","at most one Byzantine identity",
            "every honest identity retains one conflict lock across every copy/restart"],
        "boundary":"One surviving voter cannot create a three-vote certificate. Reducing the threshold or independently creating a second roster does not inherit this property."})
}

fn timeout_refund_counterexample() -> Result<Value, String> {
    let mut s = State::initial();
    if !s.export(0, &vec![], 1, 1) {
        return Err("fixture export".into());
    }
    let transfer = s
        .exports
        .iter()
        .next()
        .ok_or("fixture export absent")?
        .clone();
    if !s.deliver(&transfer) {
        return Err("fixture delivery".into());
    }
    s.invariant().map_err(str::to_owned)?;
    // Deliberately unsafe policy, not a method accepted by the candidate model.
    s.nodes[0].active.insert(vec![]);
    if s.invariant().is_ok() {
        return Err("unsafe refund not detected".into());
    }
    Ok(json!({"status":"UNSAFE_TIMEOUT_REFUND_COUNTEREXAMPLE",
        "trace":["Earth certifies an export and consumes its input.",
            "Proxima verifies/imports it; every return receipt is lost.",
            "Earth refunds on local silence; both domains now hold spend rights."],
        "active_units_after_unsafe_refund":2,"allowed_units":1}))
}

fn run() -> Result<Value, String> {
    Ok(json!({
        "format":"RLD-EXCLUSIVE-RIGHTS-RESEARCH-OBSERVATIONS-1",
        "qualification":"NO_VALUE_FINITE_MODEL_AND_CRYPTOGRAPHIC_COUNTEREXAMPLES_ONLY",
        "overall":"ORIGINAL_UNCONDITIONAL_REQUIREMENTS_NOT_SOLVED",
        "handoff":model()?,"copied_software_authority":cloned_key_witness()?,
        "issuance":issuance()?,"fixed_quorum":quorum_boundary(),
        "unsafe_timeout_refund":timeout_refund_counterexample()?,
        "whitepaper_replacement_ready":false,"mainnet_authorized":false
    }))
}

fn main() {
    match run() {
        Ok(value) => println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON observation")
        ),
        Err(error) => {
            eprintln!("RESEARCH_INCOMPLETE_OR_MODEL_DEFECT: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_bounded_handoff_exploration() {
        model().unwrap();
    }

    #[test]
    fn cloned_signatures_are_not_an_antidouble_spend_primitive() {
        cloned_key_witness().unwrap();
    }

    #[test]
    fn exclusive_issuance_has_explicit_authority_boundary() {
        issuance().unwrap();
    }

    #[test]
    fn loss_of_receipts_cannot_authorize_refund() {
        timeout_refund_counterexample().unwrap();
    }

    #[test]
    fn altered_destination_and_unrooted_bundle_refuse_unchanged() {
        let mut s = State::initial();
        assert!(s.export(0, &vec![], 1, 0));
        let original = s.exports.iter().next().unwrap().clone();
        let mut changed = original.clone();
        changed[0] = Action::Export {
            source: 0,
            target: 2,
            owner: 0,
        };
        let before = s.clone();
        assert!(!s.deliver(&changed));
        assert_eq!(s, before);
        let invalid = vec![Action::Export {
            source: 2,
            target: 1,
            owner: 0,
        }];
        assert!(replay(&invalid).is_err());
    }

    #[test]
    fn third_region_can_pay_after_two_handoffs_with_no_receipts() {
        let mut s = State::initial();
        assert!(s.export(0, &vec![], 1, 1));
        let first = s.exports.iter().next().unwrap().clone();
        assert!(s.deliver(&first));
        assert!(s.export(1, &first, 2, 0));
        let second = s.exports.iter().find(|h| h.len() == 2).unwrap().clone();
        assert!(s.deliver(&second));
        assert!(s.pay(2, &second, 1));
        assert!(s.acknowledgments.is_empty());
        s.invariant().unwrap();
        let before = s.clone();
        assert!(!s.deliver(&first));
        assert!(!s.deliver(&second));
        assert_eq!(s, before);
    }

    #[test]
    fn reward_input_boundaries() {
        assert_eq!(reward(CAP, 0), Some(250_000 * 10u128.pow(24)));
        assert_eq!(reward(CAP / 2, 0), Some(125_000 * 10u128.pow(24)));
        assert_eq!(reward(1, 0), Some(1));
        assert_eq!(reward(1, 1), Some(0));
        assert_eq!(reward(CAP + 1, 0), None);
        assert_eq!(reward(CAP, ERA), None);
        assert_eq!(quorum_boundary()["conflicting_three_vote_certificates"], 0);
    }
}
