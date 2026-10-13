//! Fresh local public no-value signatures; no Agent or custody authority.
use super::body_witness_tests::{certified_with_commands, header, replay, stream};
use super::export_archive_tests::{inventory, seal_format};
use super::*;
use crate::tests::{channel_integration as channel, public};
use std::time::Instant;

#[derive(Serialize)]
struct Cut {
    selected: Statement,
    root: Hash,
    totals: (Amount, Amount, Amount, Amount),
    status: serde_json::Value,
}

fn action_id(command: &Command) -> Hash {
    let Command::Channel(body) = command else {
        panic!("expected actual channel command")
    };
    body.action.intent.id().unwrap()
}

fn challenge(
    native: &Replay,
    cid: Hash,
    reserve: Hash,
    sequence: u64,
    payouts: [Amount; 2],
    fee: Amount,
) -> Command {
    channel::command(
        &native.chain,
        &native.trust,
        channels::Action::Challenge {
            channel: cid,
            state: Box::new(channel::signed_state(
                &native.chain,
                &native.trust,
                cid,
                sequence,
                payouts,
            )),
            reserve,
            fee,
        },
        None,
        &[],
    )
}

fn deny_template(
    native: &Replay,
    flat: &Stream<Record>,
    root: &Path,
    command: Command,
    fragment: &str,
) -> String {
    let before_files = inventory(root);
    let before_ledger = native.chain.ledger.clone();
    let before_boundary = (
        native.chain.height(),
        native.chain.finalized,
        flat.storage_head(),
        native.executed.observed_executed_head(),
    );
    let mut staged = native.chain.clone();
    crate::paged_bft::prepare_parent(&mut staged, &native.evidence).unwrap();
    let error = staged
        .template(vec![command], public(10), &native.trust, &native.evidence)
        .unwrap_err();
    assert!(error.contains(fragment), "{error}");
    assert_eq!(staged.ledger, before_ledger);
    assert_eq!(native.chain.ledger, before_ledger);
    assert_eq!(
        (
            native.chain.height(),
            native.chain.finalized,
            flat.storage_head(),
            native.executed.observed_executed_head()
        ),
        before_boundary
    );
    assert_eq!(inventory(root), before_files);
    error
}

fn phase(started: &Instant, name: &str, event: &str, height: u64) {
    eprintln!(
        "channel_window_phase={}",
        serde_json::json!({
            "phase": name, "event": event, "native_height": height,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}

fn progress(started: &Instant, native: &Replay, flat: &Stream<Record>, milestone: Option<&Cut>) {
    // These exact sizes are sampled only at named transitions/every256 heights;
    // the ordinary Native kernel still performs its unchanged checks every record.
    let ledger_bytes = encode("paged-bft-native-ledger", &native.chain.ledger)
        .unwrap()
        .len();
    let evidence_bytes =
        crate::encoded_size::check("evidence", &ActiveEvidence(&native.evidence)).unwrap();
    eprintln!(
        "channel_window_progress={}",
        serde_json::json!({
            "native_height": native.chain.height(), "retained_records": flat.record_count(),
            "coins": native.chain.ledger.coins.len(), "active_snapshots": native.evidence.snapshots.len(),
            "typed_ledger_bytes": ledger_bytes, "typed_active_evidence_bytes": evidence_bytes,
            "milestone": milestone, "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}

#[test]
#[ignore = "fresh complete original channel window with full local certificate archive accounting"]
fn complete_original_channel_window_preserves_historical_accounting() {
    let started = Instant::now();
    assert_eq!(channels::WINDOW, 2016);
    let h = header();
    assert_eq!(h.bootstrap.admissions[0].rules, crate::paged_bft::RULES);
    let mut native = replay(&h);
    let (root, mut flat) = stream(&h, &native);
    eprintln!(
        "channel_window_fixture={}",
        serde_json::json!({"root": root, "currency": h.bootstrap.currency.id().unwrap()})
    );
    let scope = h.scope(&native.trust).unwrap();
    let mut records = Vec::new();
    let mut pending = Vec::new();
    let mut cuts = BTreeMap::new();
    let mut refusals = BTreeMap::new();
    let mut cid = Hash::ZERO;
    let mut reserve = Hash::ZERO;
    let mut reserve_amount = Amount::ZERO;
    let mut reserve_owner = String::new();
    let mut original_authorization = None;
    let mut settlement = Hash::ZERO;
    let mut challenge_ids = Vec::new();
    let mut settlement_outputs = BTreeMap::new();
    phase(&started, "native-history", "begin", 0);
    for height in 1..=2032 {
        let milestone_name = match height {
            4 => Some("open"),
            5 => Some("reserve-budget"),
            6 => Some("close"),
            7 => Some("first-successor-challenge"),
            2022 => Some("deadline-challenge"),
            2023 => Some("settle"),
            _ => None,
        };
        if let Some(name) = milestone_name {
            phase(&started, name, "begin", native.chain.height());
        }
        // Each denied request binds the real current Book/head and ordinary
        // next height. A refusal is never wrapped in a fabricated certificate.
        if height == 2022 || height == 2024 {
            let denied = channel::command(
                &native.chain,
                &native.trust,
                channels::Action::Settle { channel: cid },
                None,
                &[],
            );
            let (name, expected) = if height == 2022 {
                ("settle-at-deadline", "settlement strictly after deadline")
            } else {
                ("settle-twice", "channel not closing")
            };
            let error = deny_template(&native, &flat, &root, denied, expected);
            eprintln!(
                "channel_window_refusal={}",
                serde_json::json!({"name": name, "next_height": height, "error": error, "native_unchanged": true})
            );
            refusals.insert(name, error);
        }
        if height == 2023 {
            let late = challenge(
                &native,
                cid,
                reserve,
                3,
                [Amount(10), Amount(50)],
                Amount(1),
            );
            let book = &native.chain.ledger.channel_state.as_ref().unwrap().book;
            let budget = book.reserves[&reserve].budget.as_ref().unwrap();
            assert_eq!(budget.max_fee.checked_sub(budget.spent).unwrap(), Amount(3));
            let Command::Channel(body) = &late else {
                unreachable!()
            };
            let channels::Action::Challenge { state, .. } = &body.action.intent.action else {
                unreachable!()
            };
            book.channels[&cid]
                .verify_state(state, cid, &body.declaration)
                .unwrap();
            let error = deny_template(
                &native,
                &flat,
                &root,
                late,
                "higher state on a close successor through absolute deadline",
            );
            eprintln!(
                "channel_window_refusal={}",
                serde_json::json!({"name": "challenge-after-deadline", "next_height": height, "error": error, "native_unchanged": true})
            );
            refusals.insert("challenge-after-deadline", error);
        }
        let commands = match height {
            4 => {
                let open = channel::funding(&native.chain, &native.trust);
                cid = action_id(&open);
                vec![open]
            }
            5 => {
                let (input, coin) = native
                    .chain
                    .ledger
                    .coins
                    .iter()
                    .find(|(_, c)| {
                        c.payment.owner == public(10)
                            && c.mature <= height
                            && c.channel_dependencies.is_empty()
                    })
                    .unwrap();
                reserve = *input;
                reserve_amount = coin.payment.amount;
                reserve_owner = coin.payment.owner.clone();
                assert!(reserve_amount > Amount(9));
                let command = channel::command(
                    &native.chain,
                    &native.trust,
                    channels::Action::ReserveBudget {
                        channel: cid,
                        input: reserve,
                        fee_limit: Amount(3),
                        max_fee: Amount(9),
                    },
                    Some(10),
                    &[10],
                );
                let Command::Channel(body) = &command else {
                    unreachable!()
                };
                original_authorization = Some(body.action.clone());
                vec![command]
            }
            6 => {
                let input = *native
                    .chain
                    .ledger
                    .coins
                    .iter()
                    .find(|(_, c)| {
                        c.payment.owner == public(10)
                            && c.mature <= height
                            && c.channel_dependencies.is_empty()
                    })
                    .unwrap()
                    .0;
                assert_ne!(input, reserve);
                vec![channel::command(
                    &native.chain,
                    &native.trust,
                    channels::Action::Close {
                        channel: cid,
                        state: Box::new(channel::signed_state(
                            &native.chain,
                            &native.trust,
                            cid,
                            0,
                            [Amount(60), Amount::ZERO],
                        )),
                        fee_input: input,
                        fee: Amount(1),
                    },
                    Some(10),
                    &[10],
                )]
            }
            7 | 2022 => {
                let (sequence, payouts) = if height == 7 {
                    (1, [Amount(40), Amount(20)])
                } else {
                    (2, [Amount(20), Amount(40)])
                };
                let command = challenge(&native, cid, reserve, sequence, payouts, Amount(3));
                challenge_ids.push(action_id(&command));
                vec![command]
            }
            2023 => {
                let command = channel::command(
                    &native.chain,
                    &native.trust,
                    channels::Action::Settle { channel: cid },
                    None,
                    &[],
                );
                settlement = action_id(&command);
                vec![command]
            }
            _ => vec![],
        };
        let snapshot = certified_with_commands(&native, commands);
        let statement = snapshot.statement.clone();
        let record = Record::Certified(Box::new(snapshot));
        native
            .apply_retained(&record, &flat)
            .unwrap_or_else(|error| panic!("Native height {height}: {error}"));
        assert_eq!(native.chain.height(), height);
        assert!(native.chain.ledger.imports.is_empty() && native.chain.ledger.exports.is_empty());
        assert!(native.chain.ledger.coins.len() <= MAX_COINS);
        assert!(native.evidence.snapshots.len() <= MAX_SNAPSHOTS);
        pending.push(record.clone());
        records.push(record);
        if pending.len() == crate::history::PAGE_EVENTS {
            flat.append(&pending, flat.storage_head())
                .unwrap_or_else(|error| panic!("retaining height {height}: {error}"));
            pending.clear();
        }
        if let Some(name) = milestone_name {
            let totals = conservation_with_escrow(std::slice::from_ref(&native.chain)).unwrap();
            assert_eq!(
                totals.0,
                Amount(rld_pow::cumulative_emission(height.into()))
            );
            assert_eq!(totals.3, Amount::ZERO);
            assert_eq!(
                totals.0,
                add(add(totals.1, totals.2).unwrap(), totals.3).unwrap()
            );
            let book = &native.chain.ledger.channel_state.as_ref().unwrap().book;
            assert_eq!(book.channels.len(), 1);
            let escrow = &book.channels[&cid];
            let status = if height <= 5 {
                assert!(matches!(escrow.phase, channels::Phase::Open));
                serde_json::json!({"phase": "Open"})
            } else if height <= 2022 {
                let channels::Phase::Closing {
                    state,
                    close_height,
                    deadline,
                } = &escrow.phase
                else {
                    panic!("expected closing")
                };
                let sequence = if height == 6 {
                    0
                } else if height == 7 {
                    1
                } else {
                    2
                };
                assert_eq!(
                    (*close_height, *deadline, state.statement.sequence),
                    (6, 2022, sequence)
                );
                assert_eq!(*deadline, *close_height + channels::WINDOW);
                let payouts = match sequence {
                    0 => [Amount(60), Amount::ZERO],
                    1 => [Amount(40), Amount(20)],
                    _ => [Amount(20), Amount(40)],
                };
                assert_eq!(state.statement.payouts, payouts);
                serde_json::json!({"phase": "Closing", "close_height": close_height, "deadline": deadline, "sequence": sequence, "payouts": payouts})
            } else {
                let channels::Phase::Settled {
                    state,
                    close_height,
                    deadline,
                    settled_height,
                } = &escrow.phase
                else {
                    panic!("expected settled")
                };
                assert_eq!(
                    (
                        *close_height,
                        *deadline,
                        *settled_height,
                        state.statement.sequence
                    ),
                    (6, 2022, 2023, 2)
                );
                assert_eq!(state.statement.payouts, [Amount(20), Amount(40)]);
                assert!(book.reserves.is_empty());
                assert!(!native.chain.ledger.coins.contains_key(&reserve));
                for (index, (owner, amount)) in channel::parties()
                    .into_iter()
                    .zip([Amount(20), Amount(40)])
                    .enumerate()
                {
                    let output = id("output", &(settlement, index as u32)).unwrap();
                    let coin = &native.chain.ledger.coins[&output];
                    assert_eq!(coin.payment, Payment { owner, amount });
                    assert_eq!((coin.created, coin.mature), (2023, 2023));
                    assert!(coin.channel_dependencies.contains(&cid));
                    settlement_outputs.insert(output, coin.clone());
                }
                let refund = id("output", &(settlement, 32u32)).unwrap();
                let coin = &native.chain.ledger.coins[&refund];
                assert_eq!(
                    coin.payment,
                    Payment {
                        owner: reserve_owner.clone(),
                        amount: reserve_amount.checked_sub(Amount(6)).unwrap()
                    }
                );
                assert_eq!((coin.created, coin.mature), (2023, 2023));
                assert!(coin.channel_dependencies.contains(&cid));
                settlement_outputs.insert(refund, coin.clone());
                assert_eq!(
                    native
                        .chain
                        .ledger
                        .coins
                        .values()
                        .filter(
                            |coin| coin.created == 2023 && coin.channel_dependencies.contains(&cid)
                        )
                        .count(),
                    3
                );
                serde_json::json!({"phase": "Settled", "close_height": close_height, "deadline": deadline, "settled_height": settled_height, "sequence": 2, "returned_reserve": coin.payment.amount})
            };
            let spent = if height < 7 {
                Amount::ZERO
            } else if height < 2022 {
                Amount(3)
            } else {
                Amount(6)
            };
            let expected_escrow = if height == 4 {
                Amount(60)
            } else if height == 2023 {
                Amount::ZERO
            } else {
                add(Amount(60), reserve_amount.checked_sub(spent).unwrap()).unwrap()
            };
            assert_eq!(totals.2, expected_escrow);
            if (5..=2022).contains(&height) {
                assert_eq!(book.reserves.len(), 1);
                let retained = &book.reserves[&reserve];
                let budget = retained.budget.as_ref().unwrap();
                assert_eq!(retained.channel, cid);
                assert_eq!(retained.coin.payment.owner, reserve_owner);
                assert_eq!(
                    retained.coin.payment.amount,
                    reserve_amount.checked_sub(spent).unwrap()
                );
                assert_eq!(
                    (budget.original_amount, budget.max_fee, budget.spent),
                    (reserve_amount, Amount(9), spent)
                );
                assert_eq!(retained.fee_limit, Amount(3));
                assert_eq!(
                    retained.authorization.as_ref(),
                    original_authorization.as_ref().unwrap()
                );
                assert!(!native.chain.ledger.coins.contains_key(&reserve));
            }
            let cut = Cut {
                selected: statement,
                root: native.chain.ledger.root().unwrap(),
                totals,
                status,
            };
            assert_eq!(cut.selected.state, cut.root);
            progress(&started, &native, &flat, Some(&cut));
            cuts.insert(height, cut);
            phase(&started, name, "end", height);
        } else if height % 256 == 0 {
            progress(&started, &native, &flat, None);
        }
    }
    assert!(pending.is_empty());
    assert_eq!((records.len(), flat.record_count()), (2032, 2032));
    assert_eq!(records.len() / crate::history::PAGE_EVENTS, 127);
    native
        .executed
        .require_boundary(&scope, flat.record_count(), flat.storage_head())
        .unwrap();
    assert_eq!(cuts.len(), 6);
    assert_eq!(refusals.len(), 3);
    assert_eq!(native.chain.height(), 2032);
    let final_checkpoint = native.chain.finalized.unwrap();
    assert!(!native
        .evidence
        .snapshots
        .contains_key(&cuts[&5].selected.id().unwrap()));
    assert!(native
        .evidence
        .snapshots
        .contains_key(&cuts[&2023].selected.id().unwrap()));
    assert_eq!(
        native
            .chain
            .ledger
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .locked()
            .unwrap(),
        Amount::ZERO
    );
    assert_eq!(settlement_outputs.len(), 3);
    assert_eq!(challenge_ids.len(), 2);
    for (ident, coin) in &settlement_outputs {
        assert_eq!(native.chain.ledger.coins.get(ident), Some(coin));
    }
    for (position, tx) in challenge_ids.iter().enumerate() {
        let fee = &native.chain.ledger.coins[&id("output", &(*tx, 16u32)).unwrap()];
        assert_eq!(
            fee.payment,
            Payment {
                owner: public(10),
                amount: Amount(3)
            }
        );
        assert_eq!(fee.created, if position == 0 { 7 } else { 2022 });
    }
    progress(&started, &native, &flat, None);
    phase(&started, "native-history", "end", 2032);
    phase(&started, "seal-raw-archive", "begin", 2032);
    let proof = root.join("complete-window-archive");
    let head = seal_format(&proof, scope.clone(), &records, false).0;
    assert_eq!(head, flat.storage_head());
    phase(&started, "seal-raw-archive", "end", 2032);
    let mut observations = Vec::new();
    for selected_height in [5, 2023] {
        let name = format!("query-{selected_height}");
        phase(&started, &name, "begin", 2032);
        let selected = &cuts[&selected_height];
        let query = HistoricalArchiveQueryCandidate {
            format: HISTORICAL_ARCHIVE_QUERY_FORMAT.into(),
            region: h.region,
            checkpoint: selected.selected.id().unwrap(),
        };
        let before = inventory(&root);
        let observed = inspect_historical_archive_candidate(
            &proof,
            &h.bootstrap,
            &public(1),
            h.bootstrap.currency.id().unwrap(),
            head,
            &query,
        )
        .unwrap();
        assert_eq!(inventory(&root), before);
        assert_eq!(observed.selected, selected.selected);
        assert_eq!(
            (observed.currency, observed.trust_binding),
            (h.bootstrap.currency.id().unwrap(), native.trust.binding)
        );
        assert_eq!(observed.selected_ledger_root, selected.root);
        assert_eq!(
            (
                observed.issued,
                observed.liquid,
                observed.escrow,
                observed.pending_transfer
            ),
            selected.totals
        );
        assert_eq!(
            (
                observed.archive_record_count,
                observed.archive_final_height,
                observed.archive_final_checkpoint
            ),
            (2032, 2032, final_checkpoint)
        );
        assert!(observed.complete_genesis_replay && observed.local_history_only);
        assert!(
            !observed.ledger_changed
                && !observed.signing_authority
                && !observed.current_spendability_authority
                && !observed.independent_freshness_verified
                && !observed.incident_safety_verified
                && !observed.import_authority
                && !observed.recovery_authority
        );
        observations.push(observed);
        phase(&started, &name, "end", 2032);
    }
    phase(&started, "seal-bad-final-certificate", "begin", 2032);
    let mut bad = records;
    let Record::Certified(last) = bad.last_mut().unwrap() else {
        unreachable!()
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_dir = root.join("bad-final-certificate");
    let bad_head = seal_format(&bad_dir, scope, &bad, false).0;
    phase(&started, "seal-bad-final-certificate", "end", 2032);
    phase(&started, "reject-complete-bad-tail", "begin", 2032);
    let before = inventory(&root);
    let query = HistoricalArchiveQueryCandidate {
        format: HISTORICAL_ARCHIVE_QUERY_FORMAT.into(),
        region: h.region,
        checkpoint: cuts[&5].selected.id().unwrap(),
    };
    let error = inspect_historical_archive_candidate(
        &bad_dir,
        &h.bootstrap,
        &public(1),
        h.bootstrap.currency.id().unwrap(),
        bad_head,
        &query,
    )
    .unwrap_err();
    assert!(error.contains("signature"), "{error}");
    assert_eq!(inventory(&root), before);
    phase(&started, "reject-complete-bad-tail", "end", 2032);
    println!(
        "channel_window_result={}",
        serde_json::json!({
            "fixture_root": root, "certified_heights": 2032, "records": 2032, "complete_pages": 127,
            "close_height": 6, "absolute_deadline": 2022, "settled_height": 2023,
            "query5_actually_evicted": true, "query2023_actually_evicted": false,
            "final_coin_count": native.chain.ledger.coins.len(), "final_active_snapshots": native.evidence.snapshots.len(),
            "original_budget_amount": reserve_amount, "spent_challenge_fees": Amount(6),
            "returned_reserve": reserve_amount.checked_sub(Amount(6)).unwrap(),
            "milestones": cuts, "observations": observations, "template_refusals": refusals,
            "bad_complete_tail_error": error, "elapsed_seconds": started.elapsed().as_secs_f64(),
            "historical_archive_only": true, "ordinary_agent_qualified": false,
            "custody_qualified": false, "independent_qualified": false, "full_qualification": false,
        })
    );
}
