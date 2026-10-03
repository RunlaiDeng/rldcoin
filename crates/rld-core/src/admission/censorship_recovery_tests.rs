//! State-machine regressions, not authenticated recovery certificates. Runtime
//! recovery must still derive observations/resolutions from verified history.
use super::*;

fn hash(n: u8) -> AdmissionHash32 {
    AdmissionHash32([n; 32])
}

fn fixture(epoch: u128) -> (AdmissionCensorshipGuardV1, PreparedAdmissionCheckpointV1) {
    let genesis = crate::M0GenesisManifestFile::decode_json(include_bytes!(
        "../../../../vectors/m0-genesis-v3/manifest.json"
    ))
    .unwrap();
    let context = genesis.admission_genesis().context.clone();
    let prepared = PreparedAdmissionCheckpointV1 {
        checkpoint: AdmissionCheckpointV1 {
            context: context.clone(),
            admission_era: 0,
            header_id: hash(2),
            log_height: 1,
            cumulative_work: AdmissionWork([2, 0, 0, 0]),
            confirmations: 32,
            descendant_work: AdmissionWork([64, 0, 0, 0]),
            entries_root: admission_entry_root([hash(3)]).unwrap(),
            availability_root: hash(4),
            observed_ledger_epoch: epoch,
            committed_ledger_epoch: epoch,
        },
        prior_committed_header: genesis.admission_genesis().genesis_header,
        entry_ids: vec![hash(3)],
        observed_ledger_height: epoch,
        committing_ledger_height: epoch,
    };
    (
        AdmissionCensorshipGuardV1::new(context, epoch, hash(1)).unwrap(),
        prepared,
    )
}

fn recovering(epoch: u128) -> (AdmissionCensorshipGuardV1, PreparedAdmissionCheckpointV1) {
    let (mut guard, prepared) = fixture(epoch);
    guard
        .observe_confirmed_prefix(epoch, &prepared, hash(1))
        .unwrap();
    let stalled_epoch = epoch.checked_add(3).unwrap();
    guard.advance_epoch(stalled_epoch, hash(5)).unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::CensorshipStalled
    );
    guard
        .record_ledger_resolution(
            &AdmissionLedgerResolutionV1 {
                ledger_epoch: stalled_epoch,
                checkpoint_id: prepared.checkpoint.checkpoint_id(),
                included_entries: BTreeSet::from([hash(3)]),
                rejection_proofs: BTreeMap::new(),
            },
            hash(5),
        )
        .unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::RecoveryChallenge
    );
    (guard, prepared)
}

#[test]
fn rejected_observation_never_partially_adds_pending_entries() {
    let (mut guard, mut prepared) = fixture(5);
    prepared.entry_ids = vec![hash(3), AdmissionHash32::ZERO];
    prepared.checkpoint.entries_root =
        admission_entry_root(prepared.entry_ids.iter().copied()).unwrap();
    let before = guard.clone();
    assert!(guard
        .observe_confirmed_prefix(5, &prepared, hash(1))
        .is_err());
    assert_eq!(guard, before);
}

#[test]
fn recovery_preserves_one_complete_following_epoch_before_clearing() {
    let (mut guard, _) = recovering(5);
    // Resolution may finalize at the last block of epoch 8. Entering epoch 9
    // is not evidence that its complete challenge interval has elapsed.
    guard.advance_epoch(9, hash(6)).unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::RecoveryChallenge
    );
    assert!(!guard.may_sign_consensus());
    assert!(!guard.may_accept_value_eligible_finality());
    assert!(!guard.may_raise_value_cap());
    assert_eq!(guard.last_value_eligible_asset_root(), hash(1));
    guard.advance_epoch(10, hash(7)).unwrap();
    assert_eq!(guard.status(), AdmissionCensorshipStatusV1::Healthy);
    assert_eq!(guard.last_value_eligible_asset_root(), hash(7));
    guard.validate_recovered().unwrap();
}

#[test]
fn exact_observation_retry_cannot_recreate_a_resolved_obligation() {
    let (mut guard, prepared) = recovering(5);
    let before = guard.clone();
    guard
        .observe_confirmed_prefix(8, &prepared, hash(5))
        .unwrap();
    assert_eq!(guard, before);
    guard.advance_epoch(10, hash(7)).unwrap();
    guard
        .observe_confirmed_prefix(10, &prepared, hash(7))
        .unwrap();
    guard.advance_epoch(13, hash(8)).unwrap();
    assert!(guard.pending_entries().is_empty());
    assert_eq!(guard.status(), AdmissionCensorshipStatusV1::Healthy);
    guard.validate_recovered().unwrap();
}

#[test]
fn rehashed_recovery_history_cannot_claim_an_unelapsed_challenge() {
    for cleared_epoch in [8, 9] {
        let (mut guard, _) = recovering(5);
        guard.status = AdmissionCensorshipStatusV1::Healthy;
        guard.last_ledger_epoch = cleared_epoch;
        guard.recovery_started_epoch = None;
        guard
            .record_event(
                AdmissionCensorshipEventKindV1::ClearedAfterChallenge,
                cleared_epoch,
                guard.last_confirmed_checkpoint,
            )
            .unwrap();
        assert!(guard.validate_recovered().is_err());
    }
}

#[test]
fn u128_boundary_cannot_wrap_or_shorten_the_recovery_challenge() {
    let (mut guard, _) = recovering(u128::MAX - 4);
    guard.advance_epoch(u128::MAX, hash(6)).unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::RecoveryChallenge
    );
    assert_eq!(guard.history().len(), 2);
    assert_eq!(guard.last_value_eligible_asset_root(), hash(1));
    let before = guard.clone();
    assert!(guard.advance_epoch(0, hash(7)).is_err());
    assert_eq!(guard, before);
    guard.validate_recovered().unwrap();
}

#[test]
fn recovered_obligations_require_a_confirmed_position_and_nonzero_ids() {
    let (mut no_checkpoint, _) = fixture(5);
    no_checkpoint.pending_entries.insert(hash(3), 5);
    assert!(no_checkpoint.validate_recovered().is_err());
    let (mut guard, prepared) = fixture(5);
    guard
        .observe_confirmed_prefix(5, &prepared, hash(1))
        .unwrap();
    guard.pending_entries.insert(AdmissionHash32::ZERO, 5);
    assert!(guard.validate_recovered().is_err());
}

#[test]
fn recovered_rehashed_events_cannot_replace_the_protected_root_or_unresolved_scope() {
    for replace_root in [false, true] {
        let (mut guard, _) = recovering(5);
        let event = &mut guard.history[1];
        if replace_root {
            event.protected_asset_root = hash(9);
        } else {
            event.unresolved_root = admission_entry_root([hash(3)]).unwrap();
        }
        event.event_hash = event.expected_hash();
        assert!(guard.validate_recovered().is_err());
    }
}

#[test]
fn invalid_prestate_cannot_be_healed_by_a_new_clock_observation_or_resolution() {
    let (mut broken, prepared) = fixture(5);
    broken
        .observe_confirmed_prefix(5, &prepared, hash(1))
        .unwrap();
    broken.pending_entries.insert(hash(3), 6);
    assert!(broken.validate_recovered().is_err());
    let mut candidate = broken.clone();
    assert!(candidate.advance_epoch(6, hash(5)).is_err());
    assert_eq!(candidate, broken);
    assert!(candidate
        .observe_confirmed_prefix(6, &prepared, hash(5))
        .is_err());
    assert_eq!(candidate, broken);
    assert!(candidate
        .record_ledger_resolution(
            &AdmissionLedgerResolutionV1 {
                ledger_epoch: 6,
                checkpoint_id: prepared.checkpoint.checkpoint_id(),
                included_entries: BTreeSet::from([hash(3)]),
                rejection_proofs: BTreeMap::new(),
            },
            hash(5)
        )
        .is_err());
    assert_eq!(candidate, broken);
}

#[test]
fn partial_resolution_and_new_overdue_work_preserve_stall_until_a_new_full_challenge() {
    let (mut guard, mut prepared) = fixture(5);
    prepared.entry_ids.push(hash(8));
    prepared.checkpoint.entries_root =
        admission_entry_root(prepared.entry_ids.iter().copied()).unwrap();
    guard
        .observe_confirmed_prefix(5, &prepared, hash(1))
        .unwrap();
    guard.advance_epoch(8, hash(5)).unwrap();
    let resolution = |checkpoint_id, entry, epoch| AdmissionLedgerResolutionV1 {
        ledger_epoch: epoch,
        checkpoint_id,
        included_entries: BTreeSet::from([entry]),
        rejection_proofs: BTreeMap::new(),
    };
    guard
        .record_ledger_resolution(
            &resolution(prepared.checkpoint.checkpoint_id(), hash(3), 8),
            hash(5),
        )
        .unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::CensorshipStalled
    );
    assert_eq!(guard.history().len(), 1);
    let mut next = prepared.clone();
    next.checkpoint.header_id = hash(9);
    next.checkpoint.log_height = 2;
    next.checkpoint.cumulative_work = AdmissionWork([4, 0, 0, 0]);
    next.entry_ids = vec![hash(10)];
    next.checkpoint.entries_root = admission_entry_root(next.entry_ids.iter().copied()).unwrap();
    guard.observe_confirmed_prefix(8, &next, hash(5)).unwrap();
    guard.advance_epoch(9, hash(6)).unwrap();
    guard
        .record_ledger_resolution(
            &resolution(next.checkpoint.checkpoint_id(), hash(8), 9),
            hash(6),
        )
        .unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::RecoveryChallenge
    );
    guard.advance_epoch(10, hash(7)).unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::RecoveryChallenge
    );
    // New work becomes overdue at epoch 11; it cannot be hidden by the old
    // recovery timer reaching its nominal end at the same boundary.
    guard.advance_epoch(11, hash(11)).unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::CensorshipStalled
    );
    assert_eq!(
        guard.history().last().unwrap().kind,
        AdmissionCensorshipEventKindV1::RecoveryReopened
    );
    assert_eq!(guard.last_value_eligible_asset_root(), hash(1));
    guard
        .record_ledger_resolution(
            &resolution(next.checkpoint.checkpoint_id(), hash(10), 11),
            hash(11),
        )
        .unwrap();
    guard.advance_epoch(12, hash(12)).unwrap();
    assert_eq!(
        guard.status(),
        AdmissionCensorshipStatusV1::RecoveryChallenge
    );
    guard.advance_epoch(13, hash(13)).unwrap();
    assert_eq!(guard.status(), AdmissionCensorshipStatusV1::Healthy);
    guard.validate_recovered().unwrap();
}
