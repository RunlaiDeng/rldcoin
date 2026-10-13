//! Opt-in fixed-size test observation; no paths, bytes, identities or authority.
use crate::{require, Result};
use serde_json::{json, Value};
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};

const MAX_CALLS: u64 = 256;
const MAX_SYNCS: u64 = 2048;
const ARCHIVE_STAGES: [&str; 5] = [
    "staging-file-sync",
    "staging-directory-sync",
    "retained-file-sync",
    "retained-directory-sync",
    "cleanup-directory-sync",
];
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    ArchiveWrite = 0,
    SyncMany = 1,
    AtomicWrite = 2,
}
#[derive(Clone, Copy, Default)]
struct Row {
    calls: u64,
    succeeded: u64,
    failed: u64,
    seconds: f64,
    sync_calls: u64,
    sync_succeeded: u64,
    sync_failed: u64,
    sync_seconds: f64,
}
struct State {
    rows: [Row; 3],
    archive_stages: [SyncRow; 5],
    current: Option<usize>,
    complete: bool,
}
#[derive(Clone, Copy, Default)]
struct SyncRow {
    calls: u64,
    succeeded: u64,
    failed: u64,
    seconds: f64,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
pub(crate) struct Capture(PhantomData<Rc<()>>);
pub(crate) fn enabled() -> bool {
    STATE.with(|slot| slot.borrow().is_some())
}
pub(crate) fn start() -> Result<Capture> {
    STATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        require(slot.is_none(), "storage measurement already active")?;
        *slot = Some(State {
            rows: [Row::default(); 3],
            archive_stages: [SyncRow::default(); 5],
            current: None,
            complete: true,
        });
        Ok(Capture(PhantomData))
    })
}
impl Capture {
    pub(crate) fn finish(self) -> Value {
        let state = STATE
            .with(|slot| slot.borrow_mut().take())
            .expect("capture is active");
        let rows = ["ArchiveWrite", "SyncMany", "AtomicWrite"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let r = state.rows[index];
                json!({"operation":name,"calls":r.calls,"succeeded":r.succeeded,
                    "failed":r.failed,"kernel_seconds":r.seconds,"sync_calls":r.sync_calls,
                    "sync_succeeded":r.sync_succeeded,"sync_failed":r.sync_failed,
                    "actual_sync_seconds":r.sync_seconds})
            })
            .collect::<Vec<_>>();
        let archive_stages = ARCHIVE_STAGES
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let row = state.archive_stages[index];
                json!({"stage":name,"calls":row.calls,"succeeded":row.succeeded,
                "failed":row.failed,"actual_sync_seconds":row.seconds})
            })
            .collect::<Vec<_>>();
        json!({"complete":state.complete && state.current.is_none(),"rows":rows,
            "archive_stages":archive_stages,"archive_stage_times_partition_archive_sync":true,
            "scope":"storage kernels after bounded ABI validation",
            "operation_times_disjoint":true,"sync_times_disjoint":true,
            "sync_times_nested_in_kernel":true,"ledger_authority":false})
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        STATE.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(crate) fn operation(kind: Kind, work: impl FnOnce() -> Result<Value>) -> Result<Value> {
    let index = kind as usize;
    let enabled = STATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(state) = slot.as_mut() else {
            return false;
        };
        if state.current.is_some() || state.rows[index].calls == MAX_CALLS {
            state.complete = false;
            return false;
        }
        state.rows[index].calls += 1;
        state.current = Some(index);
        true
    });
    if !enabled {
        return work();
    }
    let started = Instant::now();
    let result = work();
    let seconds = started.elapsed().as_secs_f64();
    STATE.with(|slot| {
        if let Some(state) = slot.borrow_mut().as_mut() {
            let row = &mut state.rows[index];
            row.seconds += seconds;
            if result.is_ok() {
                row.succeeded += 1;
            } else {
                row.failed += 1;
            }
            state.current = None;
        }
    });
    result
}
pub(crate) struct SyncStart {
    index: usize,
    archive_stage: Option<usize>,
    started: Instant,
}
pub(crate) fn sync_start(stage: &str) -> Option<SyncStart> {
    let (index, archive_stage) = STATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let state = slot.as_mut()?;
        let index = state.current?;
        if state.rows[index].sync_calls == MAX_SYNCS {
            state.complete = false;
            return None;
        }
        state.rows[index].sync_calls += 1;
        let archive_stage = if index == Kind::ArchiveWrite as usize {
            let stage_index = ARCHIVE_STAGES.iter().position(|name| *name == stage);
            if let Some(stage_index) = stage_index {
                state.archive_stages[stage_index].calls += 1;
            } else {
                state.complete = false;
            }
            stage_index
        } else {
            None
        };
        Some((index, archive_stage))
    })?;
    // Start after observer bookkeeping, immediately before the real sync_all.
    Some(SyncStart {
        index,
        archive_stage,
        started: Instant::now(),
    })
}
pub(crate) fn sync_finish(started: Option<SyncStart>, succeeded: bool) {
    let Some(started) = started else { return };
    // Stop before observer bookkeeping and before io_error formatting.
    let seconds = started.started.elapsed().as_secs_f64();
    STATE.with(|slot| {
        if let Some(state) = slot.borrow_mut().as_mut() {
            let row = &mut state.rows[started.index];
            row.sync_seconds += seconds;
            if succeeded {
                row.sync_succeeded += 1;
            } else {
                row.sync_failed += 1;
            }
            if let Some(index) = started.archive_stage {
                let row = &mut state.archive_stages[index];
                row.seconds += seconds;
                if succeeded {
                    row.succeeded += 1;
                } else {
                    row.failed += 1;
                }
            }
        }
    });
}

#[test]
fn disabled_errors_and_scope_drop_do_not_report_success_or_stale_work() {
    operation(Kind::ArchiveWrite, || Err("disabled".into())).unwrap_err();
    assert!(sync_start("retained-file-sync").is_none());
    let capture = start().unwrap();
    assert!(start().is_err());
    assert_eq!(
        operation(Kind::ArchiveWrite, || Err("observed".into())).unwrap_err(),
        "observed"
    );
    let value = capture.finish();
    assert_eq!(value["complete"], true);
    assert_eq!(value["rows"][0]["calls"], 1);
    assert_eq!(value["rows"][0]["failed"], 1);
    assert_eq!(value["rows"][0]["succeeded"], 0);
    assert_eq!(value["rows"][0]["sync_calls"], 0);
    drop(start().unwrap());
    assert!(sync_start("retained-file-sync").is_none());
    assert_eq!(start().unwrap().finish()["rows"][0]["calls"], 0);
}

#[test]
fn nested_and_exhausted_measurements_are_incomplete_without_changing_results() {
    let capture = start().unwrap();
    operation(Kind::SyncMany, || {
        operation(Kind::AtomicWrite, || Ok(json!("retained")))
    })
    .unwrap();
    assert_eq!(capture.finish()["complete"], false);
    let capture = start().unwrap();
    for _ in 0..=MAX_CALLS {
        assert_eq!(operation(Kind::SyncMany, || Ok(json!(true))).unwrap(), true);
    }
    let value = capture.finish();
    assert_eq!(value["complete"], false);
    assert_eq!(value["rows"][1]["calls"], MAX_CALLS);
    let capture = start().unwrap();
    let error = operation(Kind::SyncMany, || {
        for _ in 0..=MAX_SYNCS {
            sync_finish(sync_start("retained-file-sync"), false);
        }
        Err("sync failure retained".into())
    })
    .unwrap_err();
    assert_eq!(error, "sync failure retained");
    let value = capture.finish();
    assert_eq!(value["complete"], false);
    assert_eq!(value["rows"][1]["failed"], 1);
    assert_eq!(value["rows"][1]["sync_calls"], MAX_SYNCS);
    assert_eq!(value["rows"][1]["sync_succeeded"], 0);
    assert_eq!(value["rows"][1]["sync_failed"], MAX_SYNCS);
}

#[test]
fn archive_stage_partition_is_scoped_and_preserves_failures() {
    let capture = start().unwrap();
    operation(Kind::ArchiveWrite, || {
        for (index, stage) in ARCHIVE_STAGES.into_iter().enumerate() {
            sync_finish(sync_start(stage), index != 2);
        }
        Err("original failure".into())
    })
    .unwrap_err();
    for kind in [Kind::SyncMany, Kind::AtomicWrite] {
        operation(kind, || {
            sync_finish(sync_start("retained-file-sync"), true);
            Ok(json!(null))
        })
        .unwrap();
    }
    let value = capture.finish();
    assert_eq!(value["complete"], true);
    assert_eq!(value["rows"][0]["sync_calls"], 5);
    assert_eq!(value["rows"][0]["sync_failed"], 1);
    let mut seconds = 0.0;
    for (index, row) in value["archive_stages"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(row["stage"], ARCHIVE_STAGES[index]);
        assert_eq!(row["calls"], 1);
        assert_eq!(row["succeeded"], u64::from(index != 2));
        assert_eq!(row["failed"], u64::from(index == 2));
        let elapsed = row["actual_sync_seconds"].as_f64().unwrap();
        assert!(elapsed.is_finite() && elapsed >= 0.0);
        seconds += elapsed;
    }
    assert!((seconds - value["rows"][0]["actual_sync_seconds"].as_f64().unwrap()).abs() < 1e-9);
    let capture = start().unwrap();
    operation(Kind::ArchiveWrite, || {
        sync_finish(sync_start("unknown-stage"), false);
        Err("unknown stage retains error".into())
    })
    .unwrap_err();
    let value = capture.finish();
    assert_eq!(value["complete"], false);
    assert_eq!(value["rows"][0]["sync_failed"], 1);
    assert!(value["archive_stages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["calls"] == 0));
}
