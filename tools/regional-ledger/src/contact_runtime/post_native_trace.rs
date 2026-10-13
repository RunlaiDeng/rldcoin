//! Test-only cumulative work after Native closes, through an actual publication.
//! Inclusive phases can overlap; these observations never authorize custody.
use super::{monotonic, payment_trace_enabled, SUBWORK_TRACE};
use crate::{require, Result};
use serde_json::{json, Value};
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

const PHASES: [&str; 14] = [
    "mesh-open-spool",
    "native-broadcast",
    "native-broadcast-select",
    "native-broadcast-frame-pack",
    "native-broadcast-enqueue",
    "native-broadcast-priority",
    "mesh-archive-completed",
    "mesh-prepare",
    "mesh-state-save-complete",
    "mesh-state-durable-write",
    "mesh-state-encode-transits",
    "mesh-state-decode-expand",
    "transit-full-check",
    "mesh-archive-read-bind",
];
type Totals = [(usize, f64); PHASES.len()];
struct Prefix {
    started: f64,
    clock: Value,
    baseline: Totals,
}
enum State {
    Starting,
    Ready(Box<Prefix>),
}
thread_local! {
    static PREFIX: RefCell<Option<State>> = const { RefCell::new(None) };
}

// Thread-affine because Drop clears the thread-local observation scope.
#[must_use]
pub(super) struct Guard(PhantomData<Rc<()>>);
impl Drop for Guard {
    fn drop(&mut self) {
        PREFIX.with(|prefix| *prefix.borrow_mut() = None);
    }
}
fn snapshot() -> Result<Totals> {
    SUBWORK_TRACE.with(|trace| {
        let trace = trace.borrow();
        let mut totals = [(0, 0.0); PHASES.len()];
        for (index, phase) in PHASES.iter().enumerate() {
            let (calls, seconds) = trace.get(phase).copied().unwrap_or_default();
            require(
                seconds.is_finite() && seconds >= 0.0 && (calls != 0 || seconds == 0.0),
                "post-Native invalid cumulative work",
            )?;
            totals[index] = (calls, seconds);
        }
        Ok(totals)
    })
}
pub(super) fn begin(clock: impl FnOnce() -> Result<Value>) -> Result<Option<Guard>> {
    if !payment_trace_enabled() {
        return Ok(None);
    }
    PREFIX.with(|prefix| -> Result<()> {
        require(prefix.borrow().is_none(), "post-Native trace reentry")?;
        *prefix.borrow_mut() = Some(State::Starting);
        Ok(())
    })?;
    // Reserve before evaluating caller metadata; errors and unwinding clean up.
    let guard = Guard(PhantomData);
    let started = monotonic()?;
    require(
        started.is_finite() && started >= 0.0,
        "post-Native invalid start",
    )?;
    let baseline = snapshot()?;
    let clock = clock()?;
    PREFIX.with(|prefix| {
        *prefix.borrow_mut() = Some(State::Ready(Box::new(Prefix {
            started,
            clock,
            baseline,
        })));
    });
    Ok(Some(guard))
}
pub(super) fn observation(at: f64) -> Result<Option<Value>> {
    if !payment_trace_enabled() {
        return Ok(None);
    }
    PREFIX.with(|prefix| {
        let prefix = prefix.borrow();
        let Some(state) = prefix.as_ref() else {
            return Ok(None);
        };
        let State::Ready(prefix) = state else {
            return Err("post-Native trace is still starting".into());
        };
        require(
            at.is_finite() && at >= prefix.started,
            "post-Native publication precedes start",
        )?;
        let current = snapshot()?;
        let mut phases = Vec::with_capacity(PHASES.len());
        for (index, phase) in PHASES.iter().enumerate() {
            let calls = current[index]
                .0
                .checked_sub(prefix.baseline[index].0)
                .ok_or("post-Native work count moved backwards")?;
            let seconds = current[index].1 - prefix.baseline[index].1;
            require(
                seconds.is_finite() && seconds >= 0.0 && (calls != 0 || seconds == 0.0),
                "post-Native work duration moved backwards or has no call",
            )?;
            phases.push(json!({"phase":phase,"calls":calls,"seconds":seconds}));
        }
        Ok(Some(
            json!({"started":prefix.started,"clock":prefix.clock,"phases":phases,
            "phase_times_overlap":true}),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Isolated {
        work: BTreeMap<&'static str, (usize, f64)>,
        active: bool,
    }
    impl Isolated {
        fn new(active: bool) -> Self {
            PREFIX.with(|prefix| assert!(prefix.borrow().is_none()));
            let work = SUBWORK_TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()));
            let active = super::super::PAYMENT_TRACE_ACTIVE.with(|old| old.replace(active));
            Self { work, active }
        }
    }
    impl Drop for Isolated {
        fn drop(&mut self) {
            PREFIX.with(|prefix| *prefix.borrow_mut() = None);
            SUBWORK_TRACE.with(|trace| *trace.borrow_mut() = std::mem::take(&mut self.work));
            super::super::PAYMENT_TRACE_ACTIVE.with(|active| active.set(self.active));
        }
    }
    fn work(phase: &'static str, calls: usize, seconds: f64) {
        SUBWORK_TRACE.with(|trace| {
            trace.borrow_mut().insert(phase, (calls, seconds));
        });
    }
    fn now() -> f64 {
        monotonic().unwrap()
    }
    fn row(value: &Value, phase: &str) -> Value {
        value["phases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["phase"] == phase)
            .unwrap()
            .clone()
    }

    #[test]
    fn publications_keep_distinct_cumulative_prefixes_and_overlap() {
        let _isolated = Isolated::new(true);
        work("native-broadcast", 4, 8.0);
        let guard = begin(|| Ok(json!({"turn":7}))).unwrap().unwrap();
        work("native-broadcast", 5, 10.0);
        work("mesh-state-save-complete", 1, 1.5);
        work("mesh-state-durable-write", 1, 1.0);
        let first = observation(now()).unwrap().unwrap();
        assert_eq!(first["phases"].as_array().unwrap().len(), 14);
        assert_eq!(first["clock"], json!({"turn":7}));
        assert_eq!(row(&first, "native-broadcast")["seconds"], 2.0);
        assert_eq!(row(&first, "mesh-state-save-complete")["seconds"], 1.5);
        assert_eq!(row(&first, "mesh-state-durable-write")["seconds"], 1.0);
        assert_eq!(row(&first, "mesh-prepare")["calls"], 0);
        assert_eq!(row(&first, "mesh-prepare")["seconds"], 0.0);
        assert_eq!(first["phase_times_overlap"], true);
        assert!(first.get("total_seconds").is_none());
        work("native-broadcast", 6, 13.0);
        let second = observation(now()).unwrap().unwrap();
        assert_eq!(row(&second, "native-broadcast")["calls"], 2);
        assert_eq!(row(&second, "native-broadcast")["seconds"], 5.0);
        assert_eq!(first["started"], second["started"]);
        assert_eq!(row(&first, "native-broadcast")["seconds"], 2.0);
        drop(guard);
        assert!(observation(now()).unwrap().is_none());
    }

    #[test]
    fn disabled_reentry_and_error_cleanup_never_construct_or_leave_stale_scope() {
        let _isolated = Isolated::new(false);
        assert!(begin(|| panic!("disabled clock constructed"))
            .unwrap()
            .is_none());
        assert!(observation(f64::NAN).unwrap().is_none());
        assert!(PREFIX.with(|prefix| prefix.borrow().is_none()));
        super::super::PAYMENT_TRACE_ACTIVE.with(|active| active.set(true));
        let failed = begin(|| {
            assert!(begin(|| panic!("reentry clock constructed")).is_err());
            Err("metadata refused".into())
        });
        assert!(failed.is_err());
        assert!(observation(now()).unwrap().is_none());
        let guard = begin(|| Ok(json!({"turn":1}))).unwrap().unwrap();
        assert!(begin(|| panic!("active reentry clock constructed")).is_err());
        super::super::PAYMENT_TRACE_ACTIVE.with(|active| active.set(false));
        assert!(begin(|| panic!("disabled active clock constructed"))
            .unwrap()
            .is_none());
        assert!(observation(f64::INFINITY).unwrap().is_none());
        super::super::PAYMENT_TRACE_ACTIVE.with(|active| active.set(true));
        assert_eq!(
            observation(now()).unwrap().unwrap()["clock"],
            json!({"turn":1})
        );
        drop(guard);
        let guard = begin(|| Ok(json!({"turn":2}))).unwrap().unwrap();
        assert_eq!(
            observation(now()).unwrap().unwrap()["clock"],
            json!({"turn":2})
        );
        drop(guard);
        assert!(observation(now()).unwrap().is_none());
    }

    #[test]
    fn invalid_cumulative_counts_durations_and_publication_clocks_refuse() {
        let _isolated = Isolated::new(true);
        for (calls, seconds) in [
            (1, 2.0),
            (2, 1.0),
            (3, -1.0),
            (3, f64::NAN),
            (3, f64::INFINITY),
            (3, f64::NEG_INFINITY),
            (2, 3.0),
        ] {
            work("mesh-prepare", 2, 2.0);
            let guard = begin(|| Ok(Value::Null)).unwrap().unwrap();
            work("mesh-prepare", calls, seconds);
            assert!(observation(now()).is_err());
            drop(guard);
            assert!(observation(now()).unwrap().is_none());
        }
        work("mesh-prepare", 0, 1.0);
        assert!(begin(|| panic!("invalid baseline built metadata")).is_err());
        work("mesh-prepare", 0, 0.0);
        let guard = begin(|| Ok(Value::Null)).unwrap().unwrap();
        let started = observation(now()).unwrap().unwrap()["started"]
            .as_f64()
            .unwrap();
        for at in [started - 1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(observation(at).is_err());
        }
        drop(guard);
    }
}
