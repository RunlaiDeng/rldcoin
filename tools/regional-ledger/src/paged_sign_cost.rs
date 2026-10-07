//! Test-only wall-clock observations. No protocol inputs, records or heads.
use std::{
    cell::{Cell, RefCell},
    time::Instant,
};
#[derive(Clone, Default)]
pub(crate) struct Summary {
    pub phases_ns: [u128; 5],
    pub publication_ns: [u128; 3],
    pub append_ns: [u128; 3],
    pub replay_ns: [u128; 3],
    pub completed_old_records: usize,
    pub completed_stream_appends: usize,
    pub completed_new_signatures: usize,
}
thread_local! {
    static COST: RefCell<Summary> = const { RefCell::new(Summary {
        phases_ns: [0; 5], publication_ns: [0; 3], append_ns: [0; 3],
        replay_ns: [0; 3], completed_old_records: 0, completed_stream_appends: 0, completed_new_signatures: 0,
    }) };
    static REPLAY_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static APPEND_ACTIVE: Cell<bool> = const { Cell::new(false) };
}
pub(crate) fn take() -> Summary {
    COST.with(|cost| std::mem::take(&mut *cost.borrow_mut()))
}
pub(crate) struct Clock {
    previous: Instant,
    phases_ns: [u128; 5],
    publication_ns: [u128; 3],
    publication_previous: Option<Instant>,
}
impl Clock {
    pub(crate) fn new() -> Self {
        REPLAY_ACTIVE.with(|active| active.set(true));
        Self {
            previous: Instant::now(),
            phases_ns: [0; 5],
            publication_ns: [0; 3],
            publication_previous: None,
        }
    }
    pub(crate) fn mark(&mut self, phase: usize) {
        if phase == 0 {
            REPLAY_ACTIVE.with(|active| active.set(false));
        }
        let now = Instant::now();
        self.phases_ns[phase] = now.duration_since(self.previous).as_nanos();
        self.previous = now;
        if phase == 3 {
            self.publication_previous = Some(now);
            APPEND_ACTIVE.with(|active| active.set(true));
        }
    }
    pub(crate) fn mark_publication(&mut self, phase: usize) {
        if phase == 0 {
            APPEND_ACTIVE.with(|active| active.set(false));
        }
        let now = Instant::now();
        if let Some(previous) = self.publication_previous {
            self.publication_ns[phase] = now.duration_since(previous).as_nanos();
        }
        self.publication_previous = Some(now);
    }
    pub(crate) fn finish(self) {
        COST.with(|cost| {
            let mut cost = cost.borrow_mut();
            for (sum, part) in cost.phases_ns.iter_mut().zip(self.phases_ns) {
                *sum += part;
            }
            for (sum, part) in cost.publication_ns.iter_mut().zip(self.publication_ns) {
                *sum += part;
            }
            cost.completed_new_signatures += 1;
        });
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        REPLAY_ACTIVE.with(|active| active.set(false));
        APPEND_ACTIVE.with(|active| active.set(false));
    }
}
/// Observe only the original stream append enclosed by the signing clock.
/// Errors do not add a completed observation; there is no protocol input.
pub(crate) struct AppendClock {
    previous: Option<Instant>,
    phases_ns: [u128; 3],
}
impl AppendClock {
    pub(crate) fn new() -> Self {
        Self {
            previous: APPEND_ACTIVE.with(|active| active.get().then(Instant::now)),
            phases_ns: [0; 3],
        }
    }
    pub(crate) fn mark(&mut self, phase: usize) {
        if let Some(previous) = self.previous {
            let now = Instant::now();
            self.phases_ns[phase] = now.duration_since(previous).as_nanos();
            self.previous = Some(now);
        }
    }
    pub(crate) fn finish(self) {
        if self.previous.is_some() {
            COST.with(|cost| {
                let mut cost = cost.borrow_mut();
                for (sum, part) in cost.append_ns.iter_mut().zip(self.phases_ns) {
                    *sum += part;
                }
                cost.completed_stream_appends += 1;
            });
        }
    }
}

/// Time the original old-record replay only, before current state is released.
pub(crate) struct ReplayClock {
    previous: Option<Instant>,
    phases_ns: [u128; 3],
}
impl ReplayClock {
    pub(crate) fn new() -> Self {
        Self {
            previous: REPLAY_ACTIVE.with(|active| active.get().then(Instant::now)),
            phases_ns: [0; 3],
        }
    }
    pub(crate) fn mark(&mut self, phase: usize) {
        if let Some(previous) = self.previous {
            let now = Instant::now();
            self.phases_ns[phase] = now.duration_since(previous).as_nanos();
            self.previous = Some(now);
        }
    }
    pub(crate) fn finish(self) {
        if self.previous.is_some() {
            COST.with(|cost| {
                let mut cost = cost.borrow_mut();
                for (sum, part) in cost.replay_ns.iter_mut().zip(self.phases_ns) {
                    *sum += part;
                }
                cost.completed_old_records += 1;
            });
        }
    }
}
