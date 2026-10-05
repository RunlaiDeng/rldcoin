//! Test-only wall-clock observations. No protocol inputs, records or heads.
use std::{cell::RefCell, time::Instant};
#[derive(Clone, Default)]
pub(crate) struct Summary {
    pub phases_ns: [u128; 5],
    pub completed_new_signatures: usize,
}
thread_local! {
    static COST: RefCell<Summary> = const { RefCell::new(Summary {
        phases_ns: [0; 5], completed_new_signatures: 0,
    }) };
}
pub(crate) fn take() -> Summary {
    COST.with(|cost| std::mem::take(&mut *cost.borrow_mut()))
}
pub(crate) struct Clock {
    previous: Instant,
    phases_ns: [u128; 5],
}
impl Clock {
    pub(crate) fn new() -> Self {
        Self {
            previous: Instant::now(),
            phases_ns: [0; 5],
        }
    }
    pub(crate) fn mark(&mut self, phase: usize) {
        let now = Instant::now();
        self.phases_ns[phase] = now.duration_since(self.previous).as_nanos();
        self.previous = now;
    }
    pub(crate) fn finish(self) {
        COST.with(|cost| {
            let mut cost = cost.borrow_mut();
            for (sum, part) in cost.phases_ns.iter_mut().zip(self.phases_ns) {
                *sum += part;
            }
            cost.completed_new_signatures += 1;
        });
    }
}
