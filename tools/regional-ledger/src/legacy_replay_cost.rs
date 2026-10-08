//! Test-only observations of complete legacy custody ancestry replay.
//! Timings and counts are never protocol inputs or persisted authority.
use std::{cell::RefCell, time::Instant};

const DEPTHS: usize = crate::epoch::MAX_EPOCHS + 1;
#[derive(Clone, serde::Serialize)]
pub(crate) struct Cost {
    pub header_attempts_by_depth: [usize; DEPTHS],
    pub header_inclusive_ns_by_depth: [u128; DEPTHS],
    pub record_attempts_by_depth: [usize; DEPTHS],
    pub record_ns_by_depth: [u128; DEPTHS],
}
thread_local! {
    static COST: RefCell<Cost> = const { RefCell::new(Cost {
        header_attempts_by_depth: [0; DEPTHS],
        header_inclusive_ns_by_depth: [0; DEPTHS],
        record_attempts_by_depth: [0; DEPTHS],
        record_ns_by_depth: [0; DEPTHS],
    }) };
}
pub(crate) fn take() -> Cost {
    COST.with(|cost| {
        cost.replace(Cost {
            header_attempts_by_depth: [0; DEPTHS],
            header_inclusive_ns_by_depth: [0; DEPTHS],
            record_attempts_by_depth: [0; DEPTHS],
            record_ns_by_depth: [0; DEPTHS],
        })
    })
}
pub(crate) struct Clock {
    start: Instant,
    depth: usize,
    header: bool,
}
impl Clock {
    pub(crate) fn header(depth: usize) -> Self {
        Self {
            start: Instant::now(),
            depth: depth.min(DEPTHS - 1),
            header: true,
        }
    }
    pub(crate) fn record(depth: usize) -> Self {
        Self {
            start: Instant::now(),
            depth: depth.min(DEPTHS - 1),
            header: false,
        }
    }
}
impl Drop for Clock {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_nanos();
        COST.with(|cost| {
            let mut cost = cost.borrow_mut();
            if self.header {
                cost.header_attempts_by_depth[self.depth] += 1;
                cost.header_inclusive_ns_by_depth[self.depth] += elapsed;
            } else {
                cost.record_attempts_by_depth[self.depth] += 1;
                cost.record_ns_by_depth[self.depth] += elapsed;
            }
        });
    }
}
