//! Test-only scalar observations of actual complete Onward Native execution.
//! No proof bytes, ledger, keys, paths, or verification verdict can be supplied.
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
    time::Instant,
};

#[derive(Clone, serde::Serialize)]
pub(crate) struct Summary {
    pub calls: u64,
    pub successful: u64,
    pub failed: u64,
    pub seconds: f64,
    pub outermost_seconds: f64,
    pub verification_calls: u64,
    pub verification_seconds: f64,
    pub max_depth: u64,
    pub complete: bool,
}
impl Default for Summary {
    fn default() -> Self {
        Self {
            calls: 0,
            successful: 0,
            failed: 0,
            seconds: 0.0,
            outermost_seconds: 0.0,
            verification_calls: 0,
            verification_seconds: 0.0,
            max_depth: 0,
            complete: true,
        }
    }
}
#[derive(Default)]
struct State {
    summary: Summary,
    depth: u64,
}
thread_local! {
    static ACTIVE: RefCell<Option<Rc<RefCell<State>>>> = const { RefCell::new(None) };
    static VERIFICATION: Cell<bool> = const { Cell::new(false) };
}

/// Marks only the existing verify_anchors call to execute_for, never the route
/// preflight or an independently invoked Native installation.
pub(crate) struct Verification {
    previous: bool,
    _same_thread: PhantomData<Rc<()>>,
}
impl Verification {
    pub(crate) fn enter() -> Self {
        Self {
            previous: VERIFICATION.with(|purpose| purpose.replace(true)),
            _same_thread: PhantomData,
        }
    }
}
impl Drop for Verification {
    fn drop(&mut self) {
        VERIFICATION.with(|purpose| purpose.set(self.previous));
    }
}

/// One synchronous measured operation owns its observations. Nested observers
/// are isolated and restore their caller, including on an error or unwind.
pub(crate) struct Scope {
    state: Rc<RefCell<State>>,
    previous: Option<Rc<RefCell<State>>>,
    previous_purpose: bool,
}
impl Scope {
    pub(crate) fn begin() -> Self {
        let state = Rc::new(RefCell::new(State::default()));
        let previous = ACTIVE.with(|active| active.replace(Some(state.clone())));
        if let Some(previous) = &previous {
            // A nested operation cannot make its paused parent's coverage whole.
            previous.borrow_mut().summary.complete = false;
        }
        let previous_purpose = VERIFICATION.with(|purpose| purpose.replace(false));
        Self {
            state,
            previous,
            previous_purpose,
        }
    }
    pub(crate) fn finish(self) -> Summary {
        let mut state = self.state.borrow_mut();
        if state.depth != 0
            || state.summary.successful.checked_add(state.summary.failed)
                != Some(state.summary.calls)
        {
            state.summary.complete = false;
        }
        state.summary.clone()
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let _ = ACTIVE.with(|active| active.replace(self.previous.take()));
        VERIFICATION.with(|purpose| purpose.set(self.previous_purpose));
    }
}

struct Running {
    state: Rc<RefCell<State>>,
    started: Instant,
    outermost: bool,
    successful: bool,
    verification: bool,
}
pub(crate) struct Span(Option<Running>);
impl Span {
    pub(crate) fn start() -> Self {
        Self::with_clock(Instant::now)
    }
    fn with_clock(clock: impl FnOnce() -> Instant) -> Self {
        let state = ACTIVE.with(|active| active.borrow().clone());
        let Some(state) = state else {
            return Self(None);
        };
        let verification = VERIFICATION.with(Cell::get);
        let outermost;
        {
            let mut data = state.borrow_mut();
            outermost = data.depth == 0;
            let bounded = data.summary.calls != u64::MAX && data.depth != u64::MAX;
            data.summary.complete &= bounded;
            data.summary.calls = data.summary.calls.saturating_add(1);
            if verification {
                data.summary.verification_calls = data.summary.verification_calls.saturating_add(1);
            }
            data.depth = data.depth.saturating_add(1);
            data.summary.max_depth = data.summary.max_depth.max(data.depth);
        }
        Self(Some(Running {
            state,
            started: clock(),
            outermost,
            successful: false,
            verification,
        }))
    }
    /// Mark only after all original fallible execution and derived bounds pass.
    pub(crate) fn succeeded(&mut self) {
        if let Some(running) = &mut self.0 {
            running.successful = true;
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(running) = &self.0 else {
            return;
        };
        // Read elapsed before observer bookkeeping; nested spans are explicit.
        let elapsed = running.started.elapsed().as_secs_f64();
        let mut data = running.state.borrow_mut();
        data.summary.seconds += elapsed;
        if running.verification {
            data.summary.verification_seconds += elapsed;
        }
        if running.outermost {
            data.summary.outermost_seconds += elapsed;
        }
        if running.successful {
            data.summary.successful = data.summary.successful.saturating_add(1);
        } else {
            data.summary.failed = data.summary.failed.saturating_add(1);
        }
        let bounded = data.depth > 0
            && data.summary.seconds.is_finite()
            && data.summary.outermost_seconds.is_finite()
            && data.summary.verification_seconds.is_finite();
        data.summary.complete &= bounded;
        data.depth = data.depth.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_span() -> Result<(), ()> {
        let _inner = Span::start();
        Err(())
    }

    fn failed_verification() -> Result<(), ()> {
        let _inner_purpose = Verification::enter();
        drop(Span::start());
        Err(())
    }

    #[test]
    fn disabled_and_nested_scopes_do_not_leak_counts_or_construct_clocks() {
        drop(Span::with_clock(|| panic!("disabled clock")));
        let outer = Scope::begin();
        let outer_span = Span::start();
        let outer_purpose = Verification::enter();
        let inner = Scope::begin();
        let mut inner_span = Span::start();
        inner_span.succeeded();
        drop(inner_span);
        let result = inner.finish();
        assert!(result.complete);
        assert_eq!((result.calls, result.successful, result.failed), (1, 1, 0));
        assert_eq!(result.verification_calls, 0); // No inherited purpose.
        assert!(VERIFICATION.with(Cell::get));
        drop(outer_purpose);
        drop(outer_span);
        let result = outer.finish();
        assert!(!result.complete); // Paused by the separate inner operation.
        assert_eq!((result.calls, result.successful, result.failed), (1, 0, 1));
        drop(Span::with_clock(|| panic!("stale clock")));
    }

    #[test]
    fn nested_execution_failures_and_unfinished_scopes_remain_explicit() {
        let scope = Scope::begin();
        let mut outer = Span::start();
        let result = failed_span();
        assert!(result.is_err());
        outer.succeeded();
        drop(outer);
        let result = scope.finish();
        assert!(result.complete);
        assert_eq!(
            (
                result.calls,
                result.successful,
                result.failed,
                result.max_depth
            ),
            (2, 1, 1, 2)
        );
        assert!(result.seconds >= result.outermost_seconds && result.outermost_seconds >= 0.0);
        let scope = Scope::begin();
        let pending = Span::start();
        assert!(!scope.finish().complete);
        drop(pending);
        drop(Span::with_clock(|| panic!("unfinished scope leaked")));

        let scope = Scope::begin();
        drop(Span::start()); // Independent installation classification.
        let outer_purpose = Verification::enter();
        let result = failed_verification();
        assert!(result.is_err());
        drop(Span::start()); // Inner error restored the outer purpose.
        drop(outer_purpose);
        drop(Span::start()); // No stale verification purpose.
        let result = scope.finish();
        assert!(result.complete);
        assert_eq!(
            (result.calls, result.failed, result.verification_calls),
            (4, 4, 2)
        );
        assert!(result.verification_seconds <= result.seconds);
    }
}
