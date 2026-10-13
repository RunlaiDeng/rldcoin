//! Test-only, optional scalar boundaries around one unmodified Runtime open.
use crate::bft_onward_network::execution_cost;
use serde_json::{json, Value};
use std::time::Instant;

const NAMES: [&str; 6] = [
    "archive_auth_seconds",
    "caller_reconcile_seconds",
    "startup_flush_seconds",
    "agent_open_seconds",
    "retained_messages_seconds",
    "local_retention_seconds",
];

#[derive(Clone, Copy)]
pub(super) enum Phase {
    ArchiveAuth,
    CallerReconcile,
    StartupFlush,
    AgentOpen,
    RetainedMessages,
    LocalRetention,
}

pub(super) struct Observation {
    started: Instant,
    seconds: [Option<f64>; 6],
    successful: [bool; 6],
    intact: bool,
    pending_seen: Option<bool>,
    outbox_seen: Option<bool>,
    archive_execution: Option<execution_cost::Summary>,
    local_calls: Option<LocalCalls>,
}
impl Observation {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            seconds: [None; 6],
            successful: [false; 6],
            intact: true,
            pending_seen: None,
            outbox_seen: None,
            archive_execution: None,
            local_calls: None,
        }
    }
    pub(super) fn with_local_calls() -> Self {
        Self {
            local_calls: Some(LocalCalls::new()),
            ..Self::new()
        }
    }
    pub(super) fn finish(self, successful: bool) -> Value {
        // Capture the whole call before summary construction.
        let total = self.started.elapsed().as_secs_f64();
        let measured: f64 = self.seconds.iter().flatten().sum();
        let valid = total.is_finite()
            && measured.is_finite()
            && self
                .seconds
                .iter()
                .flatten()
                .all(|v| v.is_finite() && *v >= 0.0)
            && measured <= total;
        let mut report = json!({
            "runtime_open_seconds": total,
            "measured_seconds": measured,
            "residual_seconds": if valid { Some(total - measured) } else { None },
            "pending_seen": self.pending_seen,
            "outbox_seen": self.outbox_seen,
            "archive_execution": self.archive_execution,
            "successful": successful,
            "complete": successful && valid && self.intact
                && self.successful.iter().all(|v| *v)
                && self.pending_seen.is_some() && self.outbox_seen.is_some(),
            "phase_success": {},
        });
        for (i, name) in NAMES.iter().enumerate() {
            report[*name] = json!(self.seconds[i]);
            report["phase_success"][name.trim_end_matches("_seconds")] = json!(self.successful[i]);
        }
        if let Some(calls) = self.local_calls {
            let complete = calls.complete();
            report["complete"] = json!(report["complete"] == true && complete);
            report["local_calls"] = json!({
                "entered": calls.entered,
                "completed": calls.rows.iter().flatten().filter(|row| row.completed).count(),
                "overflow": calls.overflow,
                "complete": complete,
                "rows": calls.rows,
            });
        }
        report
    }
}

pub(super) struct Span<'a> {
    observation: &'a mut Observation,
    phase: Phase,
    started: Instant,
    successful: bool,
    execution: Option<execution_cost::Scope>,
}
pub(super) fn start(observation: Option<&mut Observation>, phase: Phase) -> Option<Span<'_>> {
    start_with_clock(observation, phase, Instant::now)
}
fn start_with_clock(
    observation: Option<&mut Observation>,
    phase: Phase,
    clock: impl FnOnce() -> Instant,
) -> Option<Span<'_>> {
    let observation = observation?;
    // Only the actual archive authentication call owns execution observations.
    let execution = matches!(phase, Phase::ArchiveAuth).then(execution_cost::Scope::begin);
    Some(Span {
        observation,
        phase,
        started: clock(),
        successful: false,
        execution,
    })
}
pub(super) fn finish(span: Option<Span<'_>>) {
    if let Some(mut span) = span {
        span.successful = true;
    }
}
pub(super) fn caller_state(span: &mut Option<Span<'_>>, pending: bool, outbox: bool) {
    if let Some(span) = span {
        span.observation.pending_seen = Some(pending);
        span.observation.outbox_seen = Some(outbox);
    }
}
impl Drop for Span<'_> {
    fn drop(&mut self) {
        // Read time before observer bookkeeping. Early return retains failure.
        let seconds = self.started.elapsed().as_secs_f64();
        if let Some(scope) = self.execution.take() {
            self.observation.archive_execution = Some(scope.finish());
        }
        let index = self.phase as usize;
        if self.observation.seconds[index].is_some() {
            // Repeated phase calls cannot silently become complete coverage.
            self.observation.intact = false;
        } else {
            self.observation.seconds[index] = Some(seconds);
            self.observation.successful[index] = self.successful;
        }
    }
}

// Explicit two-slot storage belongs to this test open only. It is never TLS,
// a Runtime field, an authority input, or a reason to skip an original call.
struct LocalCalls {
    entered: u64,
    overflow: bool,
    rows: [Option<LocalCall>; 2],
}
impl LocalCalls {
    fn new() -> Self {
        Self {
            entered: 0,
            overflow: false,
            rows: [None, None],
        }
    }
    fn next(&mut self, kind: &'static str) -> Option<&mut LocalCall> {
        let index = self.entered;
        self.entered = self.entered.saturating_add(1);
        if index >= 2 {
            self.overflow = true;
            return None;
        }
        let row = &mut self.rows[index as usize];
        *row = Some(LocalCall {
            kind,
            completed: false,
            successful: false,
            intact: true,
            construct: None,
            retain: None,
        });
        row.as_mut()
    }
    fn complete(&self) -> bool {
        !self.overflow
            && self.entered == 2
            && self.rows.iter().all(|row| {
                row.as_ref().is_some_and(|row| {
                    row.completed
                        && row.successful
                        && row.intact
                        && [&row.construct, &row.retain].iter().all(|part| {
                            part.as_ref().is_some_and(|part| {
                                part.returned
                                    && part.successful
                                    && part.seconds.is_finite()
                                    && part.seconds >= 0.0
                                    && part.execution.complete
                            })
                        })
                })
            })
    }
}
#[derive(serde::Serialize)]
pub(super) struct LocalCall {
    kind: &'static str,
    completed: bool,
    successful: bool,
    #[serde(skip)]
    intact: bool,
    construct: Option<LocalSegment>,
    retain: Option<LocalSegment>,
}
#[derive(serde::Serialize)]
struct LocalSegment {
    seconds: f64,
    returned: bool,
    successful: bool,
    execution: execution_cost::Summary,
}
#[derive(Clone, Copy)]
pub(super) enum LocalPart {
    Construct,
    Retain,
}
pub(super) fn local_slot<'a>(
    phase: &'a mut Option<Span<'_>>,
    body: &crate::bft_network::Body,
) -> Option<&'a mut LocalCall> {
    let phase = phase.as_mut()?;
    let calls = phase.observation.local_calls.as_mut()?;
    if !matches!(phase.phase, Phase::LocalRetention) {
        phase.observation.intact = false;
        return None;
    }
    let kind = match body {
        crate::bft_network::Body::Signed(message)
            if matches!(message.as_ref(), crate::bft::Message::Timeout(_)) =>
        {
            "signed-timeout"
        }
        crate::bft_network::Body::Finalized(_) => "finalized",
        _ => "other",
    };
    calls.next(kind)
}
pub(super) struct LocalSpan<'a> {
    row: &'a mut LocalCall,
    part: LocalPart,
    scope: Option<execution_cost::Scope>,
    started: Instant,
    returned: bool,
    successful: bool,
}
pub(super) fn local_start(row: Option<&mut LocalCall>, part: LocalPart) -> Option<LocalSpan<'_>> {
    local_start_with_clock(row, part, Instant::now)
}
fn local_start_with_clock(
    row: Option<&mut LocalCall>,
    part: LocalPart,
    clock: impl FnOnce() -> Instant,
) -> Option<LocalSpan<'_>> {
    let row = row?;
    let scope = execution_cost::Scope::begin();
    Some(LocalSpan {
        row,
        part,
        scope: Some(scope),
        started: clock(),
        returned: false,
        successful: false,
    })
}
pub(super) fn local_finish(span: Option<LocalSpan<'_>>, successful: bool) {
    if let Some(mut span) = span {
        span.returned = true;
        span.successful = successful;
    }
}
impl Drop for LocalSpan<'_> {
    fn drop(&mut self) {
        let seconds = self.started.elapsed().as_secs_f64();
        let execution = self
            .scope
            .take()
            .expect("one local observation Scope")
            .finish();
        let output = match self.part {
            LocalPart::Construct => &mut self.row.construct,
            LocalPart::Retain => &mut self.row.retain,
        };
        let fresh = output.is_none();
        if fresh {
            *output = Some(LocalSegment {
                seconds,
                returned: self.returned,
                successful: self.successful,
                execution,
            });
        }
        if self.returned && (!self.successful || matches!(self.part, LocalPart::Retain)) {
            self.row.completed = true;
            self.row.successful = fresh && self.successful && self.row.intact;
        }
        if !fresh || !self.returned || !self.successful {
            self.row.intact = false;
            self.row.successful = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_open_probe_has_no_clock_or_execution_scope() {
        let outer = execution_cost::Scope::begin();
        drop(start_with_clock(None, Phase::ArchiveAuth, || {
            panic!("inactive clock")
        }));
        let mut span = execution_cost::Span::start();
        span.succeeded();
        drop(span);
        let summary = outer.finish();
        assert!(summary.complete); // No nested observer was constructed.
        assert_eq!(
            (summary.calls, summary.successful, summary.failed),
            (1, 1, 0)
        );
    }

    #[test]
    fn early_drop_and_repeated_open_phase_cannot_report_complete() {
        let mut observed = Observation::new();
        {
            let _phase = start(Some(&mut observed), Phase::ArchiveAuth);
            drop(execution_cost::Span::start());
        }
        let partial = observed.finish(false);
        assert_eq!(partial["successful"], false);
        assert_eq!(partial["complete"], false);
        assert_eq!(partial["phase_success"]["archive_auth"], false);
        assert!(partial["archive_auth_seconds"].as_f64().unwrap() >= 0.0);
        assert_eq!(partial["caller_reconcile_seconds"], Value::Null);
        assert_eq!(partial["archive_execution"]["failed"], 1);
        assert_eq!(partial["archive_execution"]["successful"], 0);
        assert_eq!(partial["archive_execution"]["complete"], true);
        let mut complete = Observation::new();
        finish(start(Some(&mut complete), Phase::ArchiveAuth));
        let mut caller = start(Some(&mut complete), Phase::CallerReconcile);
        caller_state(&mut caller, false, false);
        finish(caller);
        for phase in [
            Phase::StartupFlush,
            Phase::AgentOpen,
            Phase::RetainedMessages,
            Phase::LocalRetention,
        ] {
            finish(start(Some(&mut complete), phase));
        }
        let mut duplicate = Observation::new();
        finish(start(Some(&mut duplicate), Phase::ArchiveAuth));
        finish(start(Some(&mut duplicate), Phase::ArchiveAuth));
        assert!(!duplicate.intact);
        assert_eq!(duplicate.finish(true)["complete"], false);
        let report = complete.finish(true);
        assert_eq!(report["complete"], true);
        let measured = report["measured_seconds"].as_f64().unwrap();
        let total = report["runtime_open_seconds"].as_f64().unwrap();
        assert!(measured <= total);
        assert!(report["residual_seconds"].as_f64().unwrap() >= 0.0);
    }

    #[test]
    fn inactive_local_probe_and_sequential_scopes_do_not_inherit_execution() {
        let outer = execution_cost::Scope::begin();
        drop(local_start_with_clock(None, LocalPart::Construct, || {
            panic!("inactive local clock")
        }));
        assert!(outer.finish().complete);
        let mut calls = LocalCalls::new();
        for kind in ["signed-timeout", "finalized"] {
            let row = calls.next(kind).unwrap();
            for part in [LocalPart::Construct, LocalPart::Retain] {
                let span = local_start(Some(&mut *row), part);
                let mut execution = execution_cost::Span::start();
                execution.succeeded();
                drop(execution);
                local_finish(span, true);
            }
            assert_eq!(row.construct.as_ref().unwrap().execution.calls, 1);
            assert_eq!(row.retain.as_ref().unwrap().execution.calls, 1);
            assert!(row.completed && row.successful);
        }
        assert!(calls.complete());
        let outer = execution_cost::Scope::begin();
        assert_eq!(outer.finish().calls, 0);
        assert!(Observation::new()
            .finish(false)
            .get("local_calls")
            .is_none());
    }

    #[test]
    fn local_probe_refusal_drop_and_overflow_preserve_incompleteness() {
        let mut calls = LocalCalls::new();
        let row = calls.next("signed-timeout").unwrap();
        let span = local_start(Some(row), LocalPart::Construct);
        drop(execution_cost::Span::start());
        local_finish(span, false);
        let row = calls.rows[0].as_ref().unwrap();
        assert!(row.completed && !row.successful);
        assert!(row.retain.is_none());
        let part = row.construct.as_ref().unwrap();
        assert!(part.returned && !part.successful);
        assert_eq!((part.execution.successful, part.execution.failed), (0, 1));
        let row = calls.next("finalized").unwrap();
        drop(local_start(Some(row), LocalPart::Construct));
        let row = calls.rows[1].as_ref().unwrap();
        assert!(!row.completed && !row.successful);
        assert!(!row.construct.as_ref().unwrap().returned);
        let overflow = calls.next("other");
        drop(local_start_with_clock(
            overflow,
            LocalPart::Construct,
            || panic!("overflow clock"),
        ));
        assert_eq!(calls.entered, 3);
        assert!(calls.overflow && !calls.complete());
        assert_eq!(calls.rows.iter().flatten().count(), 2);
        let row = calls.rows[1].as_mut().unwrap();
        local_finish(local_start(Some(&mut *row), LocalPart::Retain), true);
        assert!(row.completed && !row.successful); // Later completion cannot erase a gap.
        let mut repeated = LocalCalls::new();
        let row = repeated.next("signed-timeout").unwrap();
        for part in [
            LocalPart::Construct,
            LocalPart::Construct,
            LocalPart::Retain,
        ] {
            local_finish(local_start(Some(&mut *row), part), true);
        }
        assert!(row.completed && !row.successful && !row.intact);
        assert!(!repeated.complete());
    }
}
