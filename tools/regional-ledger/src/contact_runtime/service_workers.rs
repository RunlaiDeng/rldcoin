//! Owned transport workers; the caller keeps the sole Native Runtime.
use crate::{require, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

pub(super) struct Workers {
    running: Arc<AtomicBool>,
    tasks: Vec<(&'static str, JoinHandle<Result<()>>)>,
}

impl Workers {
    pub(super) fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            tasks: Vec::new(),
        }
    }

    pub(super) fn spawn(
        &mut self,
        name: &'static str,
        work: impl FnOnce(Arc<AtomicBool>) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        require(self.tasks.len() < 2, "contact worker capacity")?;
        let running = self.running.clone();
        let task = thread::Builder::new()
            .name(name.into())
            .spawn(move || work(running))
            .map_err(|e| e.to_string())?;
        self.tasks.push((name, task));
        Ok(())
    }

    pub(super) fn require_running(&self) -> Result<()> {
        for (name, task) in &self.tasks {
            require(!task.is_finished(), &format!("{name} stopped unexpectedly"))?;
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Release);
        let mut errors = Vec::new();
        // Join every owned worker before propagating any error. The Service
        // lease and TLS context remain alive in the caller throughout this.
        for (name, task) in self.tasks.drain(..) {
            match task.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(format!("{name}: {error}")),
                Err(_) => errors.push(format!("{name} panicked")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("contact worker cleanup refused: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn blocked_transport_leaves_caller_available_and_joins_after_release() {
        let mut workers = Workers::new();
        let (entered, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        workers
            .spawn("outgoing", move |_| {
                entered.send(()).unwrap();
                waiting.recv_timeout(Duration::from_secs(2)).unwrap();
                done.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap();
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        workers.require_running().unwrap();
        assert!(!finished.load(Ordering::Acquire));
        // This caller can run its Native turn while the transport is waiting.
        release.send(()).unwrap();
        workers.finish().unwrap();
        assert!(finished.load(Ordering::Acquire));
        assert!(!workers.running.load(Ordering::Acquire));
        assert!(workers.tasks.is_empty());
    }

    #[test]
    fn error_and_panic_still_stop_and_join_the_other_worker() {
        for panic in [false, true] {
            let mut workers = Workers::new();
            let other_stopped = Arc::new(AtomicBool::new(false));
            let observed = other_stopped.clone();
            workers
                .spawn("first", move |_| {
                    assert!(!panic, "owned worker panic");
                    Err("owned worker error".into())
                })
                .unwrap();
            workers
                .spawn("second", move |running| {
                    while running.load(Ordering::Acquire) {
                        thread::yield_now();
                    }
                    observed.store(true, Ordering::Release);
                    Ok(())
                })
                .unwrap();
            assert!(workers.spawn("third", |_| Ok(())).is_err());
            let error = workers.finish().unwrap_err();
            assert!(error.contains(if panic {
                "panicked"
            } else {
                "owned worker error"
            }));
            assert!(other_stopped.load(Ordering::Acquire));
            assert!(workers.tasks.is_empty());
        }
    }

    #[test]
    fn drop_joins_workers_before_releasing_the_callers_resources() {
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = stopped.clone();
        let mut workers = Workers::new();
        workers
            .spawn("owned", move |running| {
                while running.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                observed.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap();
        drop(workers);
        assert!(stopped.load(Ordering::Acquire));
    }
}
