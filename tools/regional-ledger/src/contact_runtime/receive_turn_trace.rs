//! Test-only boundaries for one ordinary directory turn, never Native authority.
use super::*;
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

#[derive(Clone, Copy)]
struct Interval {
    started: f64,
    completed: Option<f64>,
}
struct Turn {
    id: u64,
    started: Option<f64>,
    prior_completed: Option<f64>,
    receiving: bool,
    successful: bool,
    open: Option<Interval>,
    inventory: Option<Interval>,
    peer: Option<usize>,
    file: Option<usize>,
}
#[derive(Default)]
struct State {
    next_id: u64,
    current: Option<Turn>,
    prior_completed: Option<f64>,
}
thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}
pub(super) struct Guard(u64, PhantomData<Rc<()>>);
impl Drop for Guard {
    fn drop(&mut self) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.current.as_ref().is_some_and(|turn| turn.id == self.0) {
                state.current = None;
            }
        });
    }
}
pub(super) fn reset() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.current = None;
        state.prior_completed = None;
    });
}
pub(super) fn begin(enabled: bool, clock: impl FnOnce() -> Result<f64>) -> Result<Option<Guard>> {
    if !enabled {
        return Ok(None);
    }
    let id = STATE.with(|state| -> Result<u64> {
        let mut state = state.borrow_mut();
        require(state.current.is_none(), "directory trace turn reentry")?;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or("directory trace id overflow")?;
        let id = state.next_id;
        let prior_completed = state.prior_completed.take();
        state.current = Some(Turn {
            id,
            started: None,
            prior_completed,
            receiving: true,
            successful: true,
            open: None,
            inventory: None,
            peer: None,
            file: None,
        });
        Ok(id)
    })?;
    let guard = Guard(id, PhantomData);
    let at = clock()?;
    require(at.is_finite() && at >= 0.0, "invalid directory turn start")?;
    STATE.with(|state| -> Result<()> {
        let mut state = state.borrow_mut();
        let turn = state
            .current
            .as_mut()
            .ok_or("directory trace scope reset")?;
        require(turn.id == id, "directory trace scope replaced")?;
        require(
            turn.prior_completed.is_none_or(|prior| prior <= at),
            "directory prior completion after start",
        )?;
        turn.started = Some(at);
        Ok(())
    })?;
    Ok(Some(guard))
}
fn receiving(change: impl FnOnce(&mut Turn) -> Result<()>) -> Result<()> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(turn) = state.current.as_mut().filter(|turn| turn.receiving) {
            change(turn)?;
        }
        Ok(())
    })
}
pub(super) fn open_started(clock: impl FnOnce() -> Result<f64>) -> Result<()> {
    receiving(|turn| {
        turn.open = None;
        turn.inventory = None;
        turn.file = None;
        turn.open = Some(Interval {
            started: clock()?,
            completed: None,
        });
        Ok(())
    })
}
pub(super) fn open_completed(clock: impl FnOnce() -> Result<f64>) -> Result<()> {
    receiving(|turn| {
        let open = turn.open.as_mut().ok_or("directory open start missing")?;
        require(open.completed.is_none(), "directory open already completed")?;
        open.completed = Some(clock()?);
        Ok(())
    })
}
pub(super) fn peer(index: usize) -> Result<()> {
    receiving(|turn| {
        require(index < 16, "directory trace peer bound")?;
        turn.peer = Some(index);
        turn.inventory = None;
        turn.file = None;
        Ok(())
    })
}
pub(super) fn inventory_started(clock: impl FnOnce() -> Result<f64>) -> Result<()> {
    receiving(|turn| {
        turn.inventory = None;
        turn.file = None;
        turn.inventory = Some(Interval {
            started: clock()?,
            completed: None,
        });
        Ok(())
    })
}
pub(super) fn inventory_completed(clock: impl FnOnce() -> Result<f64>) -> Result<()> {
    receiving(|turn| {
        let inventory = turn
            .inventory
            .as_mut()
            .ok_or("directory inventory start missing")?;
        require(
            inventory.completed.is_none(),
            "directory inventory already completed",
        )?;
        inventory.completed = Some(clock()?);
        Ok(())
    })
}
pub(super) fn file(index: usize) -> Result<()> {
    receiving(|turn| {
        require(index < 4, "directory trace file bound")?;
        turn.file = Some(index);
        Ok(())
    })
}
pub(super) fn unsuccessful() {
    STATE.with(|state| {
        if let Some(turn) = state.borrow_mut().current.as_mut() {
            turn.successful = false;
            turn.open = None;
            turn.inventory = None;
            turn.file = None;
        }
    });
}
pub(super) fn end_receive() {
    STATE.with(|state| {
        if let Some(turn) = state.borrow_mut().current.as_mut() {
            turn.receiving = false;
        }
    });
}
impl Guard {
    pub(super) fn finish(&self, success: bool, clock: impl FnOnce() -> Result<f64>) -> Result<()> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let Some(turn) = state.current.as_ref().filter(|turn| turn.id == self.0) else {
                return Ok(());
            };
            if !success || !turn.successful {
                return Ok(());
            }
            require(!turn.receiving, "directory receive phase still active")?;
            let at = clock()?;
            require(
                at.is_finite() && turn.started.is_some_and(|start| start <= at),
                "invalid directory turn completion",
            )?;
            state.prior_completed = Some(at);
            Ok(())
        })
    }
}
pub(super) fn observation(file_started: f64) -> Result<Option<Value>> {
    STATE.with(|state| {
        let state = state.borrow();
        let Some(turn) = state.current.as_ref().filter(|turn| turn.receiving) else {
            return Ok(None);
        };
        let start = turn.started.ok_or("directory turn start missing")?;
        let open = turn.open.ok_or("directory open missing")?;
        let opened = open.completed.ok_or("directory open incomplete")?;
        let inventory = turn.inventory.ok_or("directory inventory missing")?;
        let inventoried = inventory
            .completed
            .ok_or("directory inventory incomplete")?;
        let peer = turn.peer.ok_or("directory peer index missing")?;
        let file = turn.file.ok_or("directory file index missing")?;
        let clocks = [
            start,
            open.started,
            opened,
            inventory.started,
            inventoried,
            file_started,
        ];
        require(
            clocks.iter().all(|at| at.is_finite() && *at >= 0.0)
                && clocks.windows(2).all(|pair| pair[0] <= pair[1]),
            "directory turn clocks incomplete or out of order",
        )?;
        Ok(Some(
            json!({"turn_started":start,"prior_turn_completed":turn.prior_completed,
            "node_open":{"started":open.started,"completed":opened},
            "inventory":{"started":inventory.started,"completed":inventoried},
            "peer_index":peer,"file_index":file,"ledger_authority":false}),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prefix(start: f64) {
        open_started(|| Ok(start)).unwrap();
        open_completed(|| Ok(start + 1.0)).unwrap();
        peer(0).unwrap();
        inventory_started(|| Ok(start + 2.0)).unwrap();
        inventory_completed(|| Ok(start + 3.0)).unwrap();
        file(0).unwrap();
    }
    #[test]
    fn disabled_reentry_and_reset_preserve_scope_without_extra_clocks() {
        reset();
        assert!(begin(false, || panic!("disabled start")).unwrap().is_none());
        open_started(|| panic!("disabled open")).unwrap();
        open_completed(|| panic!("disabled open end")).unwrap();
        inventory_started(|| panic!("disabled inventory")).unwrap();
        inventory_completed(|| panic!("disabled inventory end")).unwrap();
        assert!(observation(f64::NAN).unwrap().is_none());
        assert!(begin(true, || Err("clock failed".into())).is_err());
        let a = begin(true, || Ok(1.0)).unwrap().unwrap();
        assert!(begin(true, || panic!("reentry clock")).is_err());
        prefix(2.0);
        assert_eq!(observation(6.0).unwrap().unwrap()["turn_started"], 1.0);
        reset();
        let b = begin(true, || Ok(7.0)).unwrap().unwrap();
        drop(a); // A stale guard cannot erase the new trace session.
        prefix(8.0);
        assert_eq!(observation(12.0).unwrap().unwrap()["turn_started"], 7.0);
        end_receive();
        open_started(|| panic!("post receive open")).unwrap();
        assert!(observation(f64::NAN).unwrap().is_none());
        drop(b);
        assert!(observation(f64::NAN).unwrap().is_none());
    }
    #[test]
    fn snapshots_bind_actual_lease_peer_inventory_and_file_without_backfill() {
        reset();
        let _guard = begin(true, || Ok(1.0)).unwrap().unwrap();
        assert!(observation(6.0).is_err());
        prefix(2.0);
        let first = observation(6.0).unwrap().unwrap();
        file(1).unwrap();
        let second = observation(7.0).unwrap().unwrap();
        assert_eq!(first["file_index"], 0);
        assert_eq!(second["file_index"], 1);
        peer(1).unwrap();
        file(0).unwrap();
        assert!(observation(10.0).is_err());
        inventory_started(|| Ok(8.0)).unwrap();
        assert!(observation(10.0).is_err());
        inventory_completed(|| Ok(9.0)).unwrap();
        file(0).unwrap();
        let third = observation(10.0).unwrap().unwrap();
        assert_eq!(first["node_open"], third["node_open"]);
        assert_eq!(first["inventory"]["started"], 4.0);
        assert_eq!(third["inventory"]["started"], 8.0);
        assert_eq!(third["peer_index"], 1);
        assert!(third["prior_turn_completed"].is_null());
        for invalid in [f64::NAN, f64::INFINITY, -1.0, 8.5] {
            assert!(observation(invalid).is_err());
        }
        assert!(peer(16).is_err());
        assert!(file(4).is_err());
        inventory_started(|| Ok(f64::NAN)).unwrap();
        inventory_completed(|| Ok(11.0)).unwrap();
        file(0).unwrap();
        assert!(observation(12.0).is_err());
    }
    #[test]
    fn failed_cleanup_stop_and_reopen_cannot_inherit_prior_success() {
        reset();
        let a = begin(true, || Ok(1.0)).unwrap().unwrap();
        end_receive();
        a.finish(true, || Ok(2.0)).unwrap();
        drop(a);
        let b = begin(true, || Ok(3.0)).unwrap().unwrap();
        prefix(4.0);
        let durable = observation(8.0).unwrap().unwrap();
        assert_eq!(durable["prior_turn_completed"], 2.0);
        unsuccessful(); // Cleanup after the durable event, or a stopped turn.
        open_started(|| Ok(9.0)).unwrap();
        assert!(observation(10.0).is_err()); // Failed reopen has no completion.
        unsuccessful();
        prefix(11.0);
        let reopened = observation(15.0).unwrap().unwrap();
        assert_eq!(reopened["node_open"]["started"], 11.0);
        assert_eq!(durable["node_open"]["started"], 4.0);
        end_receive();
        b.finish(true, || panic!("failed turn completion")).unwrap();
        drop(b);
        let c = begin(true, || Ok(16.0)).unwrap().unwrap();
        prefix(17.0);
        assert!(observation(21.0).unwrap().unwrap()["prior_turn_completed"].is_null());
        end_receive();
        c.finish(false, || panic!("reported error completion"))
            .unwrap();
        drop(c);
        let d = begin(true, || Ok(22.0)).unwrap().unwrap();
        prefix(23.0);
        assert!(observation(27.0).unwrap().unwrap()["prior_turn_completed"].is_null());
        drop(d); // Early return/unwind likewise records no successful finish.
        let _e = begin(true, || Ok(28.0)).unwrap().unwrap();
        prefix(29.0);
        assert!(observation(33.0).unwrap().unwrap()["prior_turn_completed"].is_null());
    }
}
