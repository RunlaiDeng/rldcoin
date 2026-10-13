//! Successful directory-consumption clocks, never a ledger or custody authority.
use super::*;

pub(super) struct Observation {
    pub file_started: f64,
    pub read_completed: f64,
    pub codec_completed: f64,
    pub parse_completed: f64,
    pub canonical_checked: f64,
    pub receive_completed: f64,
}

impl Observation {
    pub(super) fn value(&self, event_at: f64) -> Result<Value> {
        let clocks = [
            self.file_started,
            self.read_completed,
            self.codec_completed,
            self.parse_completed,
            self.canonical_checked,
            self.receive_completed,
            event_at,
        ];
        require(
            clocks.iter().all(|at| at.is_finite() && *at >= 0.0)
                && clocks.windows(2).all(|pair| pair[0] <= pair[1]),
            "directory receive clocks incomplete or out of order",
        )?;
        // The preceding interval includes scheduling, Node open and inventory.
        // Node.receive interleaves authentication and durable storage; these
        // clocks cannot separate its CPU work from filesystem waits.
        Ok(json!({"file_started":self.file_started,
            "read_completed":self.read_completed,"codec_completed":self.codec_completed,
            "parse_completed":self.parse_completed,"canonical_checked":self.canonical_checked,
            "receive_auth_and_custody_completed":self.receive_completed,
            "ledger_authority":false}))
    }
}

#[test]
fn receive_clocks_preserve_boundaries_and_refuse_missing_order() {
    let mut observation = Observation {
        file_started: 1.0,
        read_completed: 2.0,
        codec_completed: 3.0,
        parse_completed: 4.0,
        canonical_checked: 5.0,
        receive_completed: 6.0,
    };
    let value = observation.value(7.0).unwrap();
    assert_eq!(value["file_started"], 1.0);
    assert_eq!(value["receive_auth_and_custody_completed"], 6.0);
    assert_eq!(value["ledger_authority"], false);
    assert!(observation.value(5.5).is_err());
    for invalid in [f64::NAN, f64::INFINITY, -1.0, 5.1] {
        observation.parse_completed = invalid;
        assert!(observation.value(7.0).is_err());
    }
}
