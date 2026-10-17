//! Explicit local resource provisioning. No peer or backup chooses these budgets.
use crate::{
    carriage::Budget,
    kernel::{Hash, Result},
    store::Limits,
};
use serde::Deserialize;
use serde_json::{json, Value};

const FORMAT: &str = "RLD-SURVIVOR-OPERATING-POLICY-1";
// SQLite's 4-KiB page profile. This is a finite implementation resource limit,
// never a validity, history-height or reorganization-depth consensus rule.
const MAX_DATABASE: u64 = (u32::MAX as u64 - 1) * 4096;
#[derive(Clone, Copy)]
pub struct OperatingPolicy {
    ledger: Limits,
    carriage: Budget,
    mining_trials: u64,
}
impl Default for OperatingPolicy {
    fn default() -> Self {
        Self {
            ledger: Limits::default(),
            carriage: Budget::default(),
            mining_trials: 4096,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    chain_id: String,
    ledger_database_bytes: String,
    ledger_coins: String,
    carriage_database_bytes: String,
    carriage_packets: String,
    mining_trials_per_tick: String,
}
fn ensure(ok: bool, error: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn number(s: &str) -> Result<u64> {
    ensure(
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s.len() == 1 || !s.starts_with('0')),
        "INVALID_ENCODING operating policy decimal",
    )?;
    s.parse()
        .map_err(|_| "INVALID_ENCODING operating policy number".into())
}
fn machine(n: u64) -> Result<usize> {
    usize::try_from(n).map_err(|_| "RESOURCE_WAIT operating policy machine size".into())
}
impl OperatingPolicy {
    pub fn new(ledger: Limits, carriage: Budget, mining_trials: u64) -> Result<Self> {
        ensure(
            (131072..=MAX_DATABASE).contains(&ledger.database_bytes),
            "RESOURCE_WAIT operating policy ledger bytes",
        )?;
        ensure(
            ledger.coins > 0,
            "RESOURCE_WAIT operating policy coin count",
        )?;
        ensure(
            (131072..=MAX_DATABASE).contains(&(carriage.bytes as u64)) && carriage.packets > 0,
            "RESOURCE_WAIT operating policy carriage budget",
        )?;
        ensure(
            (1..=1_000_000).contains(&mining_trials),
            "RESOURCE_WAIT operating policy mining trials",
        )?;
        Ok(Self {
            ledger,
            carriage,
            mining_trials,
        })
    }
    pub fn decode(raw: &[u8], pin: Hash) -> Result<Self> {
        ensure(raw.len() <= 16384, "INVALID_ENCODING operating policy size")?;
        // Typed deserialization rejects duplicate and unknown fields; numbers are
        // canonical decimal strings, never rounded JSON floating-point values.
        let d: Document = serde_json::from_slice(raw)
            .map_err(|_| "INVALID_ENCODING operating policy document")?;
        ensure(d.format == FORMAT, "UNSUPPORTED_VERSION operating policy")?;
        ensure(
            d.chain_id == hex::encode(pin),
            "WRONG_CHAIN operating policy",
        )?;
        Self::new(
            Limits {
                database_bytes: number(&d.ledger_database_bytes)?,
                coins: machine(number(&d.ledger_coins)?)?,
            },
            Budget {
                bytes: machine(number(&d.carriage_database_bytes)?)?,
                packets: machine(number(&d.carriage_packets)?)?,
            },
            number(&d.mining_trials_per_tick)?,
        )
    }
    pub fn ledger(self) -> Limits {
        self.ledger
    }
    pub fn carriage(self) -> Budget {
        self.carriage
    }
    pub fn mining_trials(self) -> u64 {
        self.mining_trials
    }
    pub fn status(self, pin: Hash) -> Value {
        json!({"format":FORMAT,"chain_id":hex::encode(pin),"ledger_database_bytes":self.ledger.database_bytes.to_string(),"ledger_coins":self.ledger.coins.to_string(),"carriage_database_bytes":self.carriage.bytes.to_string(),"carriage_packets":self.carriage.packets.to_string(),"mining_trials_per_tick":self.mining_trials.to_string()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_defaults_and_provisioned_budgets_roundtrip_without_consensus_changes() {
        let pin = [7; 32];
        let value = OperatingPolicy::default().status(pin);
        let p = OperatingPolicy::decode(value.to_string().as_bytes(), pin).unwrap();
        assert_eq!(p.ledger().database_bytes, Limits::default().database_bytes);
        assert_eq!(p.ledger().coins, Limits::default().coins);
        assert_eq!(p.carriage().bytes, Budget::default().bytes);
        assert_eq!(p.carriage().packets, Budget::default().packets);
        assert_eq!(p.mining_trials(), 4096);
        let mut value = value;
        value["ledger_database_bytes"] = json!("536870912");
        value["carriage_database_bytes"] = json!("536870912");
        value["mining_trials_per_tick"] = json!("1");
        let p = OperatingPolicy::decode(value.to_string().as_bytes(), pin).unwrap();
        assert_eq!(p.ledger().database_bytes, 536870912);
        assert_eq!(p.carriage().bytes, 536870912);
        assert_eq!(p.mining_trials(), 1);
    }
    #[test]
    fn malformed_duplicate_unknown_wrong_chain_and_impossible_policies_refuse() {
        let pin = [7; 32];
        let value = OperatingPolicy::default().status(pin);
        assert!(OperatingPolicy::decode(value.to_string().as_bytes(), [8; 32]).is_err());
        for (field, replacement) in [
            ("format", json!("UNKNOWN")),
            ("ledger_database_bytes", json!("0")),
            ("ledger_database_bytes", json!("18446744073709551616")),
            ("ledger_coins", json!("0")),
            ("ledger_coins", json!("01")),
            ("ledger_coins", json!(1)),
            ("carriage_packets", json!("0")),
            ("carriage_database_bytes", json!("0")),
            ("mining_trials_per_tick", json!("0")),
            ("mining_trials_per_tick", json!("1000001")),
            ("unexpected", json!(true)),
        ] {
            let mut bad = value.clone();
            bad[field] = replacement;
            assert!(
                OperatingPolicy::decode(bad.to_string().as_bytes(), pin).is_err(),
                "{field}"
            );
        }
        let original = value.to_string();
        let duplicated = format!(
            "{},\"ledger_coins\":\"2\"}}",
            &original[..original.len() - 1]
        );
        assert!(OperatingPolicy::decode(duplicated.as_bytes(), pin).is_err());
        assert!(OperatingPolicy::decode(&vec![b' '; 16385], pin).is_err());
    }
}
