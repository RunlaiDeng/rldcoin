use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub const RUNLAI_PER_RLD: u128 = 1_000_000_000_000_000_000_000_000;
pub const TOTAL_SUPPLY_RLD: u128 = 100_000_000_000;
pub const TOTAL_SUPPLY_RUNLAI: u128 = TOTAL_SUPPLY_RLD * RUNLAI_PER_RLD;

/// Integer-only Rldcoin amount. JSON encoding is always a decimal string.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(pub u128);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AmountError {
    #[error("invalid runlai amount")]
    Invalid,
    #[error("amount overflow")]
    Overflow,
    #[error("amount underflow")]
    Underflow,
}

impl Amount {
    pub const ZERO: Self = Self(0);
    pub const TOTAL_SUPPLY: Self = Self(TOTAL_SUPPLY_RUNLAI);

    pub const fn from_runlai(value: u128) -> Self {
        Self(value)
    }

    pub fn from_rld_whole(value: u128) -> Result<Self, AmountError> {
        value
            .checked_mul(RUNLAI_PER_RLD)
            .map(Self)
            .ok_or(AmountError::Overflow)
    }

    pub const fn as_runlai(self) -> u128 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(AmountError::Underflow)
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Amount {
    type Err = AmountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(AmountError::Invalid);
        }
        value
            .parse::<u128>()
            .map(Self)
            .map_err(|_| AmountError::Invalid)
    }
}

impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct AmountVisitor;

impl<'de> de::Visitor<'de> for AmountVisitor {
    type Value = Amount;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a base-10 runlai amount encoded as a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value.parse::<Amount>().map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(AmountVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_supply_fits_u128() {
        assert_eq!(TOTAL_SUPPLY_RUNLAI, 10u128.pow(35));
    }

    #[test]
    fn json_is_a_string() {
        let value = Amount::from_rld_whole(12).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, format!("\"{}\"", 12 * RUNLAI_PER_RLD));
        assert_eq!(serde_json::from_str::<Amount>(&json).unwrap(), value);
    }

    #[test]
    fn json_rejects_non_string_and_non_canonical_amounts() {
        for invalid in [
            "0",
            "1",
            "\"\"",
            "\"00\"",
            "\"01\"",
            "\"+1\"",
            "\"-1\"",
            "\" 1\"",
            "\"1 \"",
            "\"340282366920938463463374607431768211456\"",
        ] {
            assert!(
                serde_json::from_str::<Amount>(invalid).is_err(),
                "non-canonical amount unexpectedly accepted: {invalid}"
            );
        }
        assert_eq!(
            serde_json::from_str::<Amount>("\"0\"").unwrap(),
            Amount::ZERO
        );
        assert_eq!(
            serde_json::from_str::<Amount>("\"340282366920938463463374607431768211455\"").unwrap(),
            Amount(u128::MAX)
        );
    }
}
