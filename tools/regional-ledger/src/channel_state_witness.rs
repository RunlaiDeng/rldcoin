//! Funding-selected state cosignature, never latest-state or ledger authority
//! by itself. Full native funding and both actual owner signatures remain mandatory.
use super::*;
use crate::{channel_receipt as r, channels as c};
pub const FORMAT: &str = "RLD-NATIVE-CHANNEL-STATE-WITNESS-V1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub format: String,
    pub profile: Hash,
    pub state: c::StateStatement,
    pub parties: [String; 2],
    /// Witness-attested original custody commitments, not hash-only authority
    /// or independently proven private custody/freshness.
    pub inceptions: [Hash; 2],
    pub invoice: Option<r::Statement>,
}
impl Statement {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode("channel-state-witness-authorization-v1", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub statement: Statement,
    pub approval: Approval,
}
impl Proof {
    pub(crate) fn verify(
        &self,
        state: &c::StateStatement,
        parties: &[String; 2],
        key: &str,
    ) -> Result<()> {
        encode("complete-channel-state-witness-proof", self)?;
        let s = &self.statement;
        require(
            s.format == FORMAT
                && s.profile == c::profile_hash()?
                && s.state == *state
                && s.parties == *parties
                && s.parties[0] < s.parties[1]
                && s.inceptions.iter().all(|h| !h.is_zero())
                && s.inceptions[0] != s.inceptions[1]
                && self.approval.key == key,
            "state witness purpose/role/complete statement differs",
        )?;
        if let Some(invoice) = &s.invoice {
            require(
                invoice.format == r::FORMAT
                    && invoice.profile == s.profile
                    && invoice.expected.currency == state.currency
                    && invoice.expected.region == state.region
                    && invoice.expected.channel == state.channel
                    && invoice.next_state == id("channel-receipt-state-v1", state)?,
                "state witness invoice domain/state differs",
            )?;
        }
        verify_bytes(key, &s.bytes()?, &self.approval.signature)
    }
}
#[cfg(test)]
pub(crate) fn fixture(
    state: &c::StateStatement,
    parties: [String; 2],
    invoice: Option<r::Statement>,
) -> Box<Proof> {
    let statement = Statement {
        format: FORMAT.into(),
        profile: c::profile_hash().unwrap(),
        state: state.clone(),
        inceptions: parties
            .each_ref()
            .map(|owner| id("public-fixture-inception", &(state.channel, owner)).unwrap()),
        parties,
        invoice,
    };
    let approval = Approval {
        key: crate::tests::public(12),
        signature: crate::tests::signature(12, &statement.bytes().unwrap()),
    };
    Box::new(Proof {
        statement,
        approval,
    })
}
