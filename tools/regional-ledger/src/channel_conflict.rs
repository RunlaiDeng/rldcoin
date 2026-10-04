//! Complete native funding replay plus two distinct valid joint states.
//! This retains obligations and restricts future actions; it never selects value.
use super::*;
pub const FORMAT: &str = "RLD-NATIVE-CHANNEL-CONFLICT-V1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub channel: Hash,
    pub anchor: Hash,
    pub funding: Evidence,
    pub left: channels::SignedState,
    pub right: channels::SignedState,
}
impl Conflict {
    pub fn canonical(
        currency: Hash,
        region: Hash,
        channel: Hash,
        anchor: Hash,
        funding: Evidence,
        left: channels::SignedState,
        right: channels::SignedState,
    ) -> Result<Self> {
        let (left, right) = if id("channel-conflict-state", &left.statement)?
            < id("channel-conflict-state", &right.statement)?
        {
            (left, right)
        } else {
            (right, left)
        };
        Ok(Self {
            format: FORMAT.into(),
            currency,
            region,
            channel,
            anchor,
            funding,
            left,
            right,
        })
    }
    pub fn id(&self) -> Result<Hash> {
        id(
            "native-channel-conflict-v1",
            &(
                self.currency,
                self.region,
                self.channel,
                &self.left.statement,
                &self.right.statement,
            ),
        )
    }
    pub fn verify(&self, trust: &Trust) -> Result<()> {
        encode("complete-channel-conflict", self)?;
        require(
            self.format == FORMAT
                && self.currency == trust.currency()?
                && channels::is_profile(&trust.region(self.region)?.rules),
            "channel incident domain/profile",
        )?;
        let checked = VerifiedEvidence::verify(&self.funding, trust)?;
        let (snapshot, ledger) = checked
            .snapshots
            .get(&self.anchor)
            .ok_or("channel funding anchor missing")?;
        require(
            snapshot.statement.region == self.region,
            "channel funding anchor region",
        )?;
        let state = ledger
            .channel_state
            .as_ref()
            .ok_or("anchor has no native channel funding")?;
        state.declaration.verify(trust, self.region)?;
        let escrow = state
            .book
            .channels
            .get(&self.channel)
            .ok_or("channel absent from native funding")?;
        escrow.verify_state(&self.left, self.channel, &state.declaration)?;
        escrow.verify_state(&self.right, self.channel, &state.declaration)?;
        require(
            self.left.statement.sequence == self.right.statement.sequence
                && id("channel-conflict-state", &self.left.statement)?
                    < id("channel-conflict-state", &self.right.statement)?,
            "channel states compatible, different sequence or noncanonical pair",
        )
    }
}
