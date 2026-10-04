//! Public state authorization derived from the exact durable private owner
//! responses. No private journals or caller heads are exported in its proof.
use super::*;
use crate::channel_state_witness as sw;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SealRecord {
    pub body: Combined,
    pub proof: sw::Proof,
}
impl Combined {
    fn state(&self) -> &c::SignedState {
        match self {
            Self::Initial(s) => s,
            Self::Payment(r) => &r.next,
        }
    }
    fn invoice(&self) -> Option<r::Statement> {
        match self {
            Self::Initial(_) => None,
            Self::Payment(r) => Some(r.statement.clone()),
        }
    }
    fn sealed(&self, proof: &sw::Proof) -> Self {
        let mut out = self.clone();
        match &mut out {
            Self::Initial(s) => s.witness = Some(Box::new(proof.clone())),
            Self::Payment(r) => r.next.witness = Some(Box::new(proof.clone())),
        }
        out
    }
}
fn original_births(
    node: &Store,
    owners: &BTreeMap<Hash, Journal>,
    state: &c::StateStatement,
) -> Result<[Hash; 2]> {
    let native = node
        .chain
        .ledger
        .channel_state
        .as_ref()
        .ok_or("native funding absent")?;
    let parties = native
        .book
        .channels
        .get(&state.channel)
        .ok_or("channel absent")?
        .terms()?
        .0;
    let mut births = Vec::new();
    for party in parties {
        let binding = Binding {
            purpose: PURPOSE.into(),
            profile: c::profile_hash()?,
            currency: state.currency,
            region: state.region,
            channel: state.channel,
            owner: party.clone(),
        };
        let mut birth = owners
            .get(&slot(&binding)?)
            .ok_or("both original witness owner inceptions required")?
            .clone();
        birth.records.clear();
        births.push(birth.head()?);
    }
    Ok([births[0], births[1]])
}
pub(super) fn request_inceptions(
    node: &Store,
    owners: &BTreeMap<Hash, Journal>,
    request: &Request,
) -> Result<()> {
    if let Request::Payment(r) = request {
        require(
            r.prior
                .witness
                .as_ref()
                .ok_or("prior state witness absent")?
                .statement
                .inceptions
                == original_births(node, owners, &r.prior.statement)?,
            "owner request replaces original witnessed inceptions",
        )?;
    }
    Ok(())
}
fn derive(
    node: &Store,
    owners: &BTreeMap<Hash, Journal>,
    body: &Combined,
) -> Result<sw::Statement> {
    require(
        body.state().witness.is_none(),
        "witness seal requires exact unwitnessed construction",
    )?;
    let state = &body.state().statement;
    let native = node
        .chain
        .ledger
        .channel_state
        .as_ref()
        .ok_or("native funding absent")?;
    let parties = native
        .book
        .channels
        .get(&state.channel)
        .ok_or("channel absent")?
        .terms()?
        .0
        .clone();
    let mut parts = Vec::new();
    let mut births = Vec::new();
    for party in &parties {
        let binding = Binding {
            purpose: PURPOSE.into(),
            profile: c::profile_hash()?,
            currency: state.currency,
            region: state.region,
            channel: state.channel,
            owner: party.clone(),
        };
        let owner = owners
            .get(&slot(&binding)?)
            .ok_or("both original witness owner inceptions required")?;
        owner.validate(node)?;
        let last = owner
            .records
            .last()
            .ok_or("both durable latest owner responses required")?;
        request_inceptions(node, owners, &last.partial.request)?;
        parts.push(last.partial.clone());
        let mut birth = owner.clone();
        birth.records.clear();
        births.push(birth.head()?);
    }
    require(
        combine_inner(node, parts, false)? == *body,
        "seal body differs from exact both highest retained owner responses",
    )?;
    Ok(sw::Statement {
        format: sw::FORMAT.into(),
        profile: c::profile_hash()?,
        state: state.clone(),
        parties,
        inceptions: [births[0], births[1]],
        invoice: body.invoice(),
    })
}
pub(super) fn validate(
    node: &Store,
    binding: &WitnessBinding,
    owners: &BTreeMap<Hash, Journal>,
    record: &SealRecord,
) -> Result<()> {
    require(
        record.proof.statement == derive(node, owners, &record.body)?,
        "seal inception/state/invoice assertion differs from native owner custody",
    )?;
    let state = record.body.state();
    let native = node
        .chain
        .ledger
        .channel_state
        .as_ref()
        .ok_or("funding absent")?;
    let escrow = native
        .book
        .channels
        .get(&state.statement.channel)
        .ok_or("channel absent")?;
    let role = match &escrow.funding.intent.action {
        c::Action::Open {
            witness: Some(key), ..
        } => key,
        _ => return Err("funding witness role absent".into()),
    };
    require(
        role == &binding.key,
        "seal witness role differs from signed funding",
    )?;
    record
        .proof
        .verify(&state.statement, escrow.terms()?.0, role)?;
    // Full native public authorization as well as the private custody assertion.
    match record.body.sealed(&record.proof) {
        Combined::Initial(s) => escrow.verify_state(&s, s.statement.channel, &native.declaration),
        Combined::Payment(r) => r.verify_anchor(&node.trust, &node.evidence),
    }
}
#[derive(Debug, Serialize)]
pub struct Sealed {
    pub combined: Combined,
    pub witness_head: Hash,
    pub first_sealed_this_call: bool,
    pub independent_operations_qualified: bool,
}
impl Witness {
    pub fn seal(
        &mut self,
        node: &Store,
        body: Combined,
        key: &Path,
        heads: (Hash, Hash),
    ) -> Result<Sealed> {
        let (native_head, whead) = heads;
        node.require_storage_head(native_head)?;
        let owners = self.current(node, whead)?;
        require(
            !self
                .journal
                .entries
                .iter()
                .any(|e| matches!(&e.payload,Payload::Seal(s) if s.body==body)),
            "exact seal already retained; use keyless recover-seal",
        )?;
        let statement = derive(node, &owners, &body)?;
        let parts = owners
            .values()
            .filter(|j| j.binding.channel == statement.state.channel)
            .filter_map(|j| j.records.last().map(|r| r.partial.clone()))
            .collect();
        require(
            combine(node, parts, native_head)? == body,
            "seal needs current fully reviewed native owner responses",
        )?;
        let approval =
            crate::signer::read_and_sign(key, &self.journal.binding.key, &statement.bytes()?)?;
        let record = SealRecord {
            body,
            proof: sw::Proof {
                statement,
                approval,
            },
        };
        validate(node, &self.journal.binding, &owners, &record)?;
        self.append(node, Payload::Seal(Box::new(record.clone())), key, whead)?;
        Ok(Sealed {
            combined: record.body.sealed(&record.proof),
            witness_head: self.head()?,
            first_sealed_this_call: true,
            independent_operations_qualified: false,
        })
    }
    pub fn recover_seal(
        &mut self,
        node: &Store,
        body: &Combined,
        heads: (Hash, Hash),
    ) -> Result<Sealed> {
        let (native_head, whead) = heads;
        node.require_storage_head(native_head)?;
        require(self.healthy, "witness handle failed; reopen")?;
        let target = self.pending.as_ref().unwrap_or(&self.journal);
        target.replay(node)?;
        let (n, entry, record) = target
            .entries
            .iter()
            .enumerate()
            .find_map(|(n, e)| match &e.payload {
                Payload::Seal(s) if s.body == *body => Some((n, e, s.as_ref())),
                _ => None,
            })
            .ok_or("exact seal absent; recover cannot first-sign")?;
        require(
            whead == target.head()? || (n + 1 == target.entries.len() && whead == entry.previous),
            "seal recovery stale witness head",
        )?;
        require(
            self.pending.is_none() || n + 1 == target.entries.len(),
            "pending seal must be this exact response",
        )?;
        let output = record.body.sealed(&record.proof);
        if let Some(next) = &self.pending {
            File::open(self.dir.join("witness.next"))
                .map_err(io)?
                .sync_all()
                .map_err(io)?;
            fs::rename(self.dir.join("witness.next"), self.dir.join("witness.json")).map_err(io)?;
            File::open(&self.dir).map_err(io)?.sync_all().map_err(io)?;
            self.journal = next.clone();
            self.pending = None;
        }
        Ok(Sealed {
            combined: output,
            witness_head: self.head()?,
            first_sealed_this_call: false,
            independent_operations_qualified: false,
        })
    }
}

#[cfg(test)]
#[path = "channel_seal_tests.rs"]
mod tests;
