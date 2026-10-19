//! Serialized key-free caller intents compose native selection and private
//! owner/retainer steps. Full child replay/audits precede signing authority.
mod control;
mod fee_policy;
mod head_log;
pub use fee_policy::FeePolicy;
mod monitor;
pub use monitor::{BackgroundMiner, FeeMonitor, MonitorConfig};
mod ingress;
pub use ingress::Ingress;
mod outbound;
pub use outbound::Outbound;
mod journal;
pub use control::Boundary as ControlBoundary;
mod onchain;
mod opening;
mod pool;
mod transfer;
use crate::{
    fast_owner,
    fast_payment::{self, ensure, Acknowledgment, Delegation, Invoice, Payment},
    fast_retainer::{self, Creation},
    fast_store::{self, Store},
    kernel::{fast, Hash, Result},
    keyfile,
};
use journal::{Done, Journal};
pub use onchain::{MiningRequest, OnchainRequest};
pub use opening::{OpeningRequest, OpeningTerms};
pub use pool::PoolMiningRequest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub use transfer::{TransferOutput, TransferRequest};
const CHILD_LIMIT: usize = 32 * 1024 * 1024;
pub(crate) fn hash(label: &str, raw: &[u8]) -> Hash {
    Sha256::digest(
        [
            b"RLD-FAST-SESSION-1/".as_slice(),
            label.as_bytes(),
            &[0],
            raw,
        ]
        .concat(),
    )
    .into()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id(pub Hash);
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let b = bytes(&s, 32).map_err(serde::de::Error::custom)?;
        Ok(Id(b
            .try_into()
            .map_err(|_| serde::de::Error::custom("INVALID ID"))?))
    }
}
pub fn bytes(raw: &str, max: usize) -> Result<Vec<u8>> {
    ensure(
        raw.len() <= max * 2
            && raw.len().is_multiple_of(2)
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "INVALID canonical bounded hex",
    )?;
    hex::decode(raw).map_err(|_| "INVALID hex".into())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    FeePolicyApprove {
        tip: Id,
        terms: FeePolicy,
        key_file: String,
        approved: bool,
    },
    FeePolicyPrepare {
        tip: Id,
        policy_request: Id,
        plan: OnchainRequest,
    },
    FeePolicySign {
        tip: Id,
        policy_request: Id,
        prepare_request: Id,
        review: Id,
        key_file: String,
    },
    OpenPrepare {
        tip: Id,
        plan: OpeningRequest,
    },
    OpenCombine {
        tip: Id,
        prepare_request: Id,
        sign_request: Id,
        review: Id,
        counterparty_partial: String,
    },
    TransferPrepare {
        tip: Id,
        plan: TransferRequest,
    },
    PoolSubmit {
        tip: Id,
        operation: String,
    },
    OnchainPrepare {
        tip: Id,
        plan: OnchainRequest,
    },
    OnchainSign {
        tip: Id,
        prepare_request: Id,
        review: Id,
        key_file: String,
        approved: bool,
    },
    Native {
        tip: Id,
        block: String,
    },
    OwnerCreate {
        tip: Id,
        channel: Id,
        owner: u8,
        delegation: String,
    },
    RetainerCreate {
        tip: Id,
        channel: Id,
        delegation: String,
    },
    OwnerPrepare {
        tip: Id,
        actor: Id,
        invoice: String,
    },
    OwnerReview {
        tip: Id,
        actor: Id,
    },
    OwnerSign {
        tip: Id,
        actor: Id,
        invoice: Id,
        review_request: Id,
        review: Id,
        key_file: String,
        approved: bool,
    },
    OwnerComplete {
        tip: Id,
        actor: Id,
        receipt: String,
        ack: String,
    },
    RetainerPrepare {
        tip: Id,
        actor: Id,
        receipt: String,
    },
    RetainerReview {
        tip: Id,
        actor: Id,
    },
    RetainerSign {
        tip: Id,
        actor: Id,
        receipt: Id,
        review_request: Id,
        review: Id,
        key_file: String,
        approved: bool,
    },
}
impl Action {
    pub fn digest(&self) -> Result<Id> {
        Ok(Id(hash(
            "REQUEST",
            &serde_json::to_vec(self).map_err(fast_retainer::io)?,
        )))
    }
    fn tip(&self) -> Hash {
        match self {
            Self::FeePolicyApprove { tip, .. }
            | Self::FeePolicyPrepare { tip, .. }
            | Self::FeePolicySign { tip, .. }
            | Self::PoolSubmit { tip, .. }
            | Self::OpenPrepare { tip, .. }
            | Self::OpenCombine { tip, .. }
            | Self::TransferPrepare { tip, .. }
            | Self::OnchainPrepare { tip, .. }
            | Self::OnchainSign { tip, .. }
            | Self::Native { tip, .. }
            | Self::OwnerCreate { tip, .. }
            | Self::RetainerCreate { tip, .. }
            | Self::OwnerPrepare { tip, .. }
            | Self::OwnerReview { tip, .. }
            | Self::OwnerSign { tip, .. }
            | Self::OwnerComplete { tip, .. }
            | Self::RetainerPrepare { tip, .. }
            | Self::RetainerReview { tip, .. }
            | Self::RetainerSign { tip, .. } => tip.0,
        }
    }
    fn actor(&self) -> Option<Id> {
        match self {
            Self::OwnerPrepare { actor, .. }
            | Self::OwnerReview { actor, .. }
            | Self::OwnerSign { actor, .. }
            | Self::OwnerComplete { actor, .. }
            | Self::RetainerPrepare { actor, .. }
            | Self::RetainerReview { actor, .. }
            | Self::RetainerSign { actor, .. } => Some(*actor),
            _ => None,
        }
    }
    fn registration(&self, chain: Hash) -> Result<Option<Registration>> {
        let (channel, role, delegation) = match self {
            Self::OwnerCreate {
                channel,
                owner,
                delegation,
                ..
            } => (*channel, *owner, delegation),
            Self::RetainerCreate {
                channel,
                delegation,
                ..
            } => (*channel, 2, delegation),
            _ => return Ok(None),
        };
        let raw = bytes(delegation, 245)?;
        ensure(
            role < 3 && raw.len() == 245,
            "INVALID session role/delegation",
        )?;
        let id = Id(hash(
            "ACTOR",
            &[
                chain.to_vec(),
                channel.0.to_vec(),
                vec![role],
                fast_payment::hash("DELEGATION-ID", &raw).to_vec(),
            ]
            .concat(),
        ));
        Ok(Some(Registration {
            id,
            channel: channel.0,
            role,
            delegation: raw,
            tip: self.tip(),
        }))
    }
    fn shape(&self) -> Result<()> {
        match self {
            Self::FeePolicyApprove {
                terms, key_file, ..
            } => {
                terms.shape()?;
                ensure(
                    !key_file.is_empty() && key_file.len() <= 4096,
                    "INVALID policy key path",
                )?;
            }
            Self::FeePolicyPrepare { plan, .. } => {
                plan.request()?;
            }
            Self::FeePolicySign { key_file, .. } => {
                ensure(
                    !key_file.is_empty() && key_file.len() <= 4096,
                    "INVALID policy key path",
                )?;
            }
            Self::OpenPrepare { plan, .. } => {
                plan.parts()?;
            }
            Self::OpenCombine {
                counterparty_partial,
                ..
            } => {
                ensure(
                    bytes(counterparty_partial, 65)?.len() == 65,
                    "INVALID counterparty opening partial",
                )?;
            }
            Self::TransferPrepare { plan, .. } => {
                plan.request()?;
            }
            Self::PoolSubmit { operation, .. } => {
                ensure(
                    !bytes(operation, 4096)?.is_empty(),
                    "INVALID empty pool operation",
                )?;
            }
            Self::OnchainPrepare { plan, .. } => {
                plan.request()?;
            }
            Self::Native { block, .. } => {
                fast::block_id(&bytes(block, 262144)?)?;
            }
            Self::OwnerCreate {
                owner, delegation, ..
            } => {
                ensure(
                    *owner < 2 && bytes(delegation, 245)?.len() == 245,
                    "INVALID owner registration",
                )?;
            }
            Self::RetainerCreate { delegation, .. } => {
                ensure(
                    bytes(delegation, 245)?.len() == 245,
                    "INVALID retainer registration",
                )?;
            }
            Self::OwnerPrepare { invoice, .. } => {
                let n = bytes(invoice, 575)?.len();
                ensure(n == 323 || n == 575, "INVALID invoice size")?;
            }
            Self::RetainerPrepare { receipt, .. } | Self::OwnerComplete { receipt, .. } => {
                let n = bytes(receipt, 831)?.len();
                ensure(n == 579 || n == 831, "INVALID receipt size")?;
                if let Self::OwnerComplete { ack, .. } = self {
                    ensure(bytes(ack, 340)?.len() == 340, "INVALID acknowledgment size")?;
                }
            }
            Self::OwnerSign { key_file, .. }
            | Self::RetainerSign { key_file, .. }
            | Self::OnchainSign { key_file, .. } => {
                ensure(
                    !key_file.is_empty() && key_file.len() <= 4096,
                    "INVALID native key path",
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Registration {
    id: Id,
    channel: Hash,
    role: u8,
    delegation: Vec<u8>,
    tip: Hash,
}
#[derive(Clone)]
struct ActorState {
    reg: Registration,
    initial: Hash,
    head: Hash,
    pending: Option<Vec<u8>>,
}
enum Actor {
    Owner(fast_owner::Journal),
    Retainer(fast_retainer::Journal),
}
impl Actor {
    fn open(path: &Path, chain: Hash, role: u8, head: Hash, now: u64) -> Result<Self> {
        if role < 2 {
            Ok(Self::Owner(fast_owner::Journal::open(
                path,
                chain,
                head,
                now,
                CHILD_LIMIT,
            )?))
        } else {
            Ok(Self::Retainer(fast_retainer::Journal::open(
                path,
                chain,
                head,
                now,
                CHILD_LIMIT,
            )?))
        }
    }
    fn head(&self) -> Hash {
        match self {
            Self::Owner(j) => j.head(),
            Self::Retainer(j) => j.head(),
        }
    }
    fn initial(&self) -> Hash {
        match self {
            Self::Owner(j) => j.initial_head(),
            Self::Retainer(j) => j.initial_head(),
        }
    }
    fn scope(&self) -> (fast::FundingOrigin, Delegation, u8) {
        match self {
            Self::Owner(j) => j.scope(),
            Self::Retainer(j) => {
                let (o, d) = j.scope();
                (o, d, 2)
            }
        }
    }
    fn audit(&mut self, p: Hash, n: Hash) -> Result<(u8, Vec<u8>)> {
        match self {
            Self::Owner(j) => j.audit_step(p, n),
            Self::Retainer(j) => j.audit_step(p, n),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    IntentDurable,
    ChildDurable,
    NativeActionEvaluated,
    ReplyDurable,
}
pub struct Session {
    root: PathBuf,
    genesis: Vec<u8>,
    chain: Hash,
    caller: Journal,
    native: Option<Store>,
    actors: BTreeMap<Id, ActorState>,
    actor_audits: BTreeMap<Id, ActorAudit>,
    mining: Option<Mining>,
    // Process-local proof over an already fully audited immutable caller/native
    // prefix. Never serialized; advance only after durable caller completion.
    onchain_audited: usize,
    pool_mining: Option<pool::PoolMining>,
    pool_cursor: usize,
    candidate: Option<Vec<u8>>,
    control: Option<control::Control>,
}
struct ActorAudit {
    head: Hash,
    prefix: fast_retainer::PrefixWitness,
    origin: fast::FundingOrigin,
    proofs: Vec<Vec<u8>>,
}
struct Mining {
    tip: Hash,
    miner: Hash,
    operations: Vec<Vec<u8>>,
    timestamp: u64,
    job: fast::MiningJob,
}
fn sync_dir(p: &Path) -> Result<()> {
    File::open(p)
        .and_then(|f| f.sync_all())
        .map_err(fast_retainer::io)
}
fn write_new(p: &Path, raw: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p).map_err(fast_retainer::io)?;
    f.write_all(raw).map_err(fast_retainer::io)?;
    fast_retainer::sync(&f, p)
}
fn actor_path(root: &Path, id: Id) -> PathBuf {
    root.join("actors")
        .join(format!("{}.journal", hex::encode(id.0)))
}
fn initial(reg: &Registration, genesis: &[u8], chain: Hash, history: &[u8]) -> Hash {
    let mut h = if reg.role < 2 {
        b"RLDFOWN1".to_vec()
    } else {
        b"RLDFRET1".to_vec()
    };
    h.extend([0, 1, 0, 1]);
    h.extend(chain);
    h.extend(reg.channel);
    h.extend(genesis);
    h.extend((history.len() as u64).to_be_bytes());
    h.extend(history);
    h.extend(&reg.delegation);
    if reg.role < 2 {
        h.push(reg.role);
    }
    if reg.role < 2 {
        Sha256::digest([b"RLD-FAST-OWNER-1/HEADER\0".as_slice(), &h].concat()).into()
    } else {
        fast_payment::hash("JOURNAL-HEADER", &h)
    }
}
fn owner_digest(
    _o: &fast::FundingOrigin,
    d: &Delegation,
    role: u8,
    i: &Invoice,
    head: Hash,
    tip: Hash,
) -> Hash {
    Sha256::digest(
        [
            b"RLD-FAST-OWNER-1/REVIEW\0".as_slice(),
            &tip,
            &head,
            &d.id(),
            &[role],
            &i.id(),
        ]
        .concat(),
    )
    .into()
}
impl Session {
    /// Assemble existing authorizations only; no key or current-backing claim.
    pub fn combine(
        &mut self,
        expected: Hash,
        actor: Id,
        invoice: Id,
        other: &[u8],
        now: u64,
    ) -> Result<Vec<u8>> {
        self.caller.check(expected)?;
        let state = self.actors.get(&actor).ok_or("MISSING combine owner")?;
        ensure(state.reg.role < 2, "INVALID combine role")?;
        let mut j = fast_owner::Journal::open(
            &actor_path(&self.root, actor),
            self.chain,
            state.head,
            now,
            CHILD_LIMIT,
        )?;
        let p = j.retained_pending(state.head, invoice.0)?;
        let own = p.partial.ok_or("MISSING retained own signature")?;
        let origin = j.scope().0;
        let inv = Invoice::verify(&origin, &p.invoice)?;
        ensure(inv.id() == invoice.0, "INVALID combine invoice")?;
        let payment = if state.reg.role == 0 {
            Payment::combine(&origin, &p.invoice, &own, other)?
        } else {
            Payment::combine(&origin, &p.invoice, other, &own)?
        };
        Ok(payment.bytes().to_vec())
    }
    pub fn create(root: &Path, genesis: &[u8], chain: Hash, now: u64) -> Result<Self> {
        Self::create_profile(root, genesis, chain, now, None)
    }
    fn create_profile(
        root: &Path,
        genesis: &[u8],
        chain: Hash,
        now: u64,
        control_path: Option<(&Path, bool)>,
    ) -> Result<Self> {
        fast::Ledger::from_genesis(genesis, chain, 100000)?;
        fs::create_dir(root).map_err(fast_retainer::io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(fast_retainer::io)?;
        }
        sync_dir(root.parent().ok_or("INVALID session parent")?)?;
        write_new(&root.join("CREATING"), &chain)?;
        fs::create_dir(root.join("actors")).map_err(fast_retainer::io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("actors"), fs::Permissions::from_mode(0o700))
                .map_err(fast_retainer::io)?;
        }
        let native = Store::create(
            &root.join("native.journal"),
            genesis,
            chain,
            now,
            fast_store::Limits::default(),
        )?;
        let caller = Journal::create(
            &root.join("caller.journal"),
            genesis,
            chain,
            native.head(),
            now,
            if control_path.is_some() { 2 } else { 1 },
        )?;
        let control = control_path
            .map(|(p, logged)| control::Control::create(p, caller.binding(), caller.head, logged))
            .transpose()?;
        sync_dir(root)?;
        fs::remove_file(root.join("CREATING")).map_err(fast_retainer::io)?;
        sync_dir(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            genesis: genesis.to_vec(),
            chain,
            caller,
            native: Some(native),
            actors: BTreeMap::new(),
            actor_audits: BTreeMap::new(),
            mining: None,
            onchain_audited: 0,
            pool_mining: None,
            pool_cursor: 0,
            candidate: None,
            control,
        })
    }
    fn structural(c: &Journal, chain: Hash) -> Result<(Hash, BTreeMap<Id, ActorState>)> {
        let mut native = c.native_initial;
        let mut actors = BTreeMap::<Id, ActorState>::new();
        for op in &c.ops {
            let Some(done) = &op.done else { continue };
            if let Some(reg) = op.intent.action.registration(chain)? {
                if let Some(h) = done.effect {
                    ensure(
                        !actors.contains_key(&reg.id) && actors.len() < 16,
                        "INVALID session actor registry/count",
                    )?;
                    actors.insert(
                        reg.id,
                        ActorState {
                            reg,
                            initial: h.0,
                            head: h.0,
                            pending: None,
                        },
                    );
                }
            } else if let Some(h) = done.effect {
                if matches!(op.intent.action, Action::Native { .. }) {
                    native = h.0;
                } else {
                    let id = op.intent.action.actor().ok_or("INVALID caller target")?;
                    actors
                        .get_mut(&id)
                        .ok_or("INVALID caller missing actor")?
                        .head = h.0;
                }
            }
        }
        Ok((native, actors))
    }
    pub fn open(
        root: &Path,
        genesis: &[u8],
        chain: Hash,
        expected: Hash,
        now: u64,
    ) -> Result<Self> {
        Self::open_profile(root, genesis, chain, expected, now, 1)
    }
    fn open_profile(
        root: &Path,
        genesis: &[u8],
        chain: Hash,
        expected: Hash,
        now: u64,
        version: u8,
    ) -> Result<Self> {
        Self::paths(root)?;
        let caller = Journal::open(
            &root.join("caller.journal"),
            genesis,
            chain,
            Some(expected),
            now,
            version,
        )?;
        ensure(
            caller.ops.last().is_none_or(|o| o.done.is_some()),
            "RESOURCE_WAIT session explicit keyless recovery required",
        )?;
        let (head, actors) = Self::structural(&caller, chain)?;
        let native = Store::open(
            &root.join("native.journal"),
            genesis,
            chain,
            head,
            now,
            fast_store::Limits::default(),
        )?;
        let mut s = Self {
            root: root.to_path_buf(),
            genesis: genesis.to_vec(),
            chain,
            caller,
            native: Some(native),
            actors,
            actor_audits: BTreeMap::new(),
            mining: None,
            onchain_audited: 0,
            pool_mining: None,
            pool_cursor: 0,
            candidate: None,
            control: None,
        };
        s.audit(now)?;
        s.onchain_audited = s.caller.ops.len();
        Ok(s)
    }
    fn paths(root: &Path) -> Result<()> {
        fast_retainer::private(root, false)?;
        fast_retainer::private(&root.join("actors"), false)?;
        ensure(
            !root.join("CREATING").exists() && !root.join("RESTORING").exists(),
            "RESOURCE_WAIT incomplete session directory",
        )
    }
    pub fn head(&self) -> Hash {
        self.caller.head
    }
    pub fn chain_id(&self) -> Hash {
        self.chain
    }
    /// Local header identity only, never independent freshness or value.
    pub fn caller_binding(&self) -> Hash {
        self.caller.binding()
    }
    pub fn native_head(&self) -> Hash {
        self.native.as_ref().unwrap().head()
    }
    pub fn tip(&self) -> Hash {
        self.native.as_ref().unwrap().ledger().tip().id()
    }
    pub fn status(&mut self, head: Hash, now: u64) -> Result<Value> {
        self.check_control(head)?;
        self.caller.check(head)?;
        let n = self
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT session native restart required")?;
        n.check(n.head(), n.ledger().tip().id(), now)?;
        Ok(
            json!({"session_head":Id(head),"native_head":Id(n.head()),"selected_tip":Id(n.ledger().tip().id()),"height":n.ledger().tip().height().to_string(),"actors":self.actors.keys().collect::<Vec<_>>(),"caller_head_control":if self.control.is_some(){"TRUSTED_FILE"}else{"EXTERNAL_EXACT_HEAD"},"caller_head_storage":self.control.as_ref().map(control::Control::storage),"fast_completion_authorized":false,"independent_freshness":false,"network_monitoring":false,"mainnet":false,"network_kind":"NO_VALUE_ONLY"}),
        )
    }
    /// Observe one output in the actual selected native ledger. This does not
    /// approve spending, release caller reservations or assert finality.
    pub fn native_coin(&mut self, head: Hash, reference: &[u8], now: u64) -> Result<Value> {
        ensure(reference.len() == 34, "INVALID native coin reference size")?;
        let mut out = self.status(head, now)?;
        let native = self.native.as_ref().unwrap();
        let next = native
            .ledger()
            .tip()
            .height()
            .checked_add(1)
            .ok_or("RESOURCE_WAIT native next height")?;
        out["output_reference"] = hex::encode(reference).into();
        out["selected_timestamp"] = native.ledger().tip().timestamp().to_string().into();
        out["native_coin"] = native
            .ledger()
            .coins()
            .get(reference)
            .map(|c| {
                json!({"owner":Id(c.owner),"amount":c.amount.to_string(),
                "maturity_height":c.maturity.to_string(),"mature_for_next_block":c.maturity<=next})
            })
            .unwrap_or(Value::Null);
        out["observation_only"] = true.into();
        out["owner_spend_authorized"] = false.into();
        out["reservation_review_required"] = true.into();
        Ok(out)
    }
    fn audit(&mut self, now: u64) -> Result<()> {
        self.caller.check(self.caller.head)?;
        ensure(
            self.native.as_ref().unwrap().initial_head() == self.caller.native_initial,
            "INVALID caller native initial head",
        )?;
        let (native_head, actors) = Self::structural(&self.caller, self.chain)?;
        ensure(
            self.native.as_ref().unwrap().head() == native_head,
            "INVALID caller native head",
        )?;
        let mut prior = self.caller.native_initial;
        // One bounded full block at a time; all native records must be covered
        // in their original order under one complete file-prefix audit.
        let steps = self.caller.ops.iter().filter_map(|op| {
            if let (Action::Native { tip, block }, Some(done)) = (&op.intent.action, &op.done) {
                if let Some(next) = done.effect {
                    let previous = prior;
                    prior = next.0;
                    return Some(
                        bytes(block, 262144).map(|block| fast_store::NativeAuditStep {
                            prior: previous,
                            next: next.0,
                            before_tip: tip.0,
                            at: op.intent.at,
                            block,
                        }),
                    );
                }
            }
            None
        });
        let transitions = self.native.as_mut().unwrap().audit_steps(steps)?;
        let mut transition = transitions.into_iter();
        let mut before_tip = self.chain;
        let mut before_head = self.caller.native_initial;
        let mut native_context = Vec::new();
        for op in &self.caller.ops {
            native_context.push(before_tip);
            let Some(done) = &op.done else { continue };
            if let Action::Native { tip, .. } = &op.intent.action {
                ensure(done.review.is_none(), "INVALID native review field")?;
                if let Some(h) = done.effect {
                    ensure(tip.0 == before_tip, "INVALID caller native prior tip")?;
                    let t = transition
                        .next()
                        .ok_or("INVALID missing native audit transition")?;
                    before_head = h.0;
                    before_tip = t;
                }
            }
        }
        ensure(
            before_head == native_head && before_tip == self.tip() && transition.next().is_none(),
            "INVALID caller reconstructed selection",
        )?;
        self.audit_onchain(&native_context)?;
        self.audit_pool(&native_context)?;
        // One actor at a time: no unchecked serialized child state and no in-memory
        // prefix for every registered owner. Native/actor memory remains separately bounded.
        let mut verified = BTreeMap::new();
        for (id, mut state) in actors {
            let unchanged = self.caller.ops[self.onchain_audited..].iter().all(|op| {
                op.intent.action.actor() != Some(id)
                    && op
                        .intent
                        .action
                        .registration(self.chain)
                        .is_ok_and(|r| r.is_none_or(|r| r.id != id))
            });
            if unchanged {
                if let Some(w) = self.actor_audits.get(&id).filter(|w| w.head == state.head) {
                    w.prefix.check(&actor_path(&self.root, id))?;
                    state.pending = self
                        .actors
                        .get(&id)
                        .ok_or("INVALID missing audited actor")?
                        .pending
                        .clone();
                    verified.insert(id, state);
                    continue;
                }
            }
            let mut child = Actor::open(
                &actor_path(&self.root, id),
                self.chain,
                state.reg.role,
                state.head,
                now,
            )?;
            ensure(
                child.initial() == state.initial,
                "INVALID actor initial head",
            )?;
            let (origin, delegation, role) = child.scope();
            ensure(
                role == state.reg.role
                    && origin.channel() == state.reg.channel
                    && delegation.bytes() == state.reg.delegation,
                "INVALID actor native/delegation scope",
            )?;
            let mut h = state.initial;
            let mut pending: Option<Vec<u8>> = None;
            let mut registered = false;
            for (index, op) in self.caller.ops.iter().enumerate() {
                let Some(done) = &op.done else { continue };
                if let Some(reg) = op.intent.action.registration(self.chain)? {
                    ensure(done.review.is_none(), "INVALID registration review")?;
                    if reg.id == id && done.effect.is_some() {
                        ensure(
                            !registered
                                && native_context[index] == reg.tip
                                && done.effect == Some(Id(state.initial)),
                            "INVALID actor registration selection",
                        )?;
                        let ledger = self.native.as_mut().unwrap().historical(reg.tip)?;
                        origin.check_current(&ledger, reg.tip, op.intent.at)?;
                        let history = self
                            .native
                            .as_ref()
                            .unwrap()
                            .history_to_height(reg.tip, origin.birth_height())?;
                        ensure(
                            initial(&reg, &self.genesis, self.chain, &history) == state.initial
                                && done.review.is_none(),
                            "INVALID actor exact initial bytes",
                        )?;
                        registered = true;
                    }
                    continue;
                }
                if op.intent.action.actor() != Some(id) {
                    continue;
                }
                ensure(registered, "INVALID actor action before registration")?;
                let step = done.effect.map(|next| child.audit(h, next.0)).transpose()?;
                let valid = done.effect.is_some() || done.review.is_some();
                if valid {
                    ensure(
                        op.intent.action.tip() == native_context[index],
                        "INVALID actor selected native context",
                    )?;
                }
                if valid && !matches!(op.intent.action, Action::OwnerComplete { .. }) {
                    let ledger = self
                        .native
                        .as_mut()
                        .unwrap()
                        .historical(native_context[index])?;
                    origin.check_current(&ledger, native_context[index], op.intent.at)?;
                }
                match &op.intent.action {
                    Action::OwnerPrepare { invoice, .. } => {
                        ensure(role < 2, "INVALID caller owner role")?;
                        let raw = bytes(invoice, 575)?;
                        if let Some((kind, payload)) = step {
                            ensure(
                                kind == 1
                                    && payload.len() == 42 + raw.len()
                                    && payload[..8] == op.intent.at.to_be_bytes()
                                    && payload[8..40] == native_context[index]
                                    && payload[40..42] == (raw.len() as u16).to_be_bytes()
                                    && payload[42..] == raw,
                                "INVALID caller owner prepare step",
                            )?;
                            pending = Some(raw.clone());
                        }
                        if done.review.is_some() {
                            ensure(
                                pending.as_ref() == Some(&raw),
                                "INVALID caller prepared review",
                            )?;
                        }
                    }
                    Action::OwnerReview { .. } => ensure(
                        done.effect.is_none() && role < 2,
                        "INVALID caller owner review effect",
                    )?,
                    Action::OwnerSign {
                        invoice,
                        review,
                        review_request,
                        approved,
                        ..
                    } => {
                        ensure(
                            role < 2 && done.review.is_none(),
                            "INVALID caller owner sign role",
                        )?;
                        if let Some((kind, payload)) = step {
                            ensure(
                                *approved
                                    && kind == 2
                                    && payload.len() == 169
                                    && payload[..8] == op.intent.at.to_be_bytes()
                                    && payload[8..40] == native_context[index],
                                "INVALID caller owner signature step",
                            )?;
                            let inv = Invoice::verify(
                                &origin,
                                pending.as_ref().ok_or("MISSING caller invoice")?,
                            )?;
                            ensure(inv.id() == invoice.0, "INVALID caller signed invoice")?;
                            inv.verify_partial(&origin, &payload[40..])?;
                            self.approval(index, *review_request, id, h, *review)?;
                            ensure(
                                owner_digest(
                                    &origin,
                                    &delegation,
                                    role,
                                    &inv,
                                    h,
                                    native_context[index],
                                ) == review.0,
                                "INVALID caller owner approval digest",
                            )?;
                        }
                    }
                    Action::OwnerComplete { receipt, ack, .. } => {
                        ensure(
                            role < 2 && done.review.is_none(),
                            "INVALID caller completion role",
                        )?;
                        if let Some((kind, payload)) = step {
                            let r = bytes(receipt, 831)?;
                            let a = bytes(ack, 340)?;
                            ensure(
                                kind == 3
                                    && payload.len() == 10 + r.len() + 340
                                    && payload[..8] == op.intent.at.to_be_bytes()
                                    && payload[8..10] == (r.len() as u16).to_be_bytes()
                                    && payload[10..10 + r.len()] == r
                                    && payload[10 + r.len()..] == a,
                                "INVALID caller complete step",
                            )?;
                            let p = Payment::verify(&origin, &r)?;
                            Acknowledgment::verify(&origin, &delegation, &p, &a)?;
                            pending = None;
                        }
                    }
                    Action::RetainerPrepare { receipt, .. } => {
                        ensure(role == 2, "INVALID caller retainer role")?;
                        let r = bytes(receipt, 831)?;
                        if let Some((kind, payload)) = step {
                            ensure(
                                kind == 1
                                    && payload.len() == 34 + r.len()
                                    && payload[..32] == native_context[index]
                                    && payload[32..34] == (r.len() as u16).to_be_bytes()
                                    && payload[34..] == r,
                                "INVALID caller retainer prepare",
                            )?;
                            pending = Some(r.clone());
                        }
                        if done.review.is_some() {
                            ensure(
                                pending.as_ref() == Some(&r),
                                "INVALID caller retained review",
                            )?;
                        }
                    }
                    Action::RetainerReview { .. } => ensure(
                        role == 2 && done.effect.is_none(),
                        "INVALID caller retainer review effect",
                    )?,
                    Action::RetainerSign {
                        receipt,
                        review,
                        review_request,
                        approved,
                        ..
                    } => {
                        ensure(
                            role == 2 && done.review.is_none(),
                            "INVALID caller retainer signing role",
                        )?;
                        if let Some((kind, payload)) = step {
                            ensure(*approved && kind == 2, "INVALID caller retainer sign step")?;
                            let p = Payment::verify(
                                &origin,
                                pending.as_ref().ok_or("MISSING caller retained payment")?,
                            )?;
                            let ack = Acknowledgment::verify(&origin, &delegation, &p, &payload)?;
                            ensure(
                                p.id() == receipt.0
                                    && ack.observed_at() == op.intent.at
                                    && ack.observed_native_tip() == native_context[index]
                                    && ack.prepared_head() == h,
                                "INVALID caller acknowledgment scope",
                            )?;
                            self.approval(index, *review_request, id, h, *review)?;
                            ensure(
                                fast_payment::review_digest(
                                    native_context[index],
                                    h,
                                    p.id(),
                                    delegation.id(),
                                ) == review.0,
                                "INVALID caller retainer approval",
                            )?;
                            pending = None;
                        }
                    }
                    _ => return Err("INVALID caller actor action".into()),
                }
                if let Some(next) = done.effect {
                    h = next.0;
                }
                if let Some(review) = done.review {
                    let expected = if role < 2 {
                        let inv = Invoice::verify(
                            &origin,
                            pending.as_ref().ok_or("MISSING caller review invoice")?,
                        )?;
                        owner_digest(&origin, &delegation, role, &inv, h, native_context[index])
                    } else {
                        let p = Payment::verify(
                            &origin,
                            pending.as_ref().ok_or("MISSING caller review receipt")?,
                        )?;
                        fast_payment::review_digest(
                            native_context[index],
                            h,
                            p.id(),
                            delegation.id(),
                        )
                    };
                    ensure(
                        review.0 == expected
                            && matches!(
                                op.intent.action,
                                Action::OwnerPrepare { .. }
                                    | Action::OwnerReview { .. }
                                    | Action::RetainerPrepare { .. }
                                    | Action::RetainerReview { .. }
                            ),
                        "INVALID caller persisted review",
                    )?;
                }
            }
            ensure(
                registered && h == state.head,
                "INVALID caller actor transition coverage",
            )?;
            state.pending = pending;
            let proofs = match &mut child {
                Actor::Owner(j) => j
                    .retained_complete(state.head)?
                    .map(|(raw, _)| {
                        Payment::verify(&origin, &raw).map(|p| vec![p.after_certificate().to_vec()])
                    })
                    .transpose()?
                    .unwrap_or_default(),
                Actor::Retainer(j) => j.protected_certificates(state.head)?,
            };
            let prefix = match &mut child {
                Actor::Owner(j) => j.authenticated_prefix(state.head)?,
                Actor::Retainer(j) => j.authenticated_prefix(state.head)?,
            };
            self.actor_audits.insert(
                id,
                ActorAudit {
                    head: state.head,
                    prefix,
                    origin,
                    proofs,
                },
            );
            verified.insert(id, state);
        }
        // An effect or review for an unknown target cannot disappear from an audit.
        for op in &self.caller.ops {
            if let (Some(id), Some(d)) = (op.intent.action.actor(), &op.done) {
                ensure(
                    (d.effect.is_none() && d.review.is_none()) || verified.contains_key(&id),
                    "INVALID caller unknown actor effect",
                )?;
            }
        }
        self.actors = verified;
        Ok(())
    }
    fn approval(&self, index: usize, request: Id, actor: Id, head: Hash, review: Id) -> Result<()> {
        let at = self.caller.ops[..index]
            .iter()
            .rposition(|o| o.intent.id == request)
            .ok_or("INVALID missing persisted approval review")?;
        let op = &self.caller.ops[at];
        let done = op
            .done
            .as_ref()
            .ok_or("INVALID incomplete approval review")?;
        ensure(
            op.intent.action.actor() == Some(actor) && done.review == Some(review),
            "INVALID persisted approval reference",
        )?;
        // No intervening child mutation may rebase the approved owner/retainer head.
        let latest = self.caller.ops[..=at]
            .iter()
            .rev()
            .find_map(|o| {
                if o.intent.action.actor() == Some(actor)
                    || o.intent
                        .action
                        .registration(self.chain)
                        .ok()
                        .flatten()
                        .is_some_and(|r| r.id == actor)
                {
                    o.done.as_ref().and_then(|d| d.effect)
                } else {
                    None
                }
            })
            .ok_or("MISSING approval child head")?;
        ensure(latest.0 == head, "INVALID stale child approval head")
    }
    fn preflight(&self, action: &Action) -> Result<()> {
        action.shape()?;
        self.pool_preflight(action)?;
        self.onchain_preflight(action)?;
        self.fee_preflight(action)?;
        if let Some(reg) = action.registration(self.chain)? {
            ensure(
                self.actors.len() < 16 && !self.actors.contains_key(&reg.id),
                "CONFLICT session actor already registered/capacity",
            )?;
        }
        if let Some(id) = action.actor() {
            let a = self.actors.get(&id).ok_or("MISSING session actor")?;
            let owner = matches!(
                action,
                Action::OwnerPrepare { .. }
                    | Action::OwnerReview { .. }
                    | Action::OwnerSign { .. }
                    | Action::OwnerComplete { .. }
            );
            ensure(owner == (a.reg.role < 2), "INVALID session actor role")?;
        }
        Ok(())
    }
    fn apply(
        &mut self,
        action: &Action,
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<(Option<Id>, Option<Id>)> {
        if let Action::PoolSubmit { tip, operation } = action {
            let n = self.native.as_mut().unwrap();
            n.check(n.head(), tip.0, now)?;
            fast::validate_operation(&bytes(operation, 4096)?, self.chain)?;
            return Ok((None, None));
        }
        if let Some(reg) = action.registration(self.chain)? {
            let n = self.native.as_mut().unwrap();
            let history = n.funding_history(n.head(), reg.tip, reg.channel, now)?;
            let creation = Creation {
                genesis: &self.genesis,
                chain: self.chain,
                history: &history,
                delegation: &reg.delegation,
                current: n.current(n.head(), reg.tip, now)?,
                limit: CHILD_LIMIT,
            };
            let p = actor_path(&self.root, reg.id);
            let head = if reg.role < 2 {
                fast_owner::Journal::create(&p, creation, reg.role)?.head()
            } else {
                fast_retainer::Journal::create(&p, creation)?.head()
            };
            return Ok((Some(Id(head)), None));
        }
        if let Action::Native { tip, block } = action {
            let n = self.native.as_mut().unwrap();
            let o = n.accept(&bytes(block, 262144)?, n.head(), tip.0, now)?;
            return Ok(((!o.already_known).then_some(Id(o.head)), None));
        }
        let id = action.actor().ok_or("INVALID session target")?;
        let state = self.actors.get(&id).ok_or("MISSING session actor")?.clone();
        if let Action::OwnerSign {
            review_request,
            review,
            approved,
            ..
        }
        | Action::RetainerSign {
            review_request,
            review,
            approved,
            ..
        } = action
        {
            ensure(*approved, "INVALID explicit native approval required")?;
            self.approval(
                self.caller.ops.len() - 1,
                *review_request,
                id,
                state.head,
                *review,
            )?;
        }
        let mut child = Actor::open(
            &actor_path(&self.root, id),
            self.chain,
            state.reg.role,
            state.head,
            now,
        )?;
        let n = self.native.as_mut().unwrap();
        n.check(n.head(), action.tip(), now)?;
        let current = n.current(n.head(), action.tip(), now)?;
        let review = match (&mut child, action) {
            (Actor::Owner(j), Action::OwnerPrepare { invoice, .. }) => Some(Id(j
                .prepare(&bytes(invoice, 575)?, state.head, current)?
                .digest)),
            (Actor::Owner(j), Action::OwnerReview { .. }) => {
                Some(Id(j.review(state.head, current)?.digest))
            }
            (
                Actor::Owner(j),
                Action::OwnerSign {
                    review,
                    invoice,
                    key_file,
                    ..
                },
            ) => {
                let pending = j.retained_pending(state.head, invoice.0)?;
                ensure(
                    Invoice::verify(&j.scope().0, &pending.invoice)?.id() == invoice.0,
                    "INVALID session invoice ID",
                )?;
                j.sign(state.head, review.0, current, || {
                    load_key(Path::new(key_file), self.chain, password)
                })?;
                None
            }
            (Actor::Owner(j), Action::OwnerComplete { receipt, ack, .. }) => {
                j.retain_complete(state.head, &bytes(receipt, 831)?, &bytes(ack, 340)?, now)?;
                None
            }
            (Actor::Retainer(j), Action::RetainerPrepare { receipt, .. }) => Some(Id(j
                .prepare(&bytes(receipt, 831)?, state.head, current)?
                .digest)),
            (Actor::Retainer(j), Action::RetainerReview { .. }) => {
                Some(Id(j.review(state.head, current)?.digest))
            }
            (
                Actor::Retainer(j),
                Action::RetainerSign {
                    review,
                    receipt,
                    key_file,
                    ..
                },
            ) => {
                let pending = state
                    .pending
                    .as_ref()
                    .ok_or("MISSING session pending receipt")?;
                ensure(
                    Payment::verify(&j.scope().0, pending)?.id() == receipt.0,
                    "INVALID session receipt ID",
                )?;
                j.acknowledge(state.head, review.0, current, || {
                    load_key(Path::new(key_file), self.chain, password)
                })?;
                None
            }
            _ => return Err("INVALID session action role".into()),
        };
        Ok((
            (child.head() != state.head).then_some(Id(child.head())),
            review,
        ))
    }
    pub fn execute(
        &mut self,
        id: Id,
        expected: Hash,
        action: Action,
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<Value> {
        self.execute_observed(id, expected, action, password, now, |_| {})
    }
    pub fn execute_observed(
        &mut self,
        id: Id,
        expected: Hash,
        action: Action,
        password: Option<&[u8]>,
        now: u64,
        mut observe: impl FnMut(Boundary),
    ) -> Result<Value> {
        self.check_control(expected)?;
        self.caller.check(expected)?;
        ensure(
            self.native.is_some(),
            "RESOURCE_WAIT session native restart required",
        )?;
        self.preflight(&action)?;
        if let Some(control) = &mut self.control {
            control.begin(
                expected,
                &journal::Intent {
                    id,
                    action: action.clone(),
                    at: now,
                },
            )?;
        }
        self.caller.begin(id, action.clone(), now)?;
        observe(Boundary::IntentDurable);
        if let Some(control) = &mut self.control {
            control.authorize(expected, &self.caller.ops.last().unwrap().intent)?;
        }
        let result = if action.native_authorization() {
            self.onchain_apply(&action, password, now)
        } else {
            self.apply(&action, password, now)
                .map(|(e, r)| (e, r, None))
        };
        let (effect, review, authorization, diagnostic) = match result {
            Ok((e, r, authorization)) => {
                observe(
                    if action.native_authorization() || matches!(action, Action::PoolSubmit { .. })
                    {
                        Boundary::NativeActionEvaluated
                    } else {
                        Boundary::ChildDurable
                    },
                );
                (e, r, authorization, None)
            }
            Err(error) => {
                let (e, r) = self.resolve(now)?;
                (
                    e,
                    r,
                    None,
                    Some({
                        let mut message = error;
                        while message.len() > 256 {
                            message.pop();
                        }
                        message
                    }),
                )
            }
        };
        self.verify_pending(
            effect,
            review,
            diagnostic.clone(),
            authorization.clone(),
            now,
        )?;
        self.caller
            .finish_authorized(effect, review, diagnostic, authorization)?;
        self.onchain_audited = self.caller.ops.len();
        observe(Boundary::ReplyDurable);
        if let Some(control) = &mut self.control {
            control.finish(self.caller.head)?;
        }
        self.output(now)
    }
    fn resolve(&mut self, now: u64) -> Result<(Option<Id>, Option<Id>)> {
        let action = self
            .caller
            .ops
            .last()
            .ok_or("MISSING caller intent")?
            .intent
            .action
            .clone();
        if action.native_authorization() || matches!(action, Action::PoolSubmit { .. }) {
            return Ok((None, None));
        }
        if let Some(reg) = action.registration(self.chain)? {
            let p = actor_path(&self.root, reg.id);
            if !p.try_exists().map_err(fast_retainer::io)? {
                return Ok((None, None));
            }
            let n = self.native.as_mut().unwrap();
            let ledger = n.historical(reg.tip)?;
            let origin = ledger.funding_origin(reg.channel)?;
            origin.check_current(&ledger, reg.tip, self.caller.ops.last().unwrap().intent.at)?;
            let history = n.history_to_height(reg.tip, origin.birth_height())?;
            let h = initial(&reg, &self.genesis, self.chain, &history);
            let c = Actor::open(&p, self.chain, reg.role, h, now)?;
            ensure(c.head() == h, "INVALID recovered actor initial head")?;
            return Ok((Some(Id(h)), None));
        }
        if let Action::Native { block, .. } = &action {
            let (prior, _) = Self::structural(&self.caller, self.chain)?;
            drop(self.native.take());
            let raw = bytes(block, 262144)?;
            let p = self.root.join("native.journal");
            let s = match Store::open(
                &p,
                &self.genesis,
                self.chain,
                prior,
                now,
                fast_store::Limits::default(),
            ) {
                Ok(s) => s,
                Err(_) => Store::recover(
                    &p,
                    &self.genesis,
                    self.chain,
                    prior,
                    fast::block_id(&raw)?,
                    now,
                    fast_store::Limits::default(),
                )?,
            };
            let effect = (s.head() != prior).then_some(Id(s.head()));
            self.native = Some(s);
            return Ok((effect, None));
        }
        let id = action.actor().ok_or("INVALID session recovery target")?;
        let state = self.actors.get(&id).ok_or("MISSING recovery actor")?;
        let path = actor_path(&self.root, id);
        if Actor::open(&path, self.chain, state.reg.role, state.head, now).is_ok() {
            return Ok((None, None));
        }
        let h = match &action {
            Action::OwnerPrepare { invoice, .. } => {
                let origin = self
                    .native
                    .as_mut()
                    .unwrap()
                    .historical(state.reg.tip)?
                    .funding_origin(state.reg.channel)?;
                let inv = Invoice::verify(&origin, &bytes(invoice, 575)?)?;
                fast_owner::Journal::recover(
                    &path,
                    self.chain,
                    state.head,
                    inv.id(),
                    now,
                    CHILD_LIMIT,
                )?
                .head
            }
            Action::OwnerSign { invoice, .. } => {
                fast_owner::Journal::recover(
                    &path,
                    self.chain,
                    state.head,
                    invoice.0,
                    now,
                    CHILD_LIMIT,
                )?
                .head
            }
            Action::OwnerComplete { receipt, .. } => {
                let origin = self
                    .native
                    .as_mut()
                    .unwrap()
                    .historical(state.reg.tip)?
                    .funding_origin(state.reg.channel)?;
                let p = Payment::verify(&origin, &bytes(receipt, 831)?)?;
                fast_owner::Journal::recover_complete(
                    &path,
                    self.chain,
                    state.head,
                    p.id(),
                    now,
                    CHILD_LIMIT,
                )?
                .0
            }
            Action::RetainerPrepare { receipt, .. } => {
                let origin = self
                    .native
                    .as_mut()
                    .unwrap()
                    .historical(state.reg.tip)?
                    .funding_origin(state.reg.channel)?;
                let p = Payment::verify(&origin, &bytes(receipt, 831)?)?;
                fast_retainer::Journal::recover(
                    &path,
                    self.chain,
                    state.head,
                    p.id(),
                    now,
                    CHILD_LIMIT,
                )?
                .head
            }
            Action::RetainerSign { receipt, .. } => {
                fast_retainer::Journal::recover(
                    &path,
                    self.chain,
                    state.head,
                    receipt.0,
                    now,
                    CHILD_LIMIT,
                )?
                .head
            }
            _ => return Err("INVALID recovery unexpected child mutation".into()),
        };
        let child = Actor::open(&path, self.chain, state.reg.role, h, now)?;
        let (origin, d, role) = child.scope();
        let review = match &action {
            Action::OwnerPrepare { invoice, .. } => {
                let i = Invoice::verify(&origin, &bytes(invoice, 575)?)?;
                Some(Id(owner_digest(&origin, &d, role, &i, h, action.tip())))
            }
            Action::RetainerPrepare { receipt, .. } => {
                let p = Payment::verify(&origin, &bytes(receipt, 831)?)?;
                Some(Id(fast_payment::review_digest(
                    action.tip(),
                    h,
                    p.id(),
                    d.id(),
                )))
            }
            _ => None,
        };
        Ok((Some(Id(h)), review))
    }
    fn verify_pending(
        &mut self,
        effect: Option<Id>,
        review: Option<Id>,
        diagnostic: Option<String>,
        authorization: Option<String>,
        now: u64,
    ) -> Result<()> {
        let i = &self
            .caller
            .ops
            .last()
            .ok_or("MISSING pending caller")?
            .intent;
        let d = Done {
            id: i.id,
            request: i.action.digest()?,
            effect,
            review,
            diagnostic,
            authorization,
        };
        self.caller.ops.last_mut().unwrap().done = Some(d);
        let result = self.audit(now);
        self.caller.ops.last_mut().unwrap().done = None;
        result
    }
    pub fn recover(
        root: &Path,
        genesis: &[u8],
        chain: Hash,
        prior: Hash,
        id: Id,
        request: Id,
        now: u64,
    ) -> Result<(Self, Value)> {
        Self::recover_profile(root, genesis, chain, prior, (id, request), now, 1)
    }
    fn recover_profile(
        root: &Path,
        genesis: &[u8],
        chain: Hash,
        prior: Hash,
        binding: (Id, Id),
        now: u64,
        version: u8,
    ) -> Result<(Self, Value)> {
        let (id, request) = binding;
        Self::paths(root)?;
        let caller = Journal::open(
            &root.join("caller.journal"),
            genesis,
            chain,
            None,
            now,
            version,
        )?;
        let last = caller
            .ops
            .last()
            .ok_or("MISSING session recovery request")?;
        ensure(
            last.prior == prior && last.intent.id == id && last.intent.action.digest()? == request,
            "INVALID exact session recovery request",
        )?;
        let pending = last.done.is_none();
        let action = last.intent.action.clone();
        let (native_head, actors) = Self::structural(&caller, chain)?;
        let native = match Store::open(
            &root.join("native.journal"),
            genesis,
            chain,
            native_head,
            now,
            fast_store::Limits::default(),
        ) {
            Ok(s) => s,
            Err(e) => {
                if pending {
                    if let Action::Native { block, .. } = &action {
                        Store::recover(
                            &root.join("native.journal"),
                            genesis,
                            chain,
                            native_head,
                            fast::block_id(&bytes(block, 262144)?)?,
                            now,
                            fast_store::Limits::default(),
                        )?
                    } else {
                        return Err(e);
                    }
                } else {
                    return Err(e);
                }
            }
        };
        let mut s = Self {
            root: root.to_path_buf(),
            genesis: genesis.to_vec(),
            chain,
            caller,
            native: Some(native),
            actors,
            actor_audits: BTreeMap::new(),
            mining: None,
            onchain_audited: 0,
            pool_mining: None,
            pool_cursor: 0,
            candidate: None,
            control: None,
        };
        if pending {
            // For a pending native step the retained store may already be one step ahead;
            // resolve uses the independently tracked pre-request head, not that observation.
            let (e, mut r) = if let Action::Native { block, .. } = &action {
                let n = s.native.as_ref().unwrap();
                if n.head() == native_head {
                    (None, None)
                } else {
                    n.block(fast::block_id(&bytes(block, 262144)?)?)?;
                    (Some(Id(n.head())), None)
                }
            } else {
                s.resolve(now)?
            };
            let diagnostic = if let Action::PoolSubmit { tip, .. } = &action {
                if tip.0 != s.tip() {
                    Some("RECOVERED_POOL_REJECTED_STALE_SELECTION".into())
                } else {
                    s.pool_preflight(&action)?;
                    let n = s.native.as_mut().unwrap();
                    n.check(n.head(), tip.0, now)?;
                    None
                }
            } else if let Action::OpenCombine { tip, .. } = &action {
                if tip.0 != s.tip() {
                    Some("RECOVERED_OPENING_REJECTED_STALE_SELECTION".into())
                } else {
                    let index = s.caller.ops.len() - 1;
                    let at = s.caller.ops[index].intent.at;
                    let raw = s.combine_opening(index, &action, at, true)?;
                    r = Some(Id(fast::operation_id(&raw)));
                    None
                }
            } else {
                Some("RECOVERED_EXISTING_EFFECT_OR_NO_CHILD_STEP".into())
            };
            s.verify_pending(e, r, diagnostic.clone(), None, now)?;
            s.caller.finish(e, r, diagnostic)?;
        } else {
            s.audit(now)?;
        }
        s.onchain_audited = s.caller.ops.len();
        let out = s.output(now)?;
        Ok((s, out))
    }
    fn output(&mut self, now: u64) -> Result<Value> {
        let op = self
            .caller
            .ops
            .last()
            .ok_or("MISSING caller result")?
            .clone();
        let done = op.done.as_ref().ok_or("MISSING caller complete response")?;
        let mut out = json!({"session_head":Id(self.head()),"native_head":Id(self.native_head()),"selected_tip":Id(self.tip()),"request_id":op.intent.id,"request_digest":op.intent.action.digest()?,"review_digest":done.review,"diagnostic":done.diagnostic,"fast_completion_authorized":false,"network_monitoring":false,"independent_freshness":false,"mainnet":false,"network_kind":"NO_VALUE_ONLY","key_loaded_by_recovery":false});
        if let Action::PoolSubmit { operation, .. } = &op.intent.action {
            if done.diagnostic.is_none() {
                let id = fast::operation_id(&bytes(operation, 4096)?);
                out["pool_operation"] = serde_json::to_value(Id(id)).map_err(fast_retainer::io)?;
                out["pool_retained"] = true.into();
                out["native_inclusion_known"] = false.into();
            }
        }
        if let Some(review) = self.onchain_output(&op.intent.action, done, op.intent.at)? {
            out["review"] = review;
        }
        let index = self.caller.ops.len() - 1;
        if done.authorization.is_some() {
            if let Some(policy) = self.policy_output(&op.intent.action, done)? {
                out["fee_policy"] = policy;
            } else if let Some((request, partial)) =
                self.opening_signature(index, &op.intent.action)?
            {
                let (proposal, _) = request.parts()?;
                out["opening_partial_hex"] = hex::encode(partial).into();
                out["opening_proposal"] =
                    serde_json::to_value(Id(fast::opening::proposal_id(&proposal, self.chain)?))
                        .map_err(fast_retainer::io)?;
                out["partial_only"] = true.into();
            } else {
                let raw = self.retained_authorization(index)?;
                out["operation_hex"] = hex::encode(&raw).into();
                out["operation_id"] = serde_json::to_value(Id(fast::operation_id(&raw)))
                    .map_err(fast_retainer::io)?;
            }
            out["ledger_admitted"] = false.into();
        }
        if matches!(op.intent.action, Action::OpenCombine { .. }) && done.review.is_some() {
            let raw = self.retained_authorization(index)?;
            out["operation_hex"] = hex::encode(&raw).into();
            out["operation_id"] =
                serde_json::to_value(Id(fast::operation_id(&raw))).map_err(fast_retainer::io)?;
            out["ledger_admitted"] = false.into();
        }
        if let Some(reg) = op.intent.action.registration(self.chain)? {
            if done.effect.is_some() {
                out["actor"] = serde_json::to_value(reg.id).map_err(fast_retainer::io)?;
                out["actor_head"] = serde_json::to_value(done.effect).map_err(fast_retainer::io)?;
            }
            return Ok(out);
        }
        if let Some(id) = op.intent.action.actor() {
            let state = self.actors.get(&id).ok_or("MISSING result actor")?;
            let mut child = Actor::open(
                &actor_path(&self.root, id),
                self.chain,
                state.reg.role,
                state.head,
                now,
            )?;
            let (origin, d, role) = child.scope();
            out["actor"] = serde_json::to_value(id).map_err(fast_retainer::io)?;
            out["actor_head"] = serde_json::to_value(Id(state.head)).map_err(fast_retainer::io)?;
            if let Some(head) = done.effect {
                // Locate the verified previous child head through the covered caller chain.
                let before = self.before_actor(self.caller.ops.len() - 1, id)?;
                let (kind, p) = child.audit(before, head.0)?;
                match (role, kind) {
                    (0 | 1, 1) => {
                        out["invoice_hex"] = hex::encode(&p[42..]).into();
                    }
                    (0 | 1, 2) => {
                        out["partial_hex"] = hex::encode(&p[40..]).into();
                    }
                    (0 | 1, 3) => {
                        let n = u16::from_be_bytes(p[8..10].try_into().unwrap()) as usize;
                        out["receipt_hex"] = hex::encode(&p[10..10 + n]).into();
                        out["ack_hex"] = hex::encode(&p[10 + n..]).into();
                    }
                    (2, 1) => {
                        out["receipt_hex"] = hex::encode(&p[34..]).into();
                    }
                    (2, 2) => {
                        out["ack_hex"] = hex::encode(p).into();
                    }
                    _ => return Err("INVALID result child step".into()),
                }
            }
            if done.review.is_some() {
                let pending = state
                    .pending
                    .as_ref()
                    .ok_or("MISSING result pending review")?;
                if role < 2 {
                    let i = Invoice::verify(&origin, pending)?;
                    out["invoice_hex"] = hex::encode(pending).into();
                    out["review"] = json!({"chain":Id(origin.chain()),"channel":Id(origin.channel()),"owner":Id(origin.owners()[role as usize]),"payer":Id(origin.owners()[i.payer()]),"recipient":Id(origin.owners()[1-i.payer()]),"amount":i.amount().to_string(),"fee":i.fee().to_string(),"invoice_id":Id(i.id()),"miner":Id(origin.miner()),"retainer":Id(d.retainer()),"sequence":i.sequence().to_string()});
                } else {
                    let p = Payment::verify(&origin, pending)?;
                    out["review"] = json!({"receipt_id":Id(p.id()),"logical_id":Id(p.logical_id()),"fee":p.fee().to_string(),"miner":Id(origin.miner()),"retainer":Id(d.retainer())});
                }
            }
        }
        Ok(out)
    }
    fn before_actor(&self, index: usize, id: Id) -> Result<Hash> {
        self.caller.ops[..index]
            .iter()
            .rev()
            .find_map(|o| {
                let same = o.intent.action.actor() == Some(id)
                    || o.intent
                        .action
                        .registration(self.chain)
                        .ok()
                        .flatten()
                        .is_some_and(|r| r.id == id);
                if same {
                    o.done.as_ref().and_then(|d| d.effect).map(|h| h.0)
                } else {
                    None
                }
            })
            .ok_or("MISSING actor previous head".into())
    }
    pub fn pending(&mut self, expected: Hash, id: Id, invoice: Id, now: u64) -> Result<Value> {
        self.caller.check(expected)?;
        let state = self.actors.get(&id).ok_or("MISSING session actor")?;
        match Actor::open(
            &actor_path(&self.root, id),
            self.chain,
            state.reg.role,
            state.head,
            now,
        )? {
            Actor::Owner(mut j) => {
                let r = j.retained_pending(state.head, invoice.0)?;
                Ok(
                    json!({"invoice_hex":hex::encode(r.invoice),"partial_hex":r.partial.map(hex::encode),"fast_completion_authorized":false,"backing_currentness_known":false}),
                )
            }
            Actor::Retainer(mut j) => Ok(
                json!({"ack_hex":hex::encode(j.retained_ack(state.head,invoice.0)?),"fast_completion_authorized":false,"backing_currentness_known":false}),
            ),
        }
    }
}
impl Session {
    /// Unsigned proposal from this owner's fully authenticated latest receipt.
    /// Constructing it does not sign, reserve or accept a supplied ledger.
    pub fn propose(
        &mut self,
        expected: Hash,
        actor: Id,
        payer: u8,
        amount: u128,
        invoice: Hash,
        now: u64,
    ) -> Result<Value> {
        self.caller.check(expected)?;
        let state = self.actors.get(&actor).ok_or("MISSING proposal owner")?;
        ensure(
            state.reg.role < 2 && state.pending.is_none(),
            "CONFLICT proposal role/pending invoice",
        )?;
        let mut child = fast_owner::Journal::open(
            &actor_path(&self.root, actor),
            self.chain,
            state.head,
            now,
            CHILD_LIMIT,
        )?;
        let (origin, _, _) = child.scope();
        let n = self.native.as_mut().ok_or("RESOURCE_WAIT native restart")?;
        let tip = n.ledger().tip().id();
        let current = n.current(n.head(), tip, now)?;
        origin.check_current(current.ledger, tip, now)?;
        let complete = child.retained_complete(state.head)?;
        let previous = complete
            .map(|(r, _)| Payment::verify(&origin, &r))
            .transpose()?;
        let i = Invoice::propose(&origin, previous.as_ref(), payer, amount, invoice)?;
        Ok(
            json!({"invoice_hex":hex::encode(i.bytes()),"invoice_id":Id(i.id()),"payer":Id(origin.owners()[i.payer()]),"recipient":Id(origin.owners()[1-i.payer()]),"amount":i.amount().to_string(),"fee":i.fee().to_string(),"selected_tip":Id(tip),"session_head":Id(expected),"signed":false,"reserved":false,"fast_completion_authorized":false}),
        )
    }
}
fn load_key(
    path: &Path,
    chain: Hash,
    password: Option<&[u8]>,
) -> Result<ed25519_dalek::SigningKey> {
    let password = password.ok_or("INVALID secure native password input required")?;
    fast_retainer::private(path, true)?;
    let mut file = File::open(path).map_err(|_| "RESOURCE_WAIT key file")?;
    let a = fs::symlink_metadata(path).map_err(|_| "RESOURCE_WAIT key metadata")?;
    let b = file.metadata().map_err(|_| "RESOURCE_WAIT opened key")?;
    ensure(
        a.len() == 187 && b.len() == 187,
        "INVALID encrypted key bound",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure(
            a.ino() == b.ino() && a.dev() == b.dev(),
            "INVALID replaced encrypted key",
        )?;
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(188)
        .read_to_end(&mut raw)
        .map_err(|_| "RESOURCE_WAIT key read")?;
    ensure(raw.len() == 187, "INVALID encrypted key size")?;
    keyfile::decrypt(&raw, chain, password)
}
