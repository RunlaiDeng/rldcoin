//! Ordinary Rust pacemaker. Native full replay and separate caller custody authorize every action.
use super::*;
use crate::{
    bft as consensus, bft_client, bft_network as net, bft_phase_schedule as phase,
    bft_proposal_schedule as proposal, bft_runtime_archive as retention, bft_tick_schedule as tick,
    contact::Frame, storage::Store, Command, Hash, Snapshot,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::fd::AsRawFd,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Validator {
    key: String,
    node_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format: String,
    state: PathBuf,
    signer_dir: PathBuf,
    head_file: PathBuf,
    key_file: PathBuf,
    key: String,
    miner: String,
    validators: Vec<Validator>,
    block_interval: f64,
    round_timeout: f64,
    stop_height: u64,
    #[serde(default)]
    startup_native_history_head: Option<Hash>,
}

pub(crate) struct Runtime {
    config: Config,
    archive: retention::Archive,
    head: Option<Hash>,
    slot: Option<(consensus::Context, u64)>,
    entered: f64,
    #[cfg(test)]
    last_decision: Option<&'static str>,
    #[cfg(test)]
    last_broadcast: Vec<Hash>,
    _lock: File,
}
fn hash(value: &Value) -> Result<Hash> {
    Ok(Hash(Sha256::digest(bytes(value)?).into()))
}
fn state_hash(value: &bft_client::State) -> Result<Hash> {
    hash(&serde_json::to_value(value).map_err(|e| e.to_string())?)
}
impl Runtime {
    pub(crate) fn open(path: &Path, node: &Store, transport: &Value) -> Result<Self> {
        let config: Config =
            serde_json::from_value(read(path, 64 * 1024)?).map_err(|e| e.to_string())?;
        require(
            (config.format == bft_client::FORMAT || config.format == bft_client::ORIGIN_FORMAT)
                && config.block_interval.is_finite()
                && (0.5..=60.0).contains(&config.block_interval)
                && config.round_timeout.is_finite()
                && config.round_timeout >= config.block_interval
                && config.round_timeout <= 300.0
                && config.stop_height <= 64,
            "Rust BFT profile/timing/height bound",
        )?;
        // A startup head is an explicitly retained input, never adopted from telemetry.
        if let Some(head) = config.startup_native_history_head {
            require(
                node.storage_head()? == head,
                "Rust BFT pinned startup Native head differs",
            )?;
        }
        files::private_path(&config.state, true)?;
        let lock = files::options()
            .read(true)
            .write(true)
            .create(true)
            .open(config.state.join(".bft-runtime.lock"))
            .map_err(|e| e.to_string())?;
        files::private_metadata(&lock)?;
        require(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another BFT runtime owns this archive",
        )?;
        let context = consensus::Context::current(node)?;
        let keys = context.keys(&node.trust, &node.evidence)?;
        require(
            config
                .validators
                .iter()
                .map(|v| v.key.clone())
                .collect::<Vec<_>>()
                == keys
                && config
                    .validators
                    .iter()
                    .map(|v| &v.node_id)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 4,
            "BFT validators differ from signed Native membership",
        )?;
        let mesh = Node::open(transport)?;
        require(
            config
                .validators
                .iter()
                .any(|v| v.key == config.key && v.node_id == mesh.id)
                && mesh.network == context.currency.to_hex()
                && mesh.region == context.region.to_hex(),
            "BFT carrier differs from independently configured signer",
        )?;
        drop(mesh);
        let caller = bft_client::Client::lock(
            &config.head_file,
            &config.signer_dir,
            config.key.clone(),
            config.format.clone(),
            node,
        )?;
        let state = caller.read()?;
        if state.pending.is_some() {
            let recovered = caller.reconcile(node, state.clone())?;
            Self::publish_head(&caller, node, &state, recovered)?;
        }
        drop(caller);
        let client = retention::Client::lock(
            &config.state,
            config.key.clone(),
            config.format.clone(),
            node,
        )?;
        let path = config.state.join("state.json");
        let (archive, head) = if fs::symlink_metadata(&path).is_ok() {
            let receipt = client.read(node)?;
            (
                retention::Archive::decode(&files::private_read_with_limit(
                    &path,
                    retention::MAX_STATE,
                )?)?,
                Some(receipt.state_sha256),
            )
        } else {
            (
                retention::Archive {
                    format: retention::FORMAT.into(),
                    snapshots: BTreeMap::new(),
                    runtime: retention::Runtime {
                        format: config.format.clone(),
                        binding: consensus::Binding {
                            currency: context.currency,
                            region: context.region,
                            key: config.key.clone(),
                        },
                        messages: BTreeMap::new(),
                        height: node.chain.height(),
                        tip: node.chain.tip()?,
                        snapshot_cache: vec![],
                        cursor: 0,
                    },
                },
                None,
            )
        };
        drop(client);
        let mut runtime = Self {
            config,
            archive,
            head,
            slot: None,
            entered: super::service::monotonic()?,
            #[cfg(test)]
            last_decision: None,
            #[cfg(test)]
            last_broadcast: Vec::new(),
            _lock: lock,
        };
        if runtime.head.is_none() {
            runtime.persist(node)?;
        }
        runtime.flush(node)?;
        let (agent, _) = consensus::Agent::inspect_with_status(&runtime.config.signer_dir, node)?;
        let messages = agent.retained_messages(node)?;
        drop(agent);
        for message in messages {
            runtime.retain_local(node, net::Body::Signed(Box::new(message)))?;
        }
        if let Some(checkpoint) = node.chain.finalized {
            if let Some(snapshot) = node
                .journal
                .evidence
                .snapshots
                .iter()
                .find(|s| s.statement.id().ok() == Some(checkpoint))
                .cloned()
            {
                runtime.retain_local(node, net::Body::Finalized(Box::new(snapshot)))?;
            }
        }
        Ok(runtime)
    }

    fn persist(&mut self, node: &Store) -> Result<()> {
        let raw = files::canonical_with_limit(&self.archive, retention::MAX_STATE)?;
        let client = retention::Client::lock(
            &self.config.state,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let receipt = client.store(node, &raw, self.head)?;
        self.head = Some(receipt.state_sha256);
        Ok(())
    }

    fn retain_local(&mut self, node: &Store, body: net::Body) -> Result<()> {
        let packed = net::local_envelope(body, node)?.envelope;
        self.retain(node, packed, true)
    }

    fn retain(&mut self, node: &Store, wire: net::WireEnvelope, local: bool) -> Result<()> {
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let envelope = wire.clone().expand()?;
        envelope.verify(node)?;
        #[cfg(test)]
        super::service::trace_subwork("retain-complete-envelope", started)?;
        let ident = hash(&serde_json::to_value(&envelope.body).map_err(|e| e.to_string())?)?;
        if self.archive.runtime.messages.contains_key(&ident) {
            // Every complete envelope authenticated first. Preserve both
            // original proof bytes and the original local-carriage flag.
            return Ok(());
        }
        require(
            self.archive.runtime.messages.len() < 512,
            "BFT retained message capacity; preserve all original evidence",
        )?;
        let value = envelope.value()?;
        let complete = serde_json::to_value(&wire).map_err(|e| e.to_string())?;
        let raw = files::canonical_with_limit(&complete, crate::contact::MAX_PAYLOAD)?;
        let mut proposed = self.archive.clone();
        let mut refs = Vec::new();
        let mut origins = None;
        for snapshot in complete["evidence"]["snapshots"]
            .as_array()
            .ok_or("BFT complete snapshot list")?
        {
            let key = hash(snapshot)?;
            if let Some(old) = proposed.snapshots.get(&key) {
                require(old == snapshot, "BFT shared snapshot collision")?;
            }
            proposed.snapshots.insert(key, snapshot.clone());
            refs.push(key);
        }
        if let Some(values) = complete["origins"].as_array() {
            let mut keys = Vec::new();
            for origin in values {
                let key = hash(origin)?;
                if let Some(old) = proposed.snapshots.get(&key) {
                    require(old == origin, "BFT shared origin collision")?;
                }
                proposed.snapshots.insert(key, origin.clone());
                keys.push(key);
            }
            origins = Some(keys);
        }
        proposed.runtime.messages.insert(
            ident,
            retention::Record {
                header: retention::Header {
                    format: envelope.format,
                    currency: envelope.currency,
                    region: envelope.region,
                },
                body: complete["body"].clone(),
                refs,
                origin_refs: origins,
                sha256: Hash(Sha256::digest(&raw).into()),
                size_bytes: raw.len(),
                value,
                local,
            },
        );
        let previous = std::mem::replace(&mut self.archive, proposed);
        #[cfg(test)]
        let started = super::service::monotonic()?;
        if let Err(e) = self.persist(node) {
            self.archive = previous;
            return Err(e);
        }
        #[cfg(test)]
        super::service::trace_subwork("retain-durable-archive", started)?;
        #[cfg(test)]
        super::service::trace_payment_event(|| {
            Ok(
                json!({"phase":"payment-body-retained","body_id":ident,"local":local,
                "body":payment_trace::body(&envelope.body)?}),
            )
        })?;
        Ok(())
    }

    fn publish_head(
        caller: &bft_client::Client,
        node: &Store,
        old: &bft_client::State,
        next: bft_client::State,
    ) -> Result<bft_client::State> {
        caller.store(
            node,
            bft_client::Transition {
                previous_sha256: state_hash(old)?,
                proposed: next,
            },
        )
    }
    fn flush(&mut self, node: &Store) -> Result<()> {
        let caller = bft_client::Client::lock(
            &self.config.head_file,
            &self.config.signer_dir,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let old = caller.read()?;
        if let Some(message) = old.outbox.clone() {
            #[cfg(test)]
            let started = super::service::monotonic()?;
            self.retain_local(node, net::Body::Signed(Box::new(message)))?;
            #[cfg(test)]
            super::service::trace_subwork("sign-envelope-retention", started)?;
            let mut next = old.clone();
            next.outbox = None;
            #[cfg(test)]
            let started = super::service::monotonic()?;
            Self::publish_head(&caller, node, &old, next)?;
            #[cfg(test)]
            super::service::trace_subwork("sign-outbox-clear", started)?;
        }
        Ok(())
    }
    fn sign(&mut self, node: &Store, request: consensus::Request) -> Result<()> {
        let caller = bft_client::Client::lock(
            &self.config.head_file,
            &self.config.signer_dir,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let old = caller.read()?;
        require(
            old.pending.is_none() && old.outbox.is_none(),
            "BFT pending/outbox requires recover-only",
        )?;
        let mut pending = old.clone();
        pending.pending = Some(request.clone());
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let (pending, mut agent) = if self.config.format == bft_client::ORIGIN_FORMAT {
            (Self::publish_head(&caller, node, &old, pending)?, None)
        } else {
            let (pending, agent) = caller.store_pending_for_sign(
                node,
                bft_client::Transition {
                    previous_sha256: state_hash(&old)?,
                    proposed: pending,
                },
            )?;
            (pending, Some(agent))
        };
        #[cfg(test)]
        super::service::trace_subwork("sign-pending-publication", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let signed = if self.config.format == bft_client::ORIGIN_FORMAT {
            crate::bft_network::sign_local_envelope(
                &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
                node,
                &self.config.signer_dir,
                node.storage_head()?,
                old.head,
                &self.config.key,
                &self.config.key_file,
            )?
            .signed
        } else {
            agent
                .as_mut()
                .ok_or("ordinary pending signer absent")?
                .sign(node, request, Some(&self.config.key_file), old.head)?
        };
        // Response publication independently inspects the exact original signed
        // result after this original signer lease is released, as before.
        drop(agent);
        #[cfg(test)]
        super::service::trace_subwork("sign-native-response", started)?;
        let mut response = pending.clone();
        response.pending = None;
        response.head = signed.head;
        response.outbox = Some(signed.message);
        #[cfg(test)]
        let started = super::service::monotonic()?;
        Self::publish_head(&caller, node, &pending, response)?;
        #[cfg(test)]
        super::service::trace_subwork("sign-response-publication", started)?;
        drop(caller);
        self.flush(node)?;
        self.entered = super::service::monotonic()?;
        Ok(())
    }

    pub(crate) fn receive(&mut self, node: &mut Store, raw: &[u8]) -> Result<()> {
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let (_received_frame, payload) = crate::contact_frame::inspect_bytes(
            raw,
            None,
            None,
            crate::contact::MAX_PAYLOAD,
            crate::contact::MAX_FRAME,
        )?;
        let wire: net::WireEnvelope = crate::bft_client::decode(&payload)?;
        let envelope = wire.clone().expand()?;
        #[cfg(test)]
        super::service::trace_subwork("receive-decode", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        envelope.verify(node)?;
        #[cfg(test)]
        super::service::trace_subwork("receive-initial-verification", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        // Certified dependencies synchronize before deduplicating an already retained body.
        if wire.format == net::ORIGIN_FORMAT {
            net::sync_origin_envelope(node, wire.clone())?;
        } else {
            net::sync(node, envelope.evidence.clone())?;
        }
        #[cfg(test)]
        super::service::trace_subwork("receive-dependency-sync", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let result = self.retain(node, wire, false);
        #[cfg(test)]
        super::service::trace_subwork("receive-retention", started)?;
        #[cfg(test)]
        if result.is_ok() {
            super::service::trace_payment_event(|| {
                Ok(
                    json!({"phase":"payment-envelope-received","frame_id":_received_frame.message_id,
                    "body_id":hash(&serde_json::to_value(&envelope.body).map_err(|e|e.to_string())?)?,
                    "body":payment_trace::body(&envelope.body)?}),
                )
            })?;
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn fixture_control_frame(&self, message: &consensus::Message) -> Result<Vec<u8>> {
        let body = serde_json::to_value(net::Body::Signed(Box::new(message.clone())))
            .map_err(|e| e.to_string())?;
        self.carriage_frame(hash(&body)?)?.retained_bytes()
    }

    #[cfg(test)]
    pub(crate) fn probe_fixture_receive(&mut self, node: &mut Store, raw: &[u8]) -> Result<Value> {
        super::service::start_work_trace();
        crate::verification_keys::cost::take();
        retention::cost::take_phases();
        retention::cost::take();
        let started = super::service::monotonic()?;
        let result = self.receive(node, raw);
        let seconds = super::service::monotonic()? - started;
        let signatures = crate::verification_keys::cost::take();
        let archive_phases = retention::cost::take_phases();
        let (archive_checks, envelope_checks) = retention::cost::take();
        Ok(
            json!({"seconds":seconds,"trace":super::service::take_work_trace(),
            "archive_phase_ns":archive_phases,
            "complete_archive_byte_checks":archive_checks,
            "complete_envelope_byte_checks":envelope_checks,
            "archive_phase_order":["parse-binding","retained-read","proposed-byte-checks",
                "new-envelope-native-authentication","durable-publication"],
            "error":result.err(),"strict_signature_checks":signatures.strict_attempts,
            "native_history_reused":signatures.native_history_reused,
            "retained_messages":self.archive.runtime.messages.len(),
            "fixture_only":true,"signing_authority":false}),
        )
    }

    fn submissions(&mut self, node: &Store) -> Result<()> {
        let root = node.directory().join("bft-submissions");
        if !root.exists() {
            return Ok(());
        }
        files::private_path(&root, true)?;
        let mut paths = fs::read_dir(&root)
            .map_err(|e| e.to_string())?
            .map(|v| v.map(|e| e.path()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>>>()?;
        require(paths.len() <= 32, "BFT submission queue capacity")?;
        paths.sort();
        for path in paths {
            let raw = files::private_read_with_limit(&path, crate::contact::MAX_PAYLOAD)?;
            // Queue files use the native typed serializer; full typed checking precedes canonical packing.
            let wire: net::WireEnvelope = crate::bft_client::decode(&raw)?;
            let envelope = wire.clone().expand()?;
            let ident = envelope.verify(node)?;
            require(
                matches!(envelope.body, net::Body::Submission(_)),
                "owner queue requires a typed submission",
            )?;
            require(
                path.file_name().and_then(|n| n.to_str())
                    == Some(&format!("{}.json", ident.to_hex())),
                "BFT submission filename binding",
            )?;
            // A native-checked owner submission from this local durable queue
            // must be carried to other validators even when this node is not
            // the current proposer. This flag grants carriage only, no debit.
            self.retain(node, wire, true)?;
        }
        Ok(())
    }
    fn candidate(
        &self,
        node: &Store,
        context: &consensus::Context,
        high: Option<Hash>,
    ) -> Result<Snapshot> {
        // Received proof custody does not import value. Propose its exact
        // retained Native record through the same certified execution path as
        // owner submissions; permanent import tombstones prevent retries.
        let mut commands = node
            .journal
            .contact_records
            .values()
            .filter(|r| !node.chain.ledger.imports.contains_key(&r.export))
            .map(|r| Command::Import {
                snapshot: r.snapshot,
                export: r.export,
            })
            .collect::<Vec<_>>();
        if node.trust.region(node.chain.region)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES {
            commands.extend(node.complete_origin_pending_imports()?);
        }
        for record in self.archive.runtime.messages.values() {
            let wire: net::WireEnvelope = serde_json::from_value(self.archive.envelope(record)?)
                .map_err(|e| e.to_string())?;
            let envelope = wire.expand()?;
            envelope.verify(node)?;
            match envelope.body {
                net::Body::Signed(message) => {
                    if let consensus::Message::Proposal(p) = *message {
                        if high == Some(p.snapshot.statement.id()?) && p.context()? == *context {
                            return Ok(*p.snapshot);
                        }
                    }
                }
                net::Body::Submission(proposed) => commands.extend(proposed),
                _ => {}
            }
        }
        require(
            high.is_none(),
            "highest prepared proposal requires its retained complete envelope",
        )?;
        let mut selected = Vec::new();
        let mut seen = BTreeSet::new();
        for command in commands {
            if selected.len() == 4 {
                break;
            }
            let id = hash(&serde_json::to_value(&command).map_err(|e| e.to_string())?)?;
            if seen.insert(id) {
                let mut proposed = selected.clone();
                proposed.push(command);
                let candidate = node.bft_candidate(proposed.clone(), self.config.miner.clone());
                #[cfg(test)]
                super::service::trace_payment_event(|| {
                    Ok(
                        json!({"phase":"payment-command-selection","context":context,
                        "intents":payment_trace::intents(&proposed)?,"accepted":candidate.is_ok(),
                        "error":candidate.as_ref().err()}),
                    )
                })?;
                if candidate.is_ok() {
                    selected = proposed;
                }
            }
        }
        node.bft_candidate(selected, self.config.miner.clone())
    }

    fn prepare_owned_proposal(
        &mut self,
        node: &mut Store,
        context: &consensus::Context,
        round: u64,
        snapshot: &Snapshot,
        timeout: &Option<consensus::TimeoutCertificate>,
    ) -> Result<()> {
        require(
            consensus::Context::current(node)? == *context,
            "post-Propose Native context changed",
        )?;
        let caller = bft_client::Client::lock(
            &self.config.head_file,
            &self.config.signer_dir,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let head = caller.read()?.head;
        drop(caller);
        let pins = proposal::Pins {
            signer: &self.config.signer_dir,
            archive: &self.config.state,
            key: self.config.key.clone(),
            runtime_format: self.config.format.clone(),
            head,
            archive_head: self.head.ok_or("post-Propose archive head missing")?,
            context: context.clone(),
            round,
        };
        let observed = phase::observe(
            node,
            pins,
            phase::Mode::Start,
            phase::Input {
                context: context.clone(),
                order: self.archive.runtime.messages.keys().copied().collect(),
            },
        )?;
        if let phase::Action::Prepare { proposal, .. } = observed.action {
            require(
                proposal.leader.key == self.config.key
                    && proposal.round == round
                    && proposal.snapshot.as_ref() == snapshot
                    && proposal.timeout == *timeout,
                "post-Propose Prepare differs from exact retained own proposal",
            )?;
            self.sign(node, consensus::Request::Prepare(proposal.clone()))?;
            self.commit_prepared_proposal(node, &proposal)?;
        }
        Ok(())
    }

    fn commit_prepared_proposal(
        &mut self,
        node: &mut Store,
        original: &consensus::Proposal,
    ) -> Result<()> {
        let context = original.context()?;
        require(
            consensus::Context::current(node)? == context,
            "post-Prepare Native context changed",
        )?;
        let value = original.snapshot.statement.id()?;
        let mut possible = BTreeSet::new();
        for record in self.archive.runtime.messages.values() {
            let body: net::Body =
                serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())?;
            if let net::Body::Signed(message) = body {
                if let consensus::Message::Vote(vote) = *message {
                    if vote.phase == consensus::Phase::Prepare
                        && vote.context == context
                        && vote.round == original.round
                        && vote.value == value
                    {
                        possible.insert(vote.approval.key);
                    }
                }
            }
        }
        // This count can only decline work; it grants no authentication or
        // signing rights. A possible quorum always takes full Native policy.
        if possible.len() < 3 {
            return Ok(());
        }
        let caller = bft_client::Client::lock(
            &self.config.head_file,
            &self.config.signer_dir,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let head = caller.read()?.head;
        drop(caller);
        let pins = proposal::Pins {
            signer: &self.config.signer_dir,
            archive: &self.config.state,
            key: self.config.key.clone(),
            runtime_format: self.config.format.clone(),
            head,
            archive_head: self.head.ok_or("post-Prepare archive head missing")?,
            context: context.clone(),
            round: original.round,
        };
        let observed = phase::observe(
            node,
            pins,
            phase::Mode::Commit,
            phase::Input {
                context,
                order: self.archive.runtime.messages.keys().copied().collect(),
            },
        )?;
        if let phase::Action::Commit {
            proposal, prepared, ..
        } = observed.action
        {
            require(
                proposal.as_ref() == original,
                "post-Prepare Commit differs from exact original proposal",
            )?;
            self.sign(
                node,
                consensus::Request::Commit {
                    proposal: proposal.clone(),
                    prepared,
                },
            )?;
            self.finalize_committed_proposal(node, &proposal)?;
        }
        Ok(())
    }

    fn finalize_committed_proposal(
        &mut self,
        node: &mut Store,
        original: &consensus::Proposal,
    ) -> Result<()> {
        let context = original.context()?;
        require(
            consensus::Context::current(node)? == context,
            "post-Commit Native context changed",
        )?;
        let value = original.snapshot.statement.id()?;
        let mut possible = BTreeSet::new();
        for record in self.archive.runtime.messages.values() {
            let body: net::Body =
                serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())?;
            if let net::Body::Signed(message) = body {
                if let consensus::Message::Vote(vote) = *message {
                    if vote.phase == consensus::Phase::Commit
                        && vote.context == context
                        && vote.round == original.round
                        && vote.value == value
                    {
                        possible.insert(vote.approval.key);
                    }
                }
            }
        }
        // This count only declines work. Complete certificate authentication and
        // value execution still belong to the original Native policy/Store.
        if possible.len() < 3 {
            return Ok(());
        }
        let caller = bft_client::Client::lock(
            &self.config.head_file,
            &self.config.signer_dir,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let head = caller.read()?.head;
        drop(caller);
        let pins = proposal::Pins {
            signer: &self.config.signer_dir,
            archive: &self.config.state,
            key: self.config.key.clone(),
            runtime_format: self.config.format.clone(),
            head,
            archive_head: self.head.ok_or("post-Commit archive head missing")?,
            context: context.clone(),
            round: original.round,
        };
        let observed = phase::observe(
            node,
            pins,
            phase::Mode::Committed,
            phase::Input {
                context,
                order: self.archive.runtime.messages.keys().copied().collect(),
            },
        )?;
        if let phase::Action::Finalize { snapshot } = observed.action {
            let mut unsigned = *snapshot.clone();
            unsigned.bft = None;
            require(
                &unsigned == original.snapshot.as_ref(),
                "post-Commit finality differs from exact original proposal",
            )?;
            node.finalize(*snapshot.clone())?;
            self.observe_installed_parent(node)?;
            self.retain_local(node, net::Body::Finalized(snapshot))?;
        }
        Ok(())
    }

    fn observe_installed_parent(&mut self, node: &Store) -> Result<()> {
        let context = consensus::Context::current(node)?;
        if self.slot.as_ref().map(|slot| &slot.0) != Some(&context) {
            // A successfully installed Native successor begins its local
            // round-zero clock now, even if no subsequent tick runs promptly.
            // This observation grants no signature or finality authority.
            self.slot = Some((context, 0));
            self.entered = super::service::monotonic()?;
        }
        Ok(())
    }

    pub(crate) fn tick(&mut self, node: &mut Store) -> Result<()> {
        #[cfg(test)]
        let started = super::service::monotonic()?;
        self.flush(node)?;
        self.submissions(node)?;
        #[cfg(test)]
        super::service::trace_subwork("consensus-flush-submissions", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let context = consensus::Context::current(node)?;
        let (agent, status) = consensus::Agent::inspect_with_status(&self.config.signer_dir, node)?;
        drop(agent);
        #[cfg(test)]
        super::service::trace_subwork("consensus-signer-inspection", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let round = if status.state.context.as_ref() == Some(&context) {
            status.state.round
        } else {
            0
        };
        if self.slot.as_ref() != Some(&(context.clone(), round)) {
            self.slot = Some((context.clone(), round));
            self.entered = super::service::monotonic()?;
        }
        let caller = bft_client::Client::lock(
            &self.config.head_file,
            &self.config.signer_dir,
            self.config.key.clone(),
            self.config.format.clone(),
            node,
        )?;
        let head = caller.read()?.head;
        drop(caller);
        #[cfg(test)]
        super::service::trace_subwork("consensus-caller-inspection", started)?;
        let pins = proposal::Pins {
            signer: &self.config.signer_dir,
            archive: &self.config.state,
            key: self.config.key.clone(),
            runtime_format: self.config.format.clone(),
            head,
            archive_head: self.head.ok_or("missing BFT archive head")?,
            context: context.clone(),
            round,
        };
        let stopped =
            node.chain.height() >= self.config.stop_height || !self.config.key_file.exists();
        let input = tick::Input {
            context: context.clone(),
            order: self.archive.runtime.messages.keys().copied().collect(),
            stage: tick::Stage::Begin,
            proposed: None,
            entered_at: self.entered,
            interval: self.config.block_interval,
            timeout: self.config.round_timeout,
            stopped,
            initial_wait: false,
            timeout_refresh: true,
        };
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let decision = tick::observe(node, pins, input)?.action;
        #[cfg(test)]
        super::service::trace_subwork("consensus-complete-observe", started)?;
        #[cfg(test)]
        {
            self.last_decision = Some(match &decision {
                tick::Decision::Phase(phase::Action::Idle) => "idle",
                tick::Decision::Phase(phase::Action::Prepare { .. }) => "prepare",
                tick::Decision::Phase(phase::Action::Commit { .. }) => "commit",
                tick::Decision::Phase(phase::Action::Finalize { .. }) => "finalize",
                tick::Decision::Propose { .. } => "propose",
                tick::Decision::Timeout { .. } => "timeout",
                tick::Decision::RefreshTimeout => "refresh-timeout",
                tick::Decision::WaitInitial { .. } => "initial-wait",
            });
        }
        #[cfg(test)]
        let started = super::service::monotonic()?;
        match decision {
            tick::Decision::Phase(phase::Action::Finalize { snapshot }) => {
                node.finalize(*snapshot.clone())?;
                self.observe_installed_parent(node)?;
                self.retain_local(node, net::Body::Finalized(snapshot))?;
            }
            tick::Decision::Phase(phase::Action::Prepare { proposal, .. }) => {
                self.sign(node, consensus::Request::Prepare(proposal.clone()))?;
                self.commit_prepared_proposal(node, &proposal)?;
            }
            tick::Decision::Phase(phase::Action::Commit {
                proposal, prepared, ..
            }) => {
                self.sign(
                    node,
                    consensus::Request::Commit {
                        proposal: proposal.clone(),
                        prepared,
                    },
                )?;
                self.finalize_committed_proposal(node, &proposal)?;
            }
            tick::Decision::Propose {
                round,
                timeout,
                high,
            } => {
                #[cfg(test)]
                let started = super::service::monotonic()?;
                #[cfg(test)]
                super::service::trace_payment_event(|| {
                    Ok(json!({"phase":"payment-candidate-start","context":context,
                        "round":round,"high":high,"leader":self.config.key}))
                })?;
                let snapshot = self.candidate(node, &context, high)?;
                #[cfg(test)]
                super::service::trace_subwork("consensus-proposal-construction", started)?;
                #[cfg(test)]
                super::service::trace_payment_event(|| {
                    Ok(json!({"phase":"payment-candidate-ready","context":context,
                        "round":round,"high":high,"leader":self.config.key,
                        "snapshot":payment_trace::snapshot(&snapshot)?}))
                })?;
                self.sign(
                    node,
                    consensus::Request::Propose {
                        round,
                        timeout: timeout.clone(),
                        snapshot: Box::new(snapshot.clone()),
                    },
                )?;
                self.prepare_owned_proposal(node, &context, round, &snapshot, &timeout)?;
            }
            tick::Decision::Timeout { context, round } => {
                self.sign(node, consensus::Request::Timeout { context, round })?
            }
            _ => {}
        }
        #[cfg(test)]
        super::service::trace_subwork("consensus-action", started)?;
        self.archive.runtime.height = node.chain.height();
        self.archive.runtime.tip = node.chain.tip()?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let result = self.persist(node);
        #[cfg(test)]
        super::service::trace_subwork("consensus-durable-archive", started)?;
        result
    }

    #[cfg(test)]
    pub(crate) fn sign_fixture_control(
        &mut self,
        node: &Store,
        request: consensus::Request,
    ) -> Result<consensus::Message> {
        let previous = self
            .archive
            .runtime
            .messages
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        self.sign(node, request)?;
        let mut added = self
            .archive
            .runtime
            .messages
            .iter()
            .filter(|(id, _)| !previous.contains(id));
        let (_, record) = added
            .next()
            .ok_or("fixture requires a fresh original response")?;
        require(added.next().is_none(), "fixture response is ambiguous")?;
        match serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())? {
            net::Body::Signed(message) => Ok(*message),
            _ => Err("fixture original response is not a signed control".into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_fixture_sign_control(
        &mut self,
        node: &Store,
        request: consensus::Request,
    ) -> Result<(consensus::Message, Value)> {
        super::service::start_work_trace();
        consensus::sign_cost::take();
        crate::verification_keys::cost::take();
        consensus::custody_cost::take();
        let started = super::service::monotonic()?;
        let result = self.sign_fixture_control(node, request);
        let seconds = super::service::monotonic()? - started;
        let native = consensus::sign_cost::take();
        let signatures = crate::verification_keys::cost::take();
        let complete_opens = consensus::custody_cost::take();
        let report = json!({"seconds":seconds,"trace":super::service::take_work_trace(),
            "complete_signer_opens":complete_opens,
            "error":result.as_ref().err(),"native_sign_phases_ns":native.phases_ns,
            "native_replay_ns":native.replay_ns,"native_replayed_records":native.completed_old_records,
            "native_records":native.native_records,"new_signatures":native.completed_new_signatures,
            "strict_signature_checks":signatures.strict_attempts,
            "native_history_reused":signatures.native_history_reused,
            "fixture_only":true,"independent_operations":false});
        Ok((result?, report))
    }

    #[cfg(test)]
    pub(crate) fn fixture_controls(&self) -> Result<Vec<consensus::Message>> {
        self.archive
            .runtime
            .messages
            .values()
            .map(|record| {
                match serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())? {
                    net::Body::Signed(message) => Ok(*message),
                    _ => Err("fixture archive contains a non-control body".into()),
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn retain_fixture_controls(
        &mut self,
        node: &Store,
        messages: &[consensus::Message],
    ) -> Result<()> {
        for message in messages {
            let wire =
                net::local_envelope(net::Body::Signed(Box::new(message.clone())), node)?.envelope;
            self.retain(node, wire, false)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn probe_tick(&mut self, node: &mut Store) -> Result<Value> {
        super::service::start_work_trace();
        retention::cost::take();
        let started = super::service::monotonic()?;
        let result = self.tick(node);
        let completed_at = super::service::monotonic()?;
        let seconds = completed_at - started;
        let (archive_checks, envelope_checks) = retention::cost::take();
        Ok(
            json!({"seconds":seconds,"trace":super::service::take_work_trace(),
            "error":result.err(),"decision":self.last_decision,
            "retained_messages":self.archive.runtime.messages.len(),
            "complete_archive_byte_checks":archive_checks,
            "complete_envelope_byte_checks":envelope_checks,
            "started_at":started,"completed_at":completed_at,
            "clock_context":self.slot.as_ref().map(|slot|&slot.0),
            "clock_round":self.slot.as_ref().map(|slot|slot.1),"clock_entered_at":self.entered,
            "fixture_only":true,"signing_authority":false}),
        )
    }

    fn carriage_frame(&self, id: Hash) -> Result<Frame> {
        let record = &self.archive.runtime.messages[&id];
        let envelope: net::WireEnvelope =
            serde_json::from_value(self.archive.envelope(record)?).map_err(|e| e.to_string())?;
        let raw = files::canonical_with_limit(&envelope, crate::contact::MAX_PAYLOAD)?;
        let payload = Hash(Sha256::digest(&raw).into());
        let mut frame = Frame {
            format: crate::contact::FRAME_FORMAT.into(),
            kind: "regional-bft".into(),
            source_chain_id: envelope.region,
            destination_chain_id: envelope.region,
            export_id: payload,
            payload_sha256: payload,
            payload_b64: STANDARD.encode(raw),
            message_id: Hash::ZERO,
        };
        frame.message_id = frame.message()?;
        Ok(frame)
    }

    pub(crate) fn broadcast(&mut self, transport: &Value) -> Result<()> {
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let mut mesh = Node::open(transport)?;
        #[cfg(test)]
        super::service::trace_work("native-broadcast-mesh-open", started)?;
        self.broadcast_node(&mut mesh)
    }

    pub(crate) fn broadcast_node(&mut self, mesh: &mut Node) -> Result<()> {
        #[cfg(test)]
        let started = super::service::monotonic()?;
        // The mesh relays each original packet to its pinned destination.
        // Re-originating every received envelope for all validators creates a
        // quadratic backlog that can starve current votes. Incoming evidence
        // stays retained in full; originate locally authored envelopes only.
        let mut records: Vec<_> = self
            .archive
            .runtime
            .messages
            .iter()
            .filter(|(_, record)| record.local)
            .map(|(id, _)| *id)
            .collect();
        if records.is_empty() {
            return Ok(());
        }
        let start = (self.archive.runtime.cursor as usize) % records.len();
        records.rotate_left(start);
        let mut current = Vec::new();
        let mut originated = None;
        for id in &records {
            let body: net::Body =
                serde_json::from_value(self.archive.runtime.messages[id].body.clone())
                    .map_err(|e| e.to_string())?;
            let priority = match body {
                net::Body::Signed(message) => match *message {
                    consensus::Message::Proposal(p)
                        if p.context()?.parent_height == self.archive.runtime.height =>
                    {
                        Some((p.round, 0))
                    }
                    consensus::Message::Vote(v)
                        if v.context.parent_height == self.archive.runtime.height =>
                    {
                        Some((
                            v.round,
                            if v.phase == consensus::Phase::Commit {
                                1
                            } else {
                                2
                            },
                        ))
                    }
                    consensus::Message::Timeout(v)
                        if v.context.parent_height == self.archive.runtime.height =>
                    {
                        Some((v.round, 3))
                    }
                    _ => None,
                },
                _ => None,
            };
            if let Some((round, priority)) = priority {
                current.push((std::cmp::Reverse(round), priority, *id));
            }
        }
        // Newer fully authenticated controls must not compete behind an older
        // proposal merely because both share a parent height. Preserve phase
        // priority inside each round and the independent historical spare.
        current.sort_by_key(|v| (v.0, v.1));
        let mut selected = current
            .into_iter()
            .take(3)
            .map(|(_, _, id)| id)
            .collect::<Vec<_>>();
        let current_count = selected.len();
        // Preserve three current consensus slots. Give one new, Native-checked
        // local owner request its first origination before historical retries.
        // Durable exact mesh packets, including cold authenticated archives,
        // decide only whether first origination occurred for every destination.
        for id in &records {
            let body: net::Body =
                serde_json::from_value(self.archive.runtime.messages[id].body.clone())
                    .map_err(|e| e.to_string())?;
            if !matches!(body, net::Body::Submission(_)) {
                continue;
            }
            if originated.is_none() {
                originated = Some(mesh.originated_frames()?);
            }
            let frame = self.carriage_frame(*id)?;
            let mut pending = false;
            for validator in &self.config.validators {
                if validator.node_id != mesh.id
                    && !originated
                        .as_ref()
                        .ok_or("first-origination observation missing")?
                        .contains(&(frame.message_id, validator.node_id.clone()))
                {
                    pending = true;
                    break;
                }
            }
            if pending {
                selected.push(*id);
                break;
            }
        }
        for id in records {
            if selected.len() == 4 {
                break;
            }
            if !selected.contains(&id) {
                selected.push(id);
            }
        }
        let mut priority = Vec::new();
        let destinations = self
            .config
            .validators
            .iter()
            .filter(|v| v.node_id != mesh.id)
            .map(|v| v.node_id.clone())
            .collect::<Vec<_>>();
        #[cfg(test)]
        super::service::trace_work("native-broadcast-select", started)?;
        let mut frames = Vec::new();
        for id in &selected {
            #[cfg(test)]
            let started = super::service::monotonic()?;
            let frame = self.carriage_frame(*id)?;
            let raw = frame.retained_bytes()?;
            #[cfg(test)]
            super::service::trace_work("native-broadcast-frame-pack", started)?;
            #[cfg(test)]
            super::service::trace_payment_event(|| {
                Ok(
                    json!({"phase":"payment-frame-prepared","body_id":id,"frame_id":frame.message_id}),
                )
            })?;
            frames.push(raw);
        }
        if !destinations.is_empty() && !frames.is_empty() {
            #[cfg(test)]
            let started = super::service::monotonic()?;
            let raws = frames.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let packets = mesh.enqueue_frame_batch(&raws, &destinations)?;
            #[cfg(test)]
            super::service::trace_work("native-broadcast-enqueue", started)?;
            for batch in packets.into_iter().take(current_count) {
                priority.extend(batch);
            }
        }
        // Current Native-checked controls retain first-carriage eligibility
        // across the following ordinary contact turn. Historical packets stay
        // retained and use the independent rotating send slots.
        #[cfg(test)]
        let started = super::service::monotonic()?;
        mesh.prioritize_originated_packets(&priority)?;
        #[cfg(test)]
        super::service::trace_work("native-broadcast-priority", started)?;
        #[cfg(test)]
        {
            self.last_broadcast = selected;
        }
        self.archive.runtime.cursor = self
            .archive
            .runtime
            .cursor
            // Advance independently of the four-item page stride, so a
            // rotating spare slot cannot alias a subset of retained bodies.
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("BFT carriage cursor exhausted")?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn current_controls(&self) -> Result<Value> {
        let mut controls = Vec::new();
        for (id, record) in &self.archive.runtime.messages {
            let body: net::Body =
                serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())?;
            let (kind, height, round) = match body {
                net::Body::Signed(message) => match *message {
                    consensus::Message::Proposal(p) => {
                        ("proposal", p.context()?.parent_height, p.round)
                    }
                    consensus::Message::Vote(v) => (
                        if v.phase == consensus::Phase::Prepare {
                            "prepare"
                        } else {
                            "commit"
                        },
                        v.context.parent_height,
                        v.round,
                    ),
                    consensus::Message::Timeout(v) => ("timeout", v.context.parent_height, v.round),
                    _ => continue,
                },
                _ => continue,
            };
            if height == self.archive.runtime.height {
                controls.push(
                    json!({"body_id":id,"frame_id":self.carriage_frame(*id)?.message_id,
                    "kind":kind,"round":round,"value":record.value,"local":record.local}),
                );
            }
        }
        Ok(
            json!({"height":self.archive.runtime.height,"round":self.slot.as_ref().map(|s|s.1),"controls":controls}),
        )
    }

    #[cfg(test)]
    pub(super) fn scheduling_observation(&self) -> Result<Value> {
        let mut counts = BTreeMap::<String, usize>::new();
        let mut selected = Vec::new();
        for (id, record) in &self.archive.runtime.messages {
            let body: net::Body =
                serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())?;
            let (kind, context_height, round) = match body {
                net::Body::Signed(message) => match *message {
                    consensus::Message::Proposal(p) => {
                        ("proposal", Some(p.context()?.parent_height), Some(p.round))
                    }
                    consensus::Message::Vote(v) => (
                        if v.phase == consensus::Phase::Prepare {
                            "prepare"
                        } else {
                            "commit"
                        },
                        Some(v.context.parent_height),
                        Some(v.round),
                    ),
                    consensus::Message::Timeout(v) => {
                        ("timeout", Some(v.context.parent_height), Some(v.round))
                    }
                    _ => ("other", None, None),
                },
                net::Body::Submission(_) => ("submission", None, None),
                _ => ("other", None, None),
            };
            if kind == "submission" || context_height == Some(self.archive.runtime.height) {
                let class = if self.slot.as_ref().map(|slot| slot.1) == round {
                    "current"
                } else {
                    "other-round"
                };
                *counts
                    .entry(format!(
                        "{kind}:{class}:{}",
                        if record.local { "local" } else { "received" }
                    ))
                    .or_default() += 1;
            }
            if self.last_broadcast.contains(id) {
                selected.push(
                    json!({"body_id":id,"frame_id":self.carriage_frame(*id)?.message_id,
                    "kind":kind,"parent_height":context_height,"round":round}),
                );
            }
        }
        Ok(
            json!({"height":self.archive.runtime.height,"round":self.slot.as_ref().map(|slot|slot.1),
            "decision":self.last_decision,"entered":self.entered,"counts":counts,"selected":selected,
            "signing_authority":false,"fixture_only":true}),
        )
    }
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod import_tests;

#[cfg(test)]
#[path = "payment_trace.rs"]
mod payment_trace;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{public, signature};
    #[test]
    fn four_rust_actors_finalize_with_native_locks_and_separate_caller_heads() {
        let root = directory(
            &fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("rld-rust-bft-{}", random().unwrap())),
        )
        .unwrap();
        let result = (|| -> Result<()> {
            let mut genesis = crate::tests::bootstrap();
            for admission in &mut genesis.admissions {
                admission.rules = consensus::RULES.into();
                admission.signature = signature(1, &admission.bytes()?);
            }
            let currency = genesis.currency.id()?;
            let region = genesis.admissions[0].id()?;
            let mut seeds = (2u8..6).collect::<Vec<_>>();
            seeds.sort_by_key(|s| public(*s));
            let mut nodes = Vec::new();
            let mut transports = Vec::new();
            let mut ids = Vec::new();
            for n in 0..4 {
                nodes.push(Store::create(
                    &root.join(format!("ledger-{n}")),
                    genesis.clone(),
                    region,
                    &public(1),
                    currency,
                )?);
                let identity = initialize(
                    &root.join(format!("transport-{n}")),
                    &currency.to_hex(),
                    &region.to_hex(),
                    "public-no-value-bft-test",
                )?;
                ids.push(
                    identity["node_id"]
                        .as_str()
                        .ok_or("fixture identity")?
                        .to_owned(),
                );
            }
            for n in 0..4 {
                transports.push(json!({"format":MESH,"network":currency,"state":root.join(format!("transport-{n}")),
                    "contacts":(0..4).filter(|p|*p!=n).map(|p|json!({"peer":ids[p],"inbox":root.join(format!("spool-{p}-{n}")),"outbox":root.join(format!("spool-{n}-{p}"))})).collect::<Vec<_>>()}));
            }
            let mut actors = Vec::new();
            for n in 0..4 {
                let signer = root.join(format!("signer-{n}"));
                let agent = consensus::Agent::create(&signer, &nodes[n], public(seeds[n]))?;
                let head = agent.head()?;
                let binding = agent.journal.binding.clone();
                drop(agent);
                let caller = directory(&root.join(format!("caller-{n}")))?.join("head.json");
                let state = bft_client::State {
                    format: bft_client::FORMAT.into(),
                    binding,
                    head,
                    pending: None,
                    outbox: None,
                };
                crate::keystore::private_create(&caller, &files::canonical(&state)?)?;
                let key = root.join(format!("key-{n}.json"));
                crate::keystore::private_create(
                    &key,
                    &serde_json::to_vec(&json!({"secret_key":hex::encode([seeds[n];32])}))
                        .map_err(|e| e.to_string())?,
                )?;
                let archive = directory(&root.join(format!("runtime-{n}")))?;
                let config = json!({"format":bft_client::FORMAT,"state":archive,"signer_dir":signer,"head_file":caller,
                    "key_file":key,"key":public(seeds[n]),"miner":public(10),"validators":seeds.iter().enumerate().map(|(p,s)|json!({"key":public(*s),"node_id":ids[p]})).collect::<Vec<_>>(),
                    "block_interval":0.5,"round_timeout":5.0,"stop_height":2});
                let path = root.join(format!("config-{n}.json"));
                atomic(&path, &config, 64 * 1024)?;
                actors.push(Runtime::open(&path, &nodes[n], &transports[n])?);
            }
            let started = super::super::service::monotonic()?;
            let deadline = started + 30.0;
            let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let threads = actors
                .into_iter()
                .zip(nodes)
                .zip(transports.clone())
                .map(|((mut actor, mut node), config)| {
                    let completed = completed.clone();
                    let failed = failed.clone();
                    std::thread::spawn(
                        move || -> Result<(Runtime, Store, Option<String>, Vec<String>)> {
                            let mut cursor = None;
                            let mut seen = Vec::new();
                            let result = (|| {
                                let mut marked = false;
                                for _ in 0..48 {
                                    require(
                                        !failed.load(std::sync::atomic::Ordering::Acquire),
                                        "another Rust actor refused; retain this fixture",
                                    )?;
                                    require(
                                        super::super::service::monotonic()? < deadline,
                                        "finite Rust BFT actor budget exhausted",
                                    )?;
                                    actor.tick(&mut node)?;
                                    actor.broadcast(&config)?;
                                    let contacts = Node::open(&config)?.contacts.clone();
                                    for (peer, contact) in contacts {
                                        super::super::service::spool(&config, &peer, &contact)?;
                                    }
                                    for (id, raw) in Node::open(&config)?.frame_page_selected(
                                        cursor.as_deref(),
                                        4,
                                        &seen,
                                    )? {
                                        actor.receive(&mut node, &raw)?;
                                        cursor = Some(id.clone());
                                        if !seen.contains(&id) {
                                            seen.push(id);
                                        }
                                    }
                                    if node.chain.height() == 2 && !marked {
                                        completed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                                        marked = true;
                                    }
                                    if completed.load(std::sync::atomic::Ordering::Acquire) == 4 {
                                        return Ok(());
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(55));
                                }
                                Err("finite Rust BFT actor iteration budget exhausted".into())
                            })();
                            if let Err(error) = result {
                                failed.store(true, std::sync::atomic::Ordering::Release);
                                return Err(error);
                            }
                            Ok((actor, node, cursor, seen))
                        },
                    )
                })
                .collect::<Vec<_>>();
            let mut actors = Vec::new();
            let mut nodes = Vec::new();
            let mut receive_cursors = Vec::new();
            let mut receive_seen = Vec::new();
            let mut error = None;
            for thread in threads {
                match thread.join().map_err(|_| "Rust BFT actor panicked")? {
                    Ok((actor, node, cursor, seen)) => {
                        actors.push(actor);
                        nodes.push(node);
                        receive_cursors.push(cursor);
                        receive_seen.push(seen);
                    }
                    Err(failure) => {
                        if error.is_none() || !failure.starts_with("another Rust actor") {
                            error = Some(failure);
                        }
                    }
                }
            }
            if let Some(error) = error {
                return Err(error);
            }
            require(
                nodes.iter().all(|n| n.chain.height() == 2),
                "four ordinary Rust actors did not independently finalize",
            )?;
            let elapsed = super::super::service::monotonic()? - started;
            eprintln!("Native actor consensus completion seconds={elapsed:.6}");
            require(
                elapsed < 30.0,
                "Rust actor consensus completion exceeded original budget",
            )?;
            let (input, coin) = nodes[3]
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, c)| c.payment.owner == public(10) && c.mature <= 3)
                .ok_or("mature next-block fixture input")?;
            let input = *input;
            let intent = crate::Intent {
                currency,
                region: nodes[3].chain.region,
                inputs: vec![input],
                outputs: vec![crate::Payment {
                    owner: public(11),
                    amount: coin.payment.amount,
                }],
                fee: crate::Amount(0),
                destination: None,
                remote: None,
                destination_fee: crate::Amount(0),
                valid_through: 4,
            };
            let approval = crate::Approval {
                key: public(10),
                signature: signature(10, &intent.bytes()?),
            };
            let commands = vec![Command::Spend(Box::new(crate::SignedIntent {
                intent,
                approvals: vec![approval],
            }))];
            let body = serde_json::to_value(net::Body::Submission(commands.clone()))
                .map_err(|e| e.to_string())?;
            // Native consent is independently verified before the non-proposer
            // carries it. Queuing and transport cannot consume its input.
            nodes[3].bft_submit(commands)?;
            actors[3].tick(&mut nodes[3])?;
            require(
                actors[3]
                    .archive
                    .runtime
                    .messages
                    .values()
                    .any(|r| r.local && r.body == body),
                "local owner submission lost carriage",
            )?;
            // Ordinary receive scheduling keeps these primitive observations
            // across ticks; resetting them here would simulate a different cold scope.
            let mut queue_seen = receive_seen;
            let mut queue_cursor = receive_cursors;
            for _ in 0..8 {
                require(
                    super::super::service::monotonic()? < deadline,
                    "original Rust actor budget exhausted during submission carriage",
                )?;
                actors[3].broadcast(&transports[3])?;
                for n in 0..4 {
                    let contacts = Node::open(&transports[n])?.contacts.clone();
                    for (peer, contact) in contacts {
                        super::super::service::spool(&transports[n], &peer, &contact)?;
                    }
                    if n < 3 {
                        for (id, raw) in Node::open(&transports[n])?.frame_page_selected(
                            queue_cursor[n].as_deref(),
                            4,
                            &queue_seen[n],
                        )? {
                            actors[n].receive(&mut nodes[n], &raw)?;
                            queue_cursor[n] = Some(id.clone());
                            if !queue_seen[n].contains(&id) {
                                queue_seen[n].push(id);
                            }
                        }
                    }
                }
                if actors
                    .iter()
                    .all(|a| a.archive.runtime.messages.values().any(|r| r.body == body))
                {
                    break;
                }
            }
            require(
                actors
                    .iter()
                    .all(|a| a.archive.runtime.messages.values().any(|r| r.body == body)),
                "native owner submission did not reach every validator",
            )?;
            require(
                nodes
                    .iter()
                    .all(|n| n.chain.height() == 2 && n.chain.ledger.coins.contains_key(&input)),
                "submission carriage debited an input",
            )?;
            let elapsed = super::super::service::monotonic()? - started;
            eprintln!("Native actor submission completion seconds={elapsed:.6}");
            require(
                elapsed < 30.0,
                "Rust actor submission completion exceeded original budget",
            )?;
            let tip = nodes[0].chain.tip()?;
            for n in &nodes {
                require(n.chain.tip()? == tip, "native finalized replicas diverged")?;
            }
            drop(actors);
            drop(nodes);
            for (n, seed) in seeds.iter().enumerate() {
                let node = Store::open_inspection(
                    &root.join(format!("ledger-{n}")),
                    &public(1),
                    currency,
                )?;
                require(
                    node.chain.height() == 2 && node.chain.tip()? == tip,
                    "cold native actor replay differs",
                )?;
                let caller = bft_client::Client::lock(
                    &root.join(format!("caller-{n}/head.json")),
                    &root.join(format!("signer-{n}")),
                    public(*seed),
                    bft_client::FORMAT.into(),
                    &node,
                )?;
                let caller_head = caller.read()?;
                require(
                    caller_head.pending.is_none() && caller_head.outbox.is_none(),
                    "caller still has pending custody",
                )?;
                let (agent, status) = consensus::Agent::inspect_with_status(
                    &root.join(format!("signer-{n}")),
                    &node,
                )?;
                require(
                    status.head == caller_head.head,
                    "cold signer/caller head differs",
                )?;
                drop(agent);
            }
            let elapsed = super::super::service::monotonic()? - started;
            eprintln!("Native actor cold custody completion seconds={elapsed:.6}");
            require(
                elapsed < 30.0,
                "Rust actor cold custody completion exceeded original budget",
            )?;
            Ok(())
        })();
        if result.is_ok() {
            fs::remove_dir_all(&root).unwrap();
        } else {
            eprintln!(
                "Rust BFT failed fresh fixture retained at {}",
                root.display()
            );
        }
        result.unwrap();
    }
}
