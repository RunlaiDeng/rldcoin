//! Ordinary paged signer custody under the explicit fresh signed ground profile.
//! Full retained native history/requests/locks precede signing or exact retries.
//! Ordinary open refuses incomplete publication. Explicit keyless recovery binds
//! the exact pending caller request/head and fully native-replayed response.
use super::*;
use crate::retained_pages::{Purpose, Scope, Stream};
const HEADER: &str = "bft-header.json";
const RECORDS: &str = "bft-records";
const FORMAT: &str = "RLD-NATIVE-PAGED-BFT-SIGNER-V1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    journal: Journal,
}
impl Header {
    fn scope(&self, node: &Store) -> Result<Scope> {
        require(
            self.format == FORMAT
                && self.journal.records.is_empty()
                && self.journal.origin.is_none()
                && crate::paged_bft::is_profile(
                    &node.trust.region(self.journal.binding.region)?.rules,
                ),
            "paged signer explicit immutable header; no legacy conversion",
        )?;
        Scope::bind(
            &node.trust,
            self.journal.binding.region,
            Purpose::BftSigner(self.journal.binding.key.clone()),
            id("paged-bft-signer-header-v1", self)?,
        )
    }
}
fn root(dir: &Path) -> Result<()> {
    crate::storage::safe_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(dir).map_err(io)?;
        require(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "paged signer private root ownership",
        )?;
    }
    for entry in fs::read_dir(dir).map_err(io)? {
        let name = entry.map_err(io)?.file_name();
        require(
            matches!(name.to_str(), Some("LOCK" | HEADER | RECORDS)),
            "paged signer unexpected retained root entry; retain unchanged",
        )?;
    }
    Ok(())
}
fn header(dir: &Path) -> Result<Header> {
    root(dir)?;
    let raw = crate::keystore::private_read(&dir.join(HEADER), MAX_BYTES)?;
    let h: Header =
        serde_json::from_slice(&raw).map_err(|_| "invalid complete paged signer header")?;
    require(
        serde_json::to_vec(&h).map_err(|_| "paged signer header encoding")? == *raw,
        "noncanonical paged signer header",
    )?;
    Ok(h)
}
impl Agent {
    pub fn head(&self) -> Result<Hash> {
        require(
            self.healthy,
            "BFT signer requires full reopen after publication failure",
        )?;
        match &self.paged {
            Some(stream) => Ok(stream.storage_head()),
            None => self.journal.head(),
        }
    }
    pub fn record_count(&self) -> usize {
        match &self.paged {
            Some(stream) => usize::try_from(stream.record_count()).unwrap_or(usize::MAX),
            None => self.journal.records.len(),
        }
    }
    fn paged_state(&self, node: &Store) -> Result<State> {
        require(
            self.healthy,
            "paged signer unhealthy; retain publication residue",
        )?;
        let h = header(&self.dir)?;
        require(
            h.journal == self.journal,
            "paged signer in-memory immutable header differs",
        )?;
        let scope = h.scope(node)?;
        let stream = self.paged.as_ref().ok_or("paged signer stream missing")?;
        stream.require_scope(&scope)?;
        let mut replay = replay::PagedReplay::new(&h.journal, node, scope.initial()?)?;
        stream.visit(stream.storage_head(), |record| replay.push(record))?;
        replay.finish(stream.storage_head())
    }
    pub(super) fn create_paged(mut agent: Self, node: &Store) -> Result<Self> {
        let h = Header {
            format: FORMAT.into(),
            journal: agent.journal.clone(),
        };
        let scope = h.scope(node)?;
        replay::PagedReplay::new(&h.journal, node, scope.initial()?)?.finish(scope.initial()?)?;
        crate::keystore::private_create(
            &agent.dir.join(HEADER),
            &serde_json::to_vec(&h).map_err(|_| "paged signer header encoding")?,
        )?;
        agent.paged = Some(Stream::create(&agent.dir.join(RECORDS), scope)?);
        agent.paged_state(node)?;
        Ok(agent)
    }
    pub(super) fn open_paged(dir: &Path, guard: File, node: &Store) -> Result<(Self, State)> {
        let h = header(dir)?;
        let scope = h.scope(node)?;
        let observed = Stream::<Record>::observe_head(&dir.join(RECORDS), &scope)?;
        let stream = Stream::open(&dir.join(RECORDS), &scope, observed)?;
        let agent = Self {
            dir: dir.into(),
            _lock: guard,
            journal: h.journal,
            healthy: true,
            paged: Some(stream),
        };
        let state = agent.paged_state(node)?;
        Ok((agent, state))
    }
    /// Explicit keyless recovery of exactly retained original response bytes.
    /// Does not create a directory, sign, reset a lock or adopt an observed head.
    pub fn recover_response(
        dir: &Path,
        node: &Store,
        request: Request,
        expected: Hash,
    ) -> Result<Signed> {
        require(
            crate::paged_bft::is_profile(&node.trust.region(node.chain.region)?.rules),
            "paged response recovery requires explicit signed profile",
        )?;
        let guard = lock(dir)?;
        let h = header(dir)?;
        let scope = h.scope(node)?;
        let records = dir.join(RECORDS);
        if !exists(&records.join("stream.next"))? {
            let (mut agent, _) = Self::open_paged(dir, guard, node)?;
            return agent.sign_paged(node, request, None, expected);
        }
        let outside_bytes = (crate::keystore::private_read(&dir.join(HEADER), MAX_BYTES)?.len()
            + crate::keystore::private_read(&dir.join("LOCK"), 16)?.len())
            as u64;
        let (stream, signed) = Stream::<Record>::recover_one_authenticated(
            &records,
            &scope,
            expected,
            2,
            outside_bytes,
            |view| {
                let mut replay = replay::PagedReplay::new(&h.journal, node, scope.initial()?)?;
                let mut last = None;
                view.visit(|record, is_last| {
                if is_last {
                    require(record.request == request && record.previous_head == expected,
                        "retained pending response differs from exact caller request/previous head")?;
                    last = Some(record.clone());
                }
                replay.push(record)
            })?;
                replay.finish(view.head())?;
                let record = last.ok_or("retained complete final response missing")?;
                Ok(Signed {
                    message: record.message,
                    previous_head: record.previous_head,
                    head: view.head(),
                    recovered_exact_retry: true,
                })
            },
        )?;
        let agent = Self {
            dir: dir.into(),
            _lock: guard,
            journal: h.journal,
            healthy: true,
            paged: Some(stream),
        };
        // Full native recheck before any original response is released.
        agent.paged_state(node)?;
        require(
            agent.head()? == signed.head,
            "recovered original response head differs",
        )?;
        Ok(signed)
    }
    /// Full native validation first; never a digest-only recovery predicate.
    pub fn contains_request(&self, node: &Store, request: &Request) -> Result<bool> {
        if let Some(stream) = &self.paged {
            self.paged_state(node)?;
            let mut found = false;
            stream.visit(stream.storage_head(), |r| {
                found |= r.request == *request;
                Ok(())
            })?;
            Ok(found)
        } else {
            self.journal.state(node)?;
            Ok(self.journal.records.iter().any(|r| r.request == *request))
        }
    }
    pub(super) fn sign_paged(
        &mut self,
        node: &Store,
        request: Request,
        key_file: Option<&Path>,
        expected: Hash,
    ) -> Result<Signed> {
        let mut state = self.paged_state(node)?;
        let head = self.head()?;
        let stream = self.paged.as_ref().ok_or("paged signer stream missing")?;
        let count = stream.record_count();
        let mut position = 0u64;
        let mut retained = None;
        stream.visit(head, |r| {
            if r.request == request {
                retained = Some((position, r.clone()));
            }
            position += 1;
            Ok(())
        })?;
        if let Some((n, r)) = retained {
            require(
                expected == head || (n + 1 == count && expected == r.previous_head),
                "paged exact retry has stale separate caller head",
            )?;
            return Ok(Signed {
                message: r.message,
                previous_head: r.previous_head,
                head,
                recovered_exact_retry: true,
            });
        }
        require(
            expected == head,
            "paged caller-retained BFT head rejects old backup",
        )?;
        let c = request.context()?;
        require(
            c == Context::current(node)?,
            "paged BFT request differs from current native parent",
        )?;
        node.safety.check_region(c.region)?;
        let proposal = match &request {
            Request::Propose { snapshot, .. } => Some(snapshot.as_ref()),
            Request::Prepare(p) | Request::Commit { proposal: p, .. } => Some(p.snapshot.as_ref()),
            _ => None,
        };
        if let Some(s) = proposal {
            require(
                crate::paged_bft::parent_matches(s, node)?,
                "paged BFT signing parent differs from native selection",
            )?;
            node.safety.check(
                &node.chain,
                &s.blocks
                    .last()
                    .ok_or("paged proposal new block missing")?
                    .commands,
                &node.evidence,
            )?;
        }
        let mut message = state.apply(&request, &self.journal.binding.key, node)?;
        message.set_approval(crate::signer::read_and_sign(
            key_file.ok_or("new paged BFT vote requires explicit private key")?,
            &self.journal.binding.key,
            &message.bytes()?,
        )?);
        let record = Record {
            previous_head: head,
            observation: Observation::current(node)?,
            request,
            message: message.clone(),
        };
        let h = header(&self.dir)?;
        let scope = h.scope(node)?;
        let mut replay = replay::PagedReplay::new(&h.journal, node, scope.initial()?)?;
        self.paged
            .as_ref()
            .ok_or("paged signer stream missing")?
            .visit(head, |r| replay.push(r))?;
        replay.push(&record)?;
        let next = crate::retained_pages::next_head(head, count, &record)?;
        replay.finish(next)?;
        let outside_bytes = (crate::keystore::private_read(&self.dir.join(HEADER), MAX_BYTES)?
            .len()
            + crate::keystore::private_read(&self.dir.join("LOCK"), 16)?.len())
            as u64;
        if let Err(e) = self
            .paged
            .as_mut()
            .ok_or("paged signer stream missing")?
            .append_accounted(&[record], head, 2, outside_bytes)
        {
            self.healthy = false;
            return Err(e);
        }
        require(
            self.head()? == next,
            "paged signer durable response head differs",
        )?;
        Ok(Signed {
            message,
            previous_head: head,
            head: next,
            recovered_exact_retry: false,
        })
    }
}

#[cfg(test)]
impl Agent {
    pub(crate) fn interrupt_publication(&mut self, boundary: u8) {
        self.paged
            .as_mut()
            .expect("fresh paged fixture")
            .interrupt_at(boundary);
    }
}
