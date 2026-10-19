//! Explicit alternative trusted-head metadata profile. Checksums bind local
//! retained intent, never native money, approval or independent freshness.
use super::{
    control::{self, Boundary, Control},
    *,
};
use fs2::FileExt;
use std::io::{Seek, SeekFrom};
const HEADER: usize = 108;
const BODY: usize = 177;
const RECORD: usize = 4 + BODY;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    id: Id,
    at: u64,
    digest: Hash,
}
#[derive(Clone)]
struct State {
    binding: Hash,
    head: Hash,
    last: Hash,
    index: u64,
    pending: Option<Pending>,
    clock: u64,
}
fn pending(intent: &journal::Intent) -> Result<Pending> {
    let raw = serde_json::to_vec(intent).map_err(fast_retainer::io)?;
    ensure(
        raw.len() <= control::PENDING_LIMIT,
        "RESOURCE_WAIT head log intent bound",
    )?;
    control::intent(&raw)?;
    Ok(Pending {
        id: intent.id,
        at: intent.at,
        digest: hash("CONTROL-LOG-INTENT", &raw),
    })
}
fn record(state: &State, kind: u8, head: Hash, p: &Pending) -> Result<(Vec<u8>, State)> {
    let mut body = vec![kind];
    body.extend(
        state
            .index
            .checked_add(1)
            .ok_or("RESOURCE_WAIT head log index")?
            .to_be_bytes(),
    );
    body.extend(state.last);
    body.extend(head);
    body.extend(p.id.0);
    body.extend(p.at.to_be_bytes());
    body.extend(p.digest);
    body.extend(hash("CONTROL-LOG-RECORD", &body));
    let next = transition(state, &body)?;
    Ok((
        [(BODY as u32).to_be_bytes().as_slice(), &body].concat(),
        next,
    ))
}
fn transition(state: &State, raw: &[u8]) -> Result<State> {
    ensure(raw.len() == BODY, "INVALID head log record size")?;
    let kind = raw[0];
    let index = u64::from_be_bytes(raw[1..9].try_into().unwrap());
    let head: Hash = raw[41..73].try_into().unwrap();
    let p = Pending {
        id: Id(raw[73..105].try_into().unwrap()),
        at: u64::from_be_bytes(raw[105..113].try_into().unwrap()),
        digest: raw[113..145].try_into().unwrap(),
    };
    let digest: Hash = raw[145..177].try_into().unwrap();
    ensure(
        index == state.index + 1
            && raw[9..41] == state.last
            && hash("CONTROL-LOG-RECORD", &raw[..145]) == digest,
        "INVALID head log predecessor/digest",
    )?;
    ensure(
        head != [0; 32] && p.id.0 != [0; 32] && p.digest != [0; 32] && p.at >= state.clock,
        "INVALID head log request/clock",
    )?;
    let mut next = state.clone();
    match kind {
        1 => {
            ensure(
                state.pending.is_none() && head == state.head,
                "INVALID head log prepare",
            )?;
            next.pending = Some(p.clone());
        }
        2 => {
            ensure(
                state.pending.as_ref() == Some(&p),
                "INVALID head log completion",
            )?;
            next.pending = None;
            next.head = head;
        }
        _ => return Err("UNSUPPORTED head log record".into()),
    }
    next.index = index;
    next.last = digest;
    next.clock = p.at;
    Ok(next)
}
fn decode(raw: &[u8]) -> Result<State> {
    ensure(
        (HEADER..=control::LIMIT).contains(&raw.len()),
        "RESOURCE_WAIT or INVALID head log bound",
    )?;
    ensure(
        &raw[..8] == b"RLDFCLG1" && raw[8..12] == [0, 1, 0, 1],
        "UNSUPPORTED caller head log",
    )?;
    let binding = raw[12..44].try_into().unwrap();
    let head = raw[44..76].try_into().unwrap();
    let last = hash("CONTROL-LOG-HEADER", &raw[..76]);
    ensure(
        raw[76..108] == last && binding != [0; 32] && head != [0; 32],
        "INVALID head log header",
    )?;
    let mut state = State {
        binding,
        head,
        last,
        index: 0,
        pending: None,
        clock: 0,
    };
    let mut r = fast_retainer::Reader { raw, at: HEADER };
    while r.at < raw.len() {
        ensure(r.u32()? as usize == BODY, "INVALID head log frame")?;
        state = transition(&state, r.take(BODY)?)?;
    }
    Ok(state)
}
fn suffix(path: &Path, s: &str) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(s);
    PathBuf::from(p)
}
pub(super) struct HeadLog {
    path: PathBuf,
    file: File,
    lease_path: PathBuf,
    lease: File,
    prefix: Vec<u8>,
    state: State,
    poisoned: bool,
    observer: Option<Box<dyn FnMut(Boundary) -> Result<()> + Send>>,
}
impl HeadLog {
    pub(super) fn create(path: &Path, binding: Hash, head: Hash) -> Result<Self> {
        let mut raw = b"RLDFCLG1".to_vec();
        raw.extend([0, 1, 0, 1]);
        raw.extend(binding);
        raw.extend(head);
        raw.extend(hash("CONTROL-LOG-HEADER", &raw));
        decode(&raw)?;
        write_new(&suffix(path, ".lock"), &binding)?;
        write_new(path, &raw)?;
        Self::open(path, false)
    }
    fn open(path: &Path, recovery: bool) -> Result<Self> {
        fast_retainer::private(fast_retainer::parent(path)?, false)?;
        fast_retainer::private(path, true)?;
        let lease_path = suffix(path, ".lock");
        fast_retainer::private(&lease_path, true)?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lease_path)
            .map_err(fast_retainer::io)?;
        FileExt::try_lock_exclusive(&lease).map_err(|_| "RESOURCE_WAIT caller head log lease")?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(fast_retainer::io)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| "RESOURCE_WAIT caller head log writer")?;
        ensure(
            file.metadata().map_err(fast_retainer::io)?.len() <= control::LIMIT as u64,
            "RESOURCE_WAIT caller head log size",
        )?;
        let mut prefix = vec![];
        Read::by_ref(&mut file)
            .take(control::LIMIT as u64 + 1)
            .read_to_end(&mut prefix)
            .map_err(fast_retainer::io)?;
        let state = decode(&prefix)?;
        let mut log = Self {
            path: path.to_path_buf(),
            file,
            lease_path,
            lease,
            prefix,
            state,
            poisoned: false,
            observer: None,
        };
        log.files()?;
        if !recovery {
            log.check(log.state.head)?;
        }
        Ok(log)
    }
    fn identities(&self) -> Result<()> {
        fast_retainer::private(fast_retainer::parent(&self.path)?, false)?;
        fast_retainer::private(&self.path, true)?;
        fast_retainer::private(&self.lease_path, true)?;
        let path = fs::symlink_metadata(&self.path).map_err(fast_retainer::io)?;
        let file = self.file.metadata().map_err(fast_retainer::io)?;
        let name = fs::symlink_metadata(&self.lease_path).map_err(fast_retainer::io)?;
        let lease = self.lease.metadata().map_err(fast_retainer::io)?;
        ensure(
            path.len() == self.prefix.len() as u64
                && file.len() == path.len()
                && name.len() == 32
                && lease.len() == 32,
            "INVALID changed head log length/lease",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                path.dev() == file.dev()
                    && path.ino() == file.ino()
                    && name.dev() == lease.dev()
                    && name.ino() == lease.ino(),
                "INVALID replaced head log file/lease",
            )?;
        }
        Ok(())
    }
    fn files(&mut self) -> Result<()> {
        ensure(!self.poisoned, "RESOURCE_WAIT head log restart required")?;
        self.identities()?;
        ensure(
            !suffix(&self.path, ".next")
                .try_exists()
                .map_err(fast_retainer::io)?,
            "RESOURCE_WAIT mixed head log candidate residue",
        )?;
        self.lease
            .seek(SeekFrom::Start(0))
            .map_err(fast_retainer::io)?;
        let mut binding = [0; 32];
        self.lease
            .read_exact(&mut binding)
            .map_err(fast_retainer::io)?;
        ensure(
            binding == self.state.binding,
            "INVALID head log lease binding",
        )?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(fast_retainer::io)?;
        let mut buffer = [0; 65536];
        for chunk in self.prefix.chunks(buffer.len()) {
            self.file
                .read_exact(&mut buffer[..chunk.len()])
                .map_err(fast_retainer::io)?;
            ensure(
                &buffer[..chunk.len()] == chunk,
                "INVALID changed head log prefix",
            )?;
        }
        self.identities()
    }
    pub(super) fn check(&mut self, head: Hash) -> Result<()> {
        self.files()?;
        ensure(
            self.state.pending.is_none(),
            "RESOURCE_WAIT head log reconciliation required",
        )?;
        ensure(
            self.state.head == head,
            "INVALID controlled caller latest head",
        )
    }
    pub(super) fn authorize(&mut self, prior: Hash, i: &journal::Intent) -> Result<()> {
        self.files()?;
        ensure(
            self.state.head == prior && self.state.pending.as_ref() == Some(&pending(i)?),
            "INVALID head log prepared caller binding",
        )
    }
    fn append(&mut self, kind: u8, head: Hash, p: &Pending) -> Result<()> {
        self.files()?;
        let (raw, next) = record(&self.state, kind, head, p)?;
        ensure(
            self.prefix.len() + raw.len() <= control::LIMIT,
            "RESOURCE_WAIT head log capacity",
        )?;
        let result = self
            .file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&raw))
            .map_err(fast_retainer::io)
            .and_then(|_| fast_retainer::sync(&self.file, &self.path));
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
        self.prefix.extend(raw);
        self.state = next;
        if let Err(e) = self.files() {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }
    fn observe(&mut self, b: Boundary) -> Result<()> {
        if let Some(f) = &mut self.observer {
            f(b)?;
        }
        Ok(())
    }
    pub(super) fn set_observer(&mut self, f: Box<dyn FnMut(Boundary) -> Result<()> + Send>) {
        self.observer = Some(f);
    }
    pub(super) fn begin(&mut self, prior: Hash, i: &journal::Intent) -> Result<()> {
        self.check(prior)?;
        let p = pending(i)?;
        ensure(
            self.prefix.len() + 2 * RECORD <= control::LIMIT,
            "RESOURCE_WAIT head log complete response reservation",
        )?;
        self.append(1, prior, &p)?;
        self.observe(Boundary::PrepareNextDurable)?;
        self.observe(Boundary::Prepared)
    }
    pub(super) fn finish(&mut self, head: Hash) -> Result<()> {
        let p = self
            .state
            .pending
            .clone()
            .ok_or("INVALID missing head log intent")?;
        self.append(2, head, &p)?;
        self.observe(Boundary::CommitNextDurable)?;
        self.observe(Boundary::Committed)
    }
}
impl Session {
    pub fn create_log_controlled(
        root: &Path,
        g: &[u8],
        chain: Hash,
        file: &Path,
        now: u64,
    ) -> Result<Self> {
        Self::create_profile(root, g, chain, now, Some((file, true)))
    }
    pub fn open_log_controlled(
        root: &Path,
        g: &[u8],
        chain: Hash,
        file: &Path,
        now: u64,
    ) -> Result<Self> {
        let c = HeadLog::open(file, false)?;
        let mut s = Self::open_profile(root, g, chain, c.state.head, now, 2)?;
        ensure(
            s.caller.binding() == c.state.binding,
            "INVALID head log caller binding",
        )?;
        s.control = Some(Control::Logged(c));
        s.check_control(s.head())?;
        Ok(s)
    }
    /// Clear only unused preparation or fully audit the exact retained request.
    /// This cannot first-execute, load a key, repair a tail or release a reserve.
    pub fn recover_log_controlled(
        root: &Path,
        g: &[u8],
        chain: Hash,
        file: &Path,
        now: u64,
    ) -> Result<(Self, Value)> {
        let mut c = HeadLog::open(file, true)?;
        let prior = c.state.head;
        let mut retained = false;
        let p = c.state.pending.clone();
        let mut s = if let Some(p) = &p {
            ensure(p.at <= now, "CLOCK_WAIT head log pending intent")?;
            let j = Journal::open(&root.join("caller.journal"), g, chain, None, now, 2)?;
            ensure(
                j.binding() == c.state.binding,
                "INVALID head log recovery binding",
            )?;
            let unchanged = j.head == prior;
            let i = j
                .ops
                .last()
                .filter(|op| op.prior == prior)
                .map(|op| op.intent.clone());
            if !unchanged {
                let i = i
                    .as_ref()
                    .ok_or("INVALID head log retained request prior")?;
                ensure(
                    pending(i)? == *p,
                    "INVALID head log exact canonical request",
                )?;
                retained = true;
            }
            drop(j);
            if unchanged {
                Self::open_profile(root, g, chain, prior, now, 2)?
            } else {
                let i = i.unwrap();
                Self::recover_profile(root, g, chain, prior, (i.id, i.action.digest()?), now, 2)?.0
            }
        } else {
            Self::open_profile(root, g, chain, prior, now, 2)?
        };
        ensure(
            s.caller.binding() == c.state.binding,
            "INVALID recovered head log caller",
        )?;
        let proof = if retained || p.is_none() && !s.caller.ops.is_empty() {
            Some(s.output(now)?)
        } else {
            None
        };
        if p.is_some() {
            c.finish(s.head())?;
        }
        c.check(s.head())?;
        s.control = Some(Control::Logged(c));
        let mut out = s.status(s.head(), now)?;
        if let Some(Value::Object(proof)) = proof {
            out.as_object_mut().unwrap().extend(proof);
        }
        out["recovery_first_execution"] = false.into();
        out["recovery_key_loaded"] = false.into();
        out["request_body_retained"] = (retained || p.is_none() && !s.caller.ops.is_empty()).into();
        if let Some(p) = p {
            out["retained_request"] = serde_json::to_value(p.id).map_err(fast_retainer::io)?;
            out["retained_intent_digest"] = hex::encode(p.digest).into();
        }
        Ok((s, out))
    }
}

#[cfg(test)]
mod tests {
    // Synthetic PUBLIC NO-VALUE local metadata only, never ledger authority.
    use super::*;
    fn header() -> Vec<u8> {
        let mut b = b"RLDFCLG1".to_vec();
        b.extend([0, 1, 0, 1]);
        b.extend([61; 32]);
        b.extend([62; 32]);
        b.extend(hash("CONTROL-LOG-HEADER", &b));
        b
    }
    fn request() -> Pending {
        Pending {
            id: Id([63; 32]),
            at: 100,
            digest: [64; 32],
        }
    }
    #[test]
    fn exact_fixed_records_bind_predecessor_request_and_prepare_completion_order() {
        let mut bytes = header();
        let state = decode(&bytes).unwrap();
        let p = request();
        let (prepare, s) = record(&state, 1, state.head, &p).unwrap();
        assert_eq!(prepare.len(), RECORD);
        bytes.extend(&prepare);
        let replay = decode(&bytes).unwrap();
        assert_eq!(replay.pending, Some(p.clone()));
        assert_eq!(replay.head, state.head);
        assert!(record(&s, 1, s.head, &p).is_err());
        assert!(record(&state, 2, state.head, &p).is_err());
        let mut wrong = p.clone();
        wrong.at += 1;
        assert!(record(&s, 2, [65; 32], &wrong).is_err());
        wrong = p.clone();
        wrong.id = Id([66; 32]);
        assert!(record(&s, 2, [65; 32], &wrong).is_err());
        let (commit, s) = record(&s, 2, [65; 32], &p).unwrap();
        bytes.extend(commit);
        assert_eq!(decode(&bytes).unwrap().head, [65; 32]);
        assert!(s.pending.is_none());
        let mut rollback = p;
        rollback.at -= 1;
        assert!(record(&s, 1, s.head, &rollback).is_err());
    }
    #[test]
    fn rehashed_invalid_transitions_versions_and_partial_frames_refuse() {
        let h = header();
        let state = decode(&h).unwrap();
        let (r, _) = record(&state, 1, state.head, &request()).unwrap();
        for index in [0, 8, 10, 12, 44, 76] {
            let mut b = h.clone();
            b[index] ^= 1;
            assert!(decode(&b).is_err());
        }
        for index in [0usize, 1, 9, 41] {
            let mut b = r.clone();
            b[4 + index] ^= 1;
            let digest = hash("CONTROL-LOG-RECORD", &b[4..4 + 145]);
            b[4 + 145..].copy_from_slice(&digest);
            let mut all = h.clone();
            all.extend(&b);
            assert!(decode(&all).is_err(), "field{index}");
        }
        for start in [73, 113] {
            let mut b = r.clone();
            b[4 + start..4 + start + 32].fill(0);
            let digest = hash("CONTROL-LOG-RECORD", &b[4..4 + 145]);
            b[149..].copy_from_slice(&digest);
            let mut all = h.clone();
            all.extend(b);
            assert!(decode(&all).is_err());
        }
        for n in [1, 3, 4, 12, r.len() - 1] {
            let mut all = h.clone();
            all.extend(&r[..n]);
            assert!(decode(&all).is_err());
        }
        let mut extra = h;
        extra.push(0);
        assert!(decode(&extra).is_err());
    }
    #[test]
    fn complete_response_capacity_uses_the_unchanged_snapshot_file_bound() {
        let mut all = header();
        let mut state = decode(&all).unwrap();
        let mut count = 0;
        while all.len() + 2 * RECORD <= control::LIMIT {
            let mut p = request();
            p.at += count;
            let (a, next) = record(&state, 1, state.head, &p).unwrap();
            let (b, next) = record(&next, 2, state.head, &p).unwrap();
            all.extend(a);
            all.extend(b);
            state = next;
            count += 1;
        }
        assert_eq!(count, 2896);
        assert!(all.len() <= 1048651);
        assert!(all.len() + RECORD <= 1048651);
        assert!(all.len() + 2 * RECORD > 1048651);
        assert_eq!(decode(&all).unwrap().index, 5792);
    }
    fn private_root(label: &str) -> PathBuf {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("rld-head-log-{label}-{}", hex::encode(nonce)));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
    #[test]
    fn actual_file_lease_identity_prefix_modes_residue_and_cold_damage_refuse() {
        for damage in 0..10 {
            let root = private_root("guards");
            let path = root.join("head");
            let mut log = HeadLog::create(&path, [61; 32], [62; 32]).unwrap();
            assert!(HeadLog::open(&path, true).is_err());
            match damage {
                0 => {
                    fs::rename(&path, root.join("old-head")).unwrap();
                    write_new(&path, &log.prefix).unwrap();
                }
                1 => {
                    fs::rename(suffix(&path, ".lock"), root.join("old-lock")).unwrap();
                    write_new(&suffix(&path, ".lock"), &[61; 32]).unwrap();
                }
                2 => fs::write(suffix(&path, ".lock"), [60; 32]).unwrap(),
                3 => {
                    let mut changed = log.prefix.clone();
                    changed[12] ^= 1;
                    fs::write(&path, changed).unwrap();
                }
                4 => write_new(&suffix(&path, ".next"), b"retained residue").unwrap(),
                5 => {
                    let mut changed = log.prefix.clone();
                    changed.push(0);
                    fs::write(&path, changed).unwrap();
                }
                6 => fs::write(&path, &log.prefix[..HEADER - 1]).unwrap(),
                7 => {
                    let mut changed = log.prefix.clone();
                    changed[9] = 2;
                    fs::write(&path, changed).unwrap();
                }
                8 => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                    }
                    #[cfg(not(unix))]
                    fs::write(suffix(&path, ".lock"), []).unwrap();
                }
                9 => {
                    let (r, _) = record(&log.state, 1, log.state.head, &request()).unwrap();
                    let mut changed = log.prefix.clone();
                    changed.extend(&r[..r.len() - 1]);
                    fs::write(&path, changed).unwrap();
                }
                _ => unreachable!(),
            }
            let bytes = fs::read(&path).unwrap();
            let lease = fs::read(suffix(&path, ".lock")).unwrap();
            let next = fs::read(suffix(&path, ".next")).ok();
            assert!(log.check([62; 32]).is_err(), "warm damage{damage}");
            drop(log);
            // A byte-identical inode replacement is a warm lease violation.
            // Cold opening cannot establish external latest-state freshness.
            if damage >= 2 {
                assert!(HeadLog::open(&path, true).is_err(), "cold damage{damage}");
            }
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(fs::read(suffix(&path, ".lock")).unwrap(), lease);
            assert_eq!(fs::read(suffix(&path, ".next")).ok(), next);
        }
    }
    #[test]
    fn real_full_file_reserves_both_records_before_preparing_any_request() {
        let root = private_root("capacity");
        let path = root.join("head");
        let log = HeadLog::create(&path, [61; 32], [62; 32]).unwrap();
        let mut all = log.prefix.clone();
        let mut state = log.state.clone();
        drop(log);
        for _ in 0..2896 {
            let p = request();
            let (a, next) = record(&state, 1, state.head, &p).unwrap();
            let (b, next) = record(&next, 2, state.head, &p).unwrap();
            all.extend(a);
            all.extend(b);
            state = next;
        }
        fs::write(&path, &all).unwrap();
        let mut log = HeadLog::open(&path, false).unwrap();
        let i = journal::Intent {
            id: Id([63; 32]),
            at: 100,
            action: Action::FeePolicySign {
                tip: Id([64; 32]),
                policy_request: Id([65; 32]),
                prepare_request: Id([66; 32]),
                review: Id([67; 32]),
                key_file: "absent-public-no-value.key".into(),
            },
        };
        let e = log.begin(state.head, &i).unwrap_err();
        assert!(e.contains("complete response reservation"), "{e}");
        assert_eq!(fs::read(&path).unwrap(), all);
        assert!(log.state.pending.is_none());
        log.check(state.head).unwrap();
    }
}
