//! Finite representation/queue diagnostics only: no Native, Mesh, TLS or value authority.
use super::*;

fn private_writer() -> (PathBuf, Writer, Arc<Shared>, Receiver<Event>, Value) {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-carriage-codec-unit-{}-{}",
            std::process::id(),
            super::super::monotonic().unwrap().to_bits()
        ));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&root).unwrap();
    let created = super::super::monotonic().unwrap();
    let binding = json!({"format":FORMAT,"pid":std::process::id(),"instance":"a".repeat(64),
        "currency":Hash::ZERO,"region":Hash::ZERO,"node_id":"b".repeat(64),
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"diagnostic_only":true,
        "native_authority":false,"signing_authority":false,"custody_acknowledgment":false,
        "payment_qualification":false,"independent_freshness_qualified":false});
    assert_eq!(binding.as_object().unwrap().len(), 13);
    let mut scope_value = binding.clone();
    scope_value.as_object_mut().unwrap().extend(
        serde_json::from_value::<serde_json::Map<String, Value>>(
            json!({"created_at":created,"clock":"local-monotonic-seconds","max_rows":MAX_ROWS,
            "max_bytes":MAX_BYTES,"max_row_bytes":MAX_ROW,"channel_capacity":CHANNEL,
            "written_order_is_global_clock_order":false}),
        )
        .unwrap(),
    );
    let (scope, scope_raw) = meta(&root, SCOPE, &scope_value).unwrap();
    let scope_sha256 = hex::encode(Sha256::digest(&scope_raw));
    let events = create(&root.join(EVENTS)).unwrap();
    let (tx, rx) = sync_channel(CHANNEL);
    let shared = Arc::new(Shared {
        tx,
        created_at: created,
        closed: AtomicBool::new(false),
        seal_requested: AtomicBool::new(true),
        requested_success: AtomicBool::new(true),
        next_attempt: AtomicU64::new(0),
        active: AtomicU64::new(0),
        handles: AtomicUsize::new(0),
        loss: AtomicU64::new(0),
        errors: AtomicU64::new(0),
        incomplete: AtomicU64::new(0),
    });
    let writer = Writer {
        root: root.clone(),
        binding: binding.clone(),
        scope,
        scope_raw,
        scope_sha256,
        events,
        digest: Sha256::new(),
        rows: 0,
        bytes: 0,
        poisoned: false,
        latest_observed_at: created,
    };
    (root, writer, shared, rx, binding)
}
fn dynamic(event: &Event, written_sequence: usize) -> Value {
    json!({"written_sequence":written_sequence,"attempt_id":event.attempt,
        "attempt_sequence":event.sequence,"lane":event.lane,"phase":event.phase,
        "observed_at":event.observed_at,"detail":event.detail})
}
fn full_row(binding: &Value, fields: &Value) -> Value {
    let mut row = binding.clone();
    row.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    row
}
fn stored_rows(raw: &[u8]) -> Vec<Value> {
    assert!(!raw.is_empty() && raw.ends_with(b"\n"));
    raw.split_inclusive(|b| *b == b'\n')
        .map(|line| {
            assert!(line.len() <= MAX_ROW && line.ends_with(b"\n"));
            serde_json::from_slice(&line[..line.len() - 1]).unwrap()
        })
        .collect()
}
fn assert_binding(binding: &Value, scope: &Value, terminal: &Value) {
    assert_eq!(scope["format"], "RLD-SERVICE-CARRIAGE-OBSERVATION-V2");
    assert_eq!(terminal["format"], scope["format"]);
    for (key, value) in binding.as_object().unwrap() {
        assert_eq!(&scope[key], value);
        assert_eq!(&terminal[key], value);
    }
    for flag in [
        "native_authority",
        "signing_authority",
        "custody_acknowledgment",
        "payment_qualification",
        "independent_freshness_qualified",
    ] {
        assert_eq!(scope[flag], false);
        assert_eq!(terminal[flag], false);
    }
    assert_eq!(scope["diagnostic_only"], true);
    assert_eq!(scope["max_rows"], MAX_ROWS);
    assert_eq!(scope["max_bytes"], MAX_BYTES);
    assert_eq!(scope["max_row_bytes"], MAX_ROW);
    assert_eq!(scope["channel_capacity"], CHANNEL);
}
#[test]
fn carriage_v2_twelve_thousand_events_reconstruct_exact_legacy_fields() {
    const COUNT: usize = 12_000;
    let (root, mut writer, shared, _rx, binding) = private_writer();
    let mut legacy_binding = binding.clone();
    legacy_binding["format"] = json!("RLD-SERVICE-CARRIAGE-OBSERVATION-V1");
    let mut expected = Vec::with_capacity(COUNT);
    let mut legacy_bytes = 0usize;
    let operations = [
        ("incoming", "challenge"),
        ("incoming", "custody"),
        ("outgoing", "prepare"),
        ("outgoing", "request"),
        ("outgoing", "reply"),
    ];
    for index in 0..COUNT {
        let (role, operation) = operations[index % operations.len()];
        let event = Event {
            attempt: (index / 5 + 1) as u64,
            sequence: (index % 5 + 1) as u64,
            lane: "mesh-lease",
            phase: "unit-metadata".into(),
            observed_at: super::super::monotonic().unwrap(),
            detail: json!({"role":role,"operation":operation,"parent_attempt_id":1,
                "main_turn":Value::Null,"ordinal":index}),
        };
        // The actual runtime metadata validator and actual Writer encoding are used.
        detail(&event.detail).unwrap();
        let fields = dynamic(&event, index + 1);
        let old = full_row(&legacy_binding, &fields);
        let old_raw = files::canonical_with_limit(&old, MAX_ROW - 1).unwrap();
        legacy_bytes = legacy_bytes.checked_add(old_raw.len() + 1).unwrap();
        expected.push(fields);
        writer.append(event).unwrap();
    }
    assert!(
        legacy_bytes > MAX_BYTES,
        "finite old complete rows must exceed original byte cap"
    );
    assert_eq!(writer.rows, COUNT);
    assert!(writer.rows < MAX_ROWS);
    assert!(writer.bytes <= MAX_BYTES);
    shared
        .next_attempt
        .store((COUNT / 5) as u64, Ordering::Release);
    writer.finish(&shared).unwrap(); // Real digest/fsync/readback and original true-finish checks.
    let raw = fs::read(root.join(EVENTS)).unwrap();
    let scope_raw = fs::read(root.join(SCOPE)).unwrap();
    let scope: Value = serde_json::from_slice(&scope_raw).unwrap();
    let terminal: Value = serde_json::from_slice(&fs::read(root.join(TERMINAL)).unwrap()).unwrap();
    assert!(scope_raw.len() <= MAX_META && raw.len() <= MAX_BYTES);
    assert_binding(&binding, &scope, &terminal);
    assert_eq!(terminal["success"], true);
    assert_eq!(terminal["rows"], COUNT);
    assert_eq!(terminal["loss"], 0);
    assert_eq!(terminal["errors"], 0);
    assert_eq!(terminal["events_bytes"], raw.len());
    assert_eq!(terminal["events_sha256"], hex::encode(Sha256::digest(&raw)));
    assert_eq!(terminal["exact_retained_integrity"], true);
    let rows = stored_rows(&raw);
    assert_eq!(rows.len(), COUNT);
    let exact_scope = hex::encode(Sha256::digest(&scope_raw));
    for (mut row, fields) in rows.into_iter().zip(expected) {
        let mut names: Vec<_> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "attempt_id",
                "attempt_sequence",
                "detail",
                "lane",
                "observed_at",
                "phase",
                "scope_sha256",
                "written_sequence"
            ]
        );
        assert_eq!(row["scope_sha256"], exact_scope);
        row.as_object_mut().unwrap().remove("scope_sha256");
        assert_eq!(
            row["observed_at"].as_f64().unwrap().to_bits(),
            fields["observed_at"].as_f64().unwrap().to_bits()
        );
        assert_eq!(
            full_row(&legacy_binding, &row),
            full_row(&legacy_binding, &fields)
        );
        assert_eq!(row, fields); // Every dynamic field, including original clock/role/parent, exact.
    }
}
#[test]
fn carriage_v2_exact_channel_128_preserves_one_loss_and_refuses_true() {
    assert_eq!(CHANNEL, 128);
    let (root, writer, shared, rx, binding) = private_writer();
    // No collector exists during these sends. A blocking replacement cannot reach assertions
    // under the externally bounded unit run. This is not a random throughput experiment.
    for index in 0..=CHANNEL {
        shared.send(Event {
            attempt: 1,
            sequence: (index + 1) as u64,
            lane: "mesh-lease",
            phase: "unit-metadata".into(),
            observed_at: super::super::monotonic().unwrap(),
            detail: json!({"ordinal":index}),
        });
    }
    assert_eq!(shared.loss.load(Ordering::Acquire), 1);
    assert_eq!(shared.errors.load(Ordering::Acquire), 0);
    shared.next_attempt.store(1, Ordering::Release);
    shared.closed.store(true, Ordering::Release);
    assert_eq!(
        collect(writer, rx, Arc::clone(&shared)).unwrap_err(),
        "Carriage incomplete observation cannot seal true"
    );
    let scope: Value = serde_json::from_slice(&fs::read(root.join(SCOPE)).unwrap()).unwrap();
    let terminal: Value = serde_json::from_slice(&fs::read(root.join(TERMINAL)).unwrap()).unwrap();
    assert_binding(&binding, &scope, &terminal);
    assert_eq!(terminal["requested_success"], true);
    assert_eq!(terminal["success"], false);
    assert_eq!(terminal["loss"], 1);
    assert_eq!(terminal["errors"], 0);
    assert_eq!(terminal["rows"], CHANNEL);
    assert_eq!(terminal["active_attempts"], 0);
    assert_eq!(terminal["remaining_sink_handles"], 0);
    let raw = fs::read(root.join(EVENTS)).unwrap();
    assert_eq!(terminal["events_sha256"], hex::encode(Sha256::digest(&raw)));
    let rows = stored_rows(&raw);
    assert_eq!(rows.len(), CHANNEL);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["written_sequence"], index + 1);
        assert_eq!(row["attempt_sequence"], index + 1);
        assert_eq!(row["detail"]["ordinal"], index);
    }
    assert_eq!(shared.loss.load(Ordering::Acquire), 1); // Drain cannot erase the dropped129th event.
}
