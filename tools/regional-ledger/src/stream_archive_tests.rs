use super::*;
use crate::stream_archive::{Binding, Record};
use crate::stream_replay::{Cursor, Record as NativeRecord};
use std::io::Write;

fn write_archive(bytes: &[u8]) -> std::path::PathBuf {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-compact-stream-{}",
            rld_core::generate_identity().public_key
        ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("history.jsonl");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    path
}
fn check(path: &std::path::Path, f: &Fixture, head: Hash) -> Result<crate::stream_replay::Head> {
    crate::stream_archive::check_archive(
        path,
        &bootstrap(),
        &public(1),
        f.trust.currency().unwrap(),
        "earth",
        head,
    )
}
fn sample(f: &Fixture) -> (Vec<u8>, crate::stream_replay::Head) {
    let binding = Binding::new(&f.trust, "earth").unwrap();
    let mut bytes = Record::Binding {
        binding: binding.clone(),
    }
    .line()
    .unwrap();
    let mut cursor = Cursor::new(f.earth.region, &f.trust).unwrap();
    for block in &f.earth.blocks {
        cursor.accept(block, &f.trust, &f.evidence).unwrap();
        bytes.extend(
            Record::from_native(
                NativeRecord::Block {
                    block: Box::new(block.clone()),
                },
                &binding,
            )
            .unwrap()
            .line()
            .unwrap(),
        );
    }
    (bytes, cursor.head().unwrap())
}

#[test]
fn exact_complete_signed_native_block_roundtrip_preserves_order_and_destinations() {
    let f = Fixture::new();
    let binding = Binding::new(&f.trust, "earth").unwrap();
    let mut native = f.earth.blocks.last().unwrap().clone();
    let spend = intent(
        &f.earth,
        &f.trust,
        coins(&f.earth, 10),
        vec![Payment {
            owner: public(11),
            amount: Amount(30),
        }],
        Some(f.proxima.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(60),
        }),
        0,
        1,
        &[10],
    );
    native.commands = vec![
        Command::Spend(Box::new(spend)),
        Command::Import {
            snapshot: Hash([21; 32]),
            export: Hash([22; 32]),
        },
    ];
    let original = NativeRecord::Block {
        block: Box::new(native.clone()),
    };
    let original_bytes = serde_json::to_vec(&original).unwrap();
    let compact = Record::from_native(original, &binding).unwrap();
    let line = compact.line().unwrap();
    assert!(line.len() < original_bytes.len());
    let parsed: Record = serde_json::from_slice(&line).unwrap();
    assert_eq!(
        serde_json::to_vec(&parsed.expand(&binding).unwrap().unwrap()).unwrap(),
        original_bytes
    );
    native.header.currency = Hash::ZERO;
    assert!(Record::from_native(
        NativeRecord::Block {
            block: Box::new(native)
        },
        &binding
    )
    .is_err());
}

#[test]
fn compact_and_complete_replay_derive_identical_head_without_mutating_archive() {
    let f = Fixture::new();
    let (bytes, head) = sample(&f);
    let path = write_archive(&bytes);
    assert_eq!(check(&path, &f, head.id().unwrap()).unwrap(), head);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(check(&path, &f, Hash::ZERO).is_err());
    assert!(crate::stream_replay::check_archive(
        &path,
        &bootstrap(),
        &public(1),
        f.trust.currency().unwrap(),
        "earth",
        head.id().unwrap()
    )
    .is_err());
    let mut complete = vec![];
    for block in &f.earth.blocks {
        serde_json::to_writer(
            &mut complete,
            &NativeRecord::Block {
                block: Box::new(block.clone()),
            },
        )
        .unwrap();
        complete.push(b'\n');
    }
    let full = write_archive(&complete);
    assert_eq!(
        crate::stream_replay::check_archive(
            &full,
            &bootstrap(),
            &public(1),
            f.trust.currency().unwrap(),
            "earth",
            head.id().unwrap()
        )
        .unwrap(),
        head
    );
    assert!(check(&full, &f, head.id().unwrap()).is_err());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(full.parent().unwrap()).unwrap();
}

#[test]
fn binding_cannot_switch_domains_repeat_hide_fields_or_adopt_serialized_state() {
    let f = Fixture::new();
    let (bytes, head) = sample(&f);
    let split = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
    let binding = Binding::new(&f.trust, "earth").unwrap();
    let mut failures = vec![bytes[split..].to_vec(), vec![]];
    let mut repeated = bytes[..split].to_vec();
    repeated.extend(&bytes);
    failures.push(repeated);
    for field in ["currency", "region", "trust"] {
        let mut wrong = binding.clone();
        match field {
            "currency" => wrong.currency = Hash::ZERO,
            "region" => wrong.region = Hash::ZERO,
            _ => wrong.trust = Hash::ZERO,
        }
        let mut value = Record::Binding { binding: wrong }.line().unwrap();
        value.extend(&bytes[split..]);
        failures.push(value);
    }
    let mut state = bytes[..split].to_vec();
    state.extend(b"{\"kind\":\"ledger\",\"ledger\":{\"minted\":\"999\"}}\n");
    failures.push(state);
    let mut unknown = bytes[..split - 2].to_vec();
    unknown.extend(b",\"unchecked_state\":{}}\n");
    unknown.extend(&bytes[split..]);
    failures.push(unknown);
    for failed in failures {
        let path = write_archive(&failed);
        assert!(check(&path, &f, head.id().unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), failed);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn altered_native_tail_signature_commitment_and_truncation_refuse_complete_replay() {
    let f = Fixture::new();
    let (bytes, head) = sample(&f);
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let mut failures = vec![bytes[..bytes.len() - 1].to_vec()];
    for field in ["state", "parent", "command_root"] {
        let mut tail: serde_json::Value = serde_json::from_slice(lines.last().unwrap()).unwrap();
        tail["block"][field] = serde_json::to_value(Hash::ZERO).unwrap();
        let record: Record = serde_json::from_value(tail).unwrap();
        let mut altered = lines[..lines.len() - 1].concat();
        altered.extend(record.line().unwrap());
        failures.push(altered);
    }
    // A canonical compact body is never an owner authorization shortcut.
    let binding = Binding::new(&f.trust, "earth").unwrap();
    let mut spend = intent(
        &f.earth,
        &f.trust,
        coins(&f.earth, 10),
        vec![Payment {
            owner: public(11),
            amount: Amount(100),
        }],
        None,
        None,
        0,
        0,
        &[10],
    );
    spend.approvals[0].signature = "00".repeat(64);
    let mut block = f.earth.blocks.last().unwrap().clone();
    block.header.height += 1;
    block.header.parent = f.earth.tip().unwrap();
    block.commands = vec![Command::Spend(Box::new(spend))];
    block.header.commands = id("commands", &block.commands).unwrap();
    mine(&mut block).unwrap();
    let mut altered = bytes.clone();
    altered.extend(
        Record::from_native(
            NativeRecord::Block {
                block: Box::new(block),
            },
            &binding,
        )
        .unwrap()
        .line()
        .unwrap(),
    );
    failures.push(altered);
    for failed in failures {
        let path = write_archive(&failed);
        assert!(check(&path, &f, head.id().unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), failed);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn oversized_noncanonical_records_and_unadmitted_bft_never_initialize_cursor() {
    let f = Fixture::new();
    let (bytes, head) = sample(&f);
    let mut whitespace = vec![b' '];
    whitespace.extend(&bytes);
    for failed in [vec![b'x'; MAX_BYTES + 1], whitespace] {
        let path = write_archive(&failed);
        assert!(check(&path, &f, head.id().unwrap()).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    let mut b = bootstrap();
    b.admissions[0].rules = crate::bft::RULES.into();
    b.admissions[0].signature = signature(1, &b.admissions[0].bytes().unwrap());
    let trust = Trust::verify(&b, &public(1), b.currency.id().unwrap()).unwrap();
    assert!(Binding::new(&trust, "earth").is_err());

    // A disk record within the limit cannot use omitted fields to expand past
    // the complete native limit. Refuse before owner execution, even with an
    // intentionally invalid padded public key in this capacity test.
    let binding = Binding::new(&f.trust, "earth").unwrap();
    let mut block = f.earth.blocks.last().unwrap().clone();
    let signed = intent(
        &f.earth,
        &f.trust,
        coins(&f.earth, 10),
        vec![Payment {
            owner: public(11),
            amount: Amount(100),
        }],
        None,
        None,
        0,
        0,
        &[10],
    );
    block.commands = vec![Command::Spend(Box::new(signed))];
    let native = NativeRecord::Block {
        block: Box::new(block),
    };
    let native_size = serde_json::to_vec(&native).unwrap().len();
    let compact = Record::from_native(native, &binding).unwrap();
    let mut value = serde_json::to_value(compact).unwrap();
    value["block"]["commands"][0]["Spend"]["outputs"][0]["owner"] =
        serde_json::Value::String("a".repeat(MAX_BYTES - native_size + public(11).len()));
    let compact: Record = serde_json::from_value(value).unwrap();
    assert!(compact.line().unwrap().len() < MAX_BYTES);
    assert!(compact
        .expand(&binding)
        .err()
        .unwrap()
        .contains("expanded complete stream record bound"));
}
