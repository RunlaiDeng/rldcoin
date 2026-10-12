//! Bounded source evidence and explicitly reviewed ordinary publication.
use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
#[path = "../../../rld-core/build_support/source_identity.rs"]
mod source_identity;
const REMOTE: &str = "https://github.com/RunlaiDeng/rldcoin.git";
const DOCS: &[&str] = &["md", "rst", "txt", "html"];
const KINDS: &[&str] = &[
    "source",
    "build-config",
    "public-vector",
    "developer-documentation",
    "security-note",
    "capability-boundary",
    "acceptance-contract",
];
const LOCAL: &[&str] = &[
    "docs/operations/evidence/",
    "docs/operations/fixtures/",
    "docs/operations/history/",
    "tmp/",
    "target/",
];
const PATTERNS: &[&str] = &[
    r"(?i)\b(?:PASS|FAIL)\s*\d+(?:\.\d+)?\s*seconds?",
    r"(?i)(?:^|[^\w-])V\d+\b[^\n]{0,180}(?-i:\bPASS\b|\bFAIL\b)",
    r"(?i)\d+\.\d+\s*seconds?",
    r"(?i)\b(?:controller_sha256|stage_sha256|private_inventory_sha256|duration_seconds|cumulative_seconds|actual_process_peak_rss_bytes)\b",
    r"/Users/[^\s`<>]+|/home/[^\s`<>]+|[A-Z]:\\Users\\",
    r"(?i)\b(?:thread|task)[^\n]{0,40}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    r"(?i)next\s+(?:stage\b|experiment\b|diagnostic\s+hypothesis)",
    r"(?i)(?:actual\s*binary|controller\s*(?:hash|SHA-?256))[^\n]{0,100}[0-9a-f]{64}\b",
    r"(?i)(?:source|binary|controller)[^\n]{0,50}(?:hash|SHA-?256)[^\n]{0,70}[0-9a-f]{64}[^\n]{0,80}(?:PASS|next\s*stage|progress)",
];
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Review {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        selection: PathBuf,
    },
    ScanDocuments {
        #[arg(long)]
        root: PathBuf,
    },
    CheckRustOnly {
        #[arg(long)]
        root: PathBuf,
    },
    Publish {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        selection: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        receipt_directory: PathBuf,
    },
    ImplementationSource {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        expected_commitment: String,
    },
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    CargoSbom {
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        source_commit: String,
        #[arg(long)]
        source_tree_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
    PqSpool {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        expected_root: String,
        #[command(subcommand)]
        action: PqSpoolAction,
    },
}
#[derive(Subcommand)]
enum PqSpoolAction {
    Init,
    Accept {
        packet: Vec<PathBuf>,
    },
    Complete {
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum SnapshotAction {
    Create {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        manifest_sha256: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    files: Vec<String>,
    content_classification: BTreeMap<String, Classification>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Classification {
    kind: String,
    purpose: String,
}
#[derive(Serialize)]
struct Reviewed {
    path: String,
    kind: String,
    purpose: String,
    sha256: Option<String>,
}
fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    ensure!(
        output.status.success(),
        "Git operation refused: {}",
        args.first().unwrap_or(&"read")
    );
    Ok(output.stdout)
}
fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(root, args)?)?.trim().into())
}
fn paths(root: &Path) -> Result<Vec<String>> {
    git(root, &["ls-files", "-z"])?
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .map(|v| String::from_utf8(v.to_vec()).map_err(Into::into))
        .collect()
}
fn safe_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !Path::new(name).is_absolute()
            && name.len() <= 4096
            && !name.contains('\\')
            && !name.chars().any(|c| c.is_control())
            && name
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".."),
        "unsafe source path"
    );
    Ok(())
}
fn regular(root: &Path, name: &str) -> Result<PathBuf> {
    safe_name(name)?;
    let mut path = root.to_path_buf();
    for part in Path::new(name).components() {
        path.push(part);
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "source symlink refused: {name}"
        );
    }
    ensure!(
        fs::symlink_metadata(&path)?.is_file(),
        "nonregular source file: {name}"
    );
    Ok(path)
}
fn prose(text: &str) -> Result<()> {
    for pattern in PATTERNS {
        ensure!(
            !Regex::new(pattern)?.is_match(text),
            "internal progress or host metadata in public prose"
        );
    }
    Ok(())
}
fn json_public(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            let banned = [
                "duration_seconds",
                "cumulative_seconds",
                "previous_used_seconds",
                "controller_sha256",
                "stage_sha256",
                "log_sha256",
                "private_inventory_sha256",
                "actual_process_peak_rss_bytes",
                "forced_owned_processes",
                "Native_Runtime_Node_calls",
                "private_key",
                "private_key_hex",
                "mnemonic",
                "seed",
                "secret_key",
                "access_token",
            ];
            ensure!(
                !banned.iter().any(|k| map.contains_key(*k)) && value["private"] != true,
                "private material or internal run metadata in public JSON"
            );
            for child in map.values() {
                json_public(child)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                json_public(child)?;
            }
        }
        Value::String(text) => prose(text)?,
        _ => {}
    }
    Ok(())
}
fn code_secrets(text: &str) -> Result<()> {
    let pem = Regex::new(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[ \t]*\r?\n(?:[A-Za-z0-9+/=]+[ \t]*\r?\n)+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    )?;
    ensure!(!pem.is_match(text), "private PEM bytes in source");
    ensure!(
        !Regex::new(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16})\b"
        )?
        .is_match(text),
        "credential bytes in source"
    );
    Ok(())
}
fn review(root: &Path, selection: &Selection) -> Result<Vec<Reviewed>> {
    ensure!(
        !selection.files.is_empty()
            && selection.files.len() == selection.content_classification.len()
            && selection
                .files
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == selection.files.len(),
        "every exact file requires classification"
    );
    selection
        .files
        .iter()
        .map(|name| {
            safe_name(name)?;
            ensure!(
                !LOCAL.iter().any(|p| name.starts_with(p))
                    && Path::new(name).file_name() != Some(std::ffi::OsStr::new("AGENTS.md")),
                "private/local path cannot be published"
            );
            let class = selection
                .content_classification
                .get(name)
                .context("missing file classification")?;
            ensure!(
                KINDS.contains(&class.kind.as_str()) && (12..=400).contains(&class.purpose.len()),
                "specific public content purpose required"
            );
            let path = root.join(name);
            let digest = if fs::symlink_metadata(&path).is_ok() {
                let path = regular(root, name)?;
                ensure!(
                    fs::metadata(&path)?.len() <= 256 * 1024 * 1024,
                    "public blob byte bound"
                );
                let raw = fs::read(path)?;
                let text = std::str::from_utf8(&raw)?;
                code_secrets(text)?;
                let ext = Path::new(name)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if DOCS.contains(&ext) {
                    ensure!(
                        !["source", "build-config", "public-vector"].contains(&class.kind.as_str()),
                        "prose classification differs"
                    );
                    prose(text)?;
                } else if ext == "json" {
                    ensure!(
                        ["public-vector", "build-config"].contains(&class.kind.as_str()),
                        "JSON classification differs"
                    );
                    json_public(&serde_json::from_slice(&raw)?)?;
                } else if ["rs", "c", "h", "sh", "js", "mjs"].contains(&ext) {
                    ensure!(class.kind == "source", "code classification differs");
                } else {
                    ensure!(
                        ["source", "build-config"].contains(&class.kind.as_str()),
                        "artifact classification differs"
                    );
                }
                Some(sha(&raw))
            } else {
                ensure!(
                    class.kind == "source" || class.kind == "build-config",
                    "deletion classification differs"
                );
                // A deletion must identify an existing remote-parent source blob.
                git(root, &["cat-file", "-e", &format!("HEAD:{name}")])?;
                None
            };
            Ok(Reviewed {
                path: name.clone(),
                kind: class.kind.clone(),
                purpose: class.purpose.clone(),
                sha256: digest,
            })
        })
        .collect()
}
fn scan(root: &Path) -> Result<()> {
    for name in paths(root)? {
        if DOCS.contains(
            &Path::new(&name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or(""),
        ) && root.join(&name).exists()
        {
            prose(&fs::read_to_string(regular(root, &name)?)?)
                .with_context(|| format!("public document {name}"))?;
        }
    }
    Ok(())
}
fn rust_only(root: &Path) -> Result<()> {
    // Retained private experiment archives are outside the distributed source set.
    // Inspect active source directories too, so ignored bytecode cannot evade CI.
    let mut todo = ["crates", "tools", "spec", "deploy", ".github"]
        .into_iter()
        .map(|name| root.join(name))
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let name = path.file_name().context("entry name")?.to_string_lossy();
            if [".git", "tmp", "target", "node_modules", ".next"].contains(&name.as_ref()) {
                continue;
            }
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                todo.push(path);
            } else if meta.is_file() {
                ensure!(
                    !["py", "pyw", "pyc", "pyo"]
                        .contains(&path.extension().and_then(|s| s.to_str()).unwrap_or("")),
                    "Python source/bytecode remains: {}",
                    path.display()
                );
            }
        }
    }
    let han = Regex::new(r"\p{Han}")?;
    let escaped =
        Regex::new(r"(?i)\\u(?:\{([0-9a-f]{1,6})\}|([0-9a-f]{4}))|&#(?:x([0-9a-f]+)|([0-9]+));")?;
    let python = Regex::new(
        r"(?m)(?:^|[\s=/])python(?:[0-9.]+)?(?:\s|$)|actions/setup-python|(?:^|\s)[^\s]+\.py(?:\s|$)",
    )?;
    let raw = git(
        root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    for name in raw.split(|b| *b == 0).filter(|v| !v.is_empty()) {
        let name = std::str::from_utf8(name)?;
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        ensure!(
            !["py", "pyw", "pyc", "pyo"].contains(&ext),
            "Python source in distributed source set: {name}"
        );
        if [
            "rs", "c", "h", "js", "mjs", "ts", "tsx", "sh", "html", "css",
        ]
        .contains(&ext)
        {
            let source = fs::read_to_string(&path)?;
            ensure!(
                !han.is_match(&source),
                "non-English source characters: {name}"
            );
            for capture in escaped.captures_iter(&source) {
                let (digits, radix) = if let Some(v) = capture.get(4) {
                    (v.as_str(), 10)
                } else {
                    (
                        capture
                            .get(1)
                            .or(capture.get(2))
                            .or(capture.get(3))
                            .context("escape digits")?
                            .as_str(),
                        16,
                    )
                };
                if let Some(ch) = u32::from_str_radix(digits, radix)
                    .ok()
                    .and_then(char::from_u32)
                {
                    ensure!(
                        !han.is_match(&ch.to_string()),
                        "escaped non-English source character: {name}"
                    );
                }
            }
        }
        if ["service", "sh", "yml", "yaml", "toml"].contains(&ext) {
            let text = fs::read_to_string(&path)?;
            ensure!(
                !python.is_match(&text),
                "Python executable in active configuration: {name}"
            );
        }
    }
    Ok(())
}
fn publish(root: &Path, selection: &Selection, message: &str, receipts: &Path) -> Result<Value> {
    // All content checks precede every Git mutation.
    let reviewed = review(root, selection)?;
    scan(root)?;
    rust_only(root)?;
    let receipts = receipts.canonicalize()?;
    ensure!(
        !receipts.starts_with(root),
        "publication receipts must remain outside checkout"
    );
    ensure!(
        git_text(root, &["branch", "--show-current"])? == "main"
            && git_text(root, &["remote", "get-url", "origin"])? == REMOTE,
        "existing main/exact origin required"
    );
    ensure!(
        git_text(root, &["diff", "--cached", "--name-only"])?.is_empty(),
        "existing staged changes require separate review"
    );
    let parent = git_text(root, &["rev-parse", "HEAD"])?;
    ensure!(
        git_text(root, &["ls-remote", "origin", "refs/heads/main"])?
            .split_whitespace()
            .next()
            == Some(&parent),
        "remote parent changed; reachable history review required"
    );
    git(root, &["diff", "--check"])?;
    let mut add = vec!["add", "--"];
    add.extend(selection.files.iter().map(String::as_str));
    git(root, &add)?;
    let staged = git_text(root, &["diff", "--cached", "--name-only"])?;
    ensure!(
        staged.lines().collect::<std::collections::BTreeSet<_>>()
            == selection.files.iter().map(String::as_str).collect(),
        "exact staged selection differs"
    );
    git(root, &["diff", "--cached", "--check"])?;
    for item in &reviewed {
        match &item.sha256 {
            Some(expected) => ensure!(
                sha(&git(root, &["show", &format!(":{}", item.path)])?) == *expected,
                "staged bytes differ"
            ),
            None => ensure!(
                !git_text(root, &["ls-files", "--", &item.path])?.contains(&item.path),
                "deleted entry remains staged"
            ),
        }
    }
    fs::write(
        receipts.join("publication-review.json"),
        serde_json::to_vec_pretty(
            &json!({"parent":parent,"files":reviewed,"human_review_required":true}),
        )?,
    )?;
    git(root, &["commit", "-m", message])?;
    let commit = git_text(root, &["rev-parse", "HEAD"])?;
    let tree = git_text(root, &["rev-parse", "HEAD^{tree}"])?;
    ensure!(
        git_text(root, &["rev-parse", "HEAD^"])? == parent,
        "unexpected publication parent"
    );
    for item in &reviewed {
        if let Some(expected) = &item.sha256 {
            ensure!(
                sha(&git(root, &["show", &format!("{commit}:{}", item.path)])?) == *expected,
                "committed bytes differ"
            );
        }
    }
    git(
        root,
        &[
            "-c",
            "push.followTags=false",
            "-c",
            "remote.origin.mirror=false",
            "push",
            "origin",
            &format!("{commit}:refs/heads/main"),
        ],
    )?;
    ensure!(
        git_text(root, &["ls-remote", "origin", "refs/heads/main"])?
            .split_whitespace()
            .next()
            == Some(&commit),
        "actual remote commit differs"
    );
    let remote = Command::new("gh")
        .args([
            "api",
            &format!("repos/RunlaiDeng/rldcoin/git/commits/{commit}"),
        ])
        .output()?;
    ensure!(
        remote.status.success(),
        "remote tree inspection failed after push"
    );
    let remote: Value = serde_json::from_slice(&remote.stdout)?;
    ensure!(
        remote["sha"] == commit && remote["tree"]["sha"] == tree,
        "actual remote tree differs"
    );
    let runs = Command::new("gh")
        .args([
            "api",
            &format!("repos/RunlaiDeng/rldcoin/actions/runs?head_sha={commit}"),
        ])
        .output()?;
    ensure!(
        runs.status.success(),
        "CI inspection unavailable after push"
    );
    let runs: Value = serde_json::from_slice(&runs.stdout)?;
    let result = json!({"commit":commit,"tree":tree,"remote_exact":true,"CI_total_count":runs["total_count"],"CI_runs":runs["workflow_runs"]});
    fs::write(
        receipts.join("push-outcome.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

#[path = "../public_carriage.rs"]
mod carriage;
#[path = "../maintenance_evidence.rs"]
mod evidence;
fn main() -> Result<()> {
    let args = Args::parse();
    let value = match args.action {
        Action::Review { root, selection } => {
            let root = root.canonicalize()?;
            let selection: Selection = serde_json::from_slice(&fs::read(selection)?)?;
            json!({"reviewed":review(&root,&selection)?})
        }
        Action::ScanDocuments { root } => {
            scan(&root.canonicalize()?)?;
            json!({"public_documents_checked":true})
        }
        Action::CheckRustOnly { root } => {
            rust_only(&root.canonicalize()?)?;
            json!({"python_source_and_runtime_entries":0,"rust_only":true})
        }
        Action::Publish {
            root,
            selection,
            message,
            receipt_directory,
        } => publish(
            &root.canonicalize()?,
            &serde_json::from_slice(&fs::read(selection)?)?,
            &message,
            &receipt_directory,
        )?,
        Action::ImplementationSource {
            root,
            manifest,
            expected_commitment,
        } => {
            let (actual, _) = source_identity::capture(&root)?;
            let actual = serde_json::to_value(actual)?;
            let expected: Value = serde_json::from_slice(&fs::read(manifest)?)?;
            ensure!(
                actual == expected && actual["commitment"] == expected_commitment,
                "implementation source or separately retained commitment differs"
            );
            json!({"result":"MATCH","commitment":expected_commitment,"binary_attested":false,"upgrade_authorized":false})
        }
        Action::Snapshot { action } => match action {
            SnapshotAction::Create { root, output } => evidence::snapshot(&root, &output)?,
            SnapshotAction::Verify {
                snapshot,
                manifest_sha256,
            } => evidence::verify(&snapshot, &manifest_sha256)?,
        },
        Action::CargoSbom {
            metadata,
            lock,
            source_commit,
            source_tree_sha256,
            output,
        } => evidence::sbom(
            &metadata,
            &lock,
            &source_commit,
            &source_tree_sha256,
            &output,
        )?,
        Action::PqSpool {
            root,
            expected_root,
            action,
        } => carriage::run(&root, &expected_root, action)?,
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_contracts_allowed_internal_runs_and_private_fields_refuse() {
        for text in [
            "At most 64 checkpoints and 256 blocks; finite fixture only.",
            "RLD-CONTACT-TCP-V4 pins TLS identities.",
        ] {
            prose(text).unwrap();
        }
        for text in [
            "PASS12.300 seconds",
            "V123 PASS full test",
            "next experiment decides",
            "/Users/operator/private/state",
        ] {
            assert!(prose(text).is_err());
        }
        assert!(json_public(&json!({"private_key":"hidden"})).is_err());
        assert!(json_public(&json!({"duration_seconds":12})).is_err());
        assert!(json_public(&json!({"fixture_only":true,"format":"RLD-WIRE-V1"})).is_ok());
    }
    #[test]
    fn unsafe_snapshot_names_refuse() {
        for name in ["../secrets", "/private", "a//b", "a/./b", "a\\b", "a\nb"] {
            assert!(safe_name(name).is_err());
        }
        safe_name("crates/rld-core/src/lib.rs").unwrap();
    }
}
