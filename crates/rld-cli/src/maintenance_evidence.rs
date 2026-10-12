use super::*;
use std::os::unix::fs::PermissionsExt;
const SNAPSHOT: &str = "RLD-SOURCE-SNAPSHOT-V1";
const SCOPE: &str = "LOCAL_CANDIDATE_NOT_RELEASE_AUTHORIZATION";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    path: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    scope: String,
    git_commit: String,
    git_tree: String,
    tree_sha256: String,
    files: Vec<Row>,
}
fn excluded(name: &str) -> Result<()> {
    safe_name(name)?;
    ensure!(
        !name.split('/').any(|p| [
            ".git",
            "target",
            "node_modules",
            ".next",
            "__pycache__",
            "keys",
            "state",
            "logs",
            "run",
            "data",
            "m0-mainnet-data"
        ]
        .contains(&p)),
        "private/cache source path"
    );
    let path = Path::new(name);
    let base = path
        .file_name()
        .context("source filename")?
        .to_string_lossy();
    ensure!(
        !base.starts_with(".env")
            && !(base.starts_with("wallet") && path.extension().is_some_and(|v| v == "json"))
            && !["pem", "key", "p12", "pfx", "py", "pyc", "pyo", "log", "sqlite"]
                .contains(&path.extension().and_then(|v| v.to_str()).unwrap_or("")),
        "sensitive source file"
    );
    Ok(())
}
fn canonical_line<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut raw = canonical(value)?;
    raw.push(b'\n');
    Ok(raw)
}
fn private_material(raw: &[u8]) -> Result<()> {
    let text = String::from_utf8_lossy(raw);
    code_secrets(&text)?;
    ensure!(!Regex::new(r#""(?:secret_key|private_key|mnemonic|seed_phrase|password|api_key)"\s*:\s*"[^"\n]{8,}""#)?.is_match(&text),"generated private material in source snapshot");
    Ok(())
}
fn durable(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    Ok(())
}
pub(super) fn snapshot(root: &Path, output: &Path) -> Result<Value> {
    let root = root.canonicalize()?;
    ensure!(
        fs::symlink_metadata(output).is_err(),
        "refusing to overwrite source snapshot"
    );
    let raw = git(
        &root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    let mut names = raw
        .split(|v| *v == 0)
        .filter(|v| !v.is_empty())
        .map(|v| String::from_utf8(v.to_vec()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    names.retain(|name| root.join(name).exists());
    names.sort();
    names.dedup();
    ensure!(names.len() <= 10_000, "source file count exceeds bound");
    for name in &names {
        excluded(name)?;
        regular(&root, name)?;
    }
    fs::create_dir(output)?;
    durable(
        &output.join("CREATING"),
        b"Incomplete source snapshot; no release authority\n",
    )?;
    fs::create_dir(output.join("tree"))?;
    let mut rows = Vec::new();
    let mut total = 0u64;
    for name in names {
        let path = regular(&root, &name)?;
        let metadata = fs::metadata(&path)?;
        ensure!(
            metadata.len() <= 256 * 1024 * 1024,
            "source file exceeds byte bound"
        );
        let raw = fs::read(&path)?;
        private_material(&raw)?;
        total = total
            .checked_add(raw.len() as u64)
            .context("source size overflow")?;
        ensure!(
            total <= 512 * 1024 * 1024,
            "source total exceeds byte bound"
        );
        let target = output.join("tree").join(&name);
        fs::create_dir_all(target.parent().context("source target parent")?)?;
        durable(&target, &raw)?;
        let mode = if metadata.permissions().mode() & 0o111 != 0 {
            "0755"
        } else {
            "0644"
        };
        fs::set_permissions(
            &target,
            fs::Permissions::from_mode(if mode == "0755" { 0o755 } else { 0o644 }),
        )?;
        File::open(&target)?.sync_all()?;
        rows.push(Row {
            path: name,
            sha256: sha(&raw),
            size_bytes: raw.len() as u64,
            mode: mode.into(),
        });
    }
    let manifest = Manifest {
        format: SNAPSHOT.into(),
        scope: SCOPE.into(),
        git_commit: git_text(&root, &["rev-parse", "HEAD"])?,
        git_tree: if git_text(
            &root,
            &["status", "--porcelain", "--untracked-files=normal"],
        )?
        .is_empty()
        {
            "CLEAN".into()
        } else {
            "DIRTY".into()
        },
        tree_sha256: sha(&canonical_line(&rows)?),
        files: rows,
    };
    let raw = canonical_line(&manifest)?;
    ensure!(raw.len() <= 4 * 1024 * 1024, "snapshot manifest byte bound");
    durable(&output.join("manifest.json"), &raw)?;
    verify_inner(output, &sha(&raw), true)?;
    let mut directories = vec![output.to_path_buf()];
    let mut cursor = 0;
    while cursor < directories.len() {
        for entry in fs::read_dir(&directories[cursor])? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.is_dir() {
                directories.push(path);
            }
        }
        cursor += 1;
    }
    for directory in directories.iter().rev() {
        File::open(directory)?.sync_all()?;
    }
    fs::remove_file(output.join("CREATING"))?;
    File::open(output)?.sync_all()?;
    File::open(output.parent().context("snapshot parent")?)?.sync_all()?;
    verify(output, &sha(&raw))
}
pub(super) fn verify(snapshot: &Path, pin: &str) -> Result<Value> {
    verify_inner(snapshot, pin, false)
}
fn verify_inner(snapshot: &Path, pin: &str, creating: bool) -> Result<Value> {
    ensure!(
        pin.len() == 64
            && pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "snapshot requires independent lowercase SHA256"
    );
    ensure!(
        creating || !snapshot.join("CREATING").exists(),
        "incomplete source snapshot refuses"
    );
    let path = regular(snapshot, "manifest.json")?;
    ensure!(
        fs::metadata(&path)?.len() <= 4 * 1024 * 1024,
        "snapshot manifest byte bound"
    );
    let raw = fs::read(path)?;
    ensure!(
        sha(&raw) == pin,
        "snapshot manifest differs from independent pin"
    );
    let document: Manifest = serde_json::from_slice(&raw)?;
    ensure!(
        document.format == SNAPSHOT
            && document.scope == SCOPE
            && canonical_line(&document)? == raw
            && document.files.len() <= 10_000
            && document.tree_sha256 == sha(&canonical_line(&document.files)?),
        "snapshot manifest canonical scope/inventory differs"
    );
    let mut total = 0u64;
    let mut last = None;
    for row in &document.files {
        excluded(&row.path)?;
        ensure!(
            last.is_none_or(|last: &str| last < row.path.as_str()),
            "snapshot entries unordered or duplicate"
        );
        last = Some(&row.path);
        let path = regular(&snapshot.join("tree"), &row.path)?;
        let metadata = fs::metadata(&path)?;
        ensure!(
            row.size_bytes <= 256 * 1024 * 1024
                && metadata.len() == row.size_bytes
                && (row.mode == "0644" || row.mode == "0755"),
            "snapshot object bounds/mode"
        );
        ensure!(
            format!("{:04o}", metadata.permissions().mode() & 0o777) == row.mode,
            "snapshot executable mode differs"
        );
        let raw = fs::read(path)?;
        ensure!(sha(&raw) == row.sha256, "snapshot object digest differs");
        private_material(&raw)?;
        total = total
            .checked_add(raw.len() as u64)
            .context("snapshot total overflow")?;
        ensure!(total <= 512 * 1024 * 1024, "snapshot total capacity");
    }
    let mut todo = vec![snapshot.join("tree")];
    let mut actual = Vec::new();
    let mut entries = 0usize;
    while let Some(dir) = todo.pop() {
        for item in fs::read_dir(dir)? {
            let path = item?.path();
            entries += 1;
            ensure!(entries <= 20_000, "snapshot object inventory capacity");
            let meta = fs::symlink_metadata(&path)?;
            ensure!(!meta.file_type().is_symlink(), "snapshot symlink refused");
            if meta.is_dir() {
                todo.push(path);
            } else {
                ensure!(meta.is_file(), "snapshot special object refused");
                actual.push(
                    path.strip_prefix(snapshot.join("tree"))?
                        .to_str()
                        .context("snapshot UTF8 path")?
                        .to_owned(),
                );
            }
        }
    }
    actual.sort();
    ensure!(
        actual
            == document
                .files
                .iter()
                .map(|r| r.path.clone())
                .collect::<Vec<_>>(),
        "snapshot extra/missing source bytes"
    );
    for item in fs::read_dir(snapshot)? {
        let item = item?;
        ensure!(
            ["tree", "manifest.json"].contains(&item.file_name().to_string_lossy().as_ref())
                || creating && item.file_name() == "CREATING",
            "unknown snapshot root object"
        );
    }
    Ok(
        json!({"format":SNAPSHOT,"manifest_sha256":pin,"tree_sha256":document.tree_sha256,"file_count":document.files.len(),"total_bytes":total,
        "binary_attested":false,"release_authorized":false}),
    )
}

pub(super) fn sbom(
    metadata: &Path,
    lock: &Path,
    commit: &str,
    tree: &str,
    output: &Path,
) -> Result<Value> {
    for (value, size) in [(commit, 40), (tree, 64)] {
        ensure!(
            value.len() == size
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "source identity must be canonical hex"
        );
    }
    let raw = fs::read(metadata)?;
    ensure!(raw.len() <= 64 * 1024 * 1024, "Cargo metadata byte bound");
    let metadata: Value = serde_json::from_slice(&raw)?;
    let lockraw = fs::read_to_string(lock)?;
    ensure!(lockraw.len() <= 8 * 1024 * 1024, "Cargo lock byte bound");
    let field = Regex::new(r#"^(name|version|source|checksum) = "([^"\\]*)"$"#)?;
    let mut checksums = BTreeMap::new();
    let mut row = BTreeMap::new();
    for line in lockraw.lines().chain(std::iter::once("[[package]]")) {
        if line == "[[package]]" {
            if !row.is_empty() {
                let name = row.remove("name").context("lock package name")?;
                let version = row.remove("version").context("lock package version")?;
                let source = row.remove("source");
                let checksum = row.remove("checksum");
                ensure!(
                    checksums
                        .insert((name, version, source), checksum)
                        .is_none(),
                    "duplicate lock package"
                );
            }
        } else if let Some(c) = field.captures(line) {
            ensure!(
                row.insert(c[1].to_owned(), c[2].to_owned()).is_none(),
                "duplicate lock package field"
            );
        }
    }
    let packages = metadata["packages"]
        .as_array()
        .context("Cargo package inventory")?;
    ensure!(packages.len() <= 10_000, "Cargo package count bound");
    let mut ids = BTreeMap::new();
    let mut result = Vec::new();
    for package in packages {
        let id = package["id"].as_str().context("Cargo package ID")?;
        let sid = format!("SPDXRef-Crate-{}", &sha(id.as_bytes())[..24]);
        ids.insert(id.to_owned(), sid.clone());
        let name = package["name"].as_str().context("Cargo name")?;
        let version = package["version"].as_str().context("Cargo version")?;
        let source = package["source"].as_str().map(String::from);
        let checksum = checksums
            .get(&(name.into(), version.into(), source.clone()))
            .context("metadata package absent from supplied Cargo lock")?;
        let mut value = json!({"SPDXID":sid,"name":name,"versionInfo":version,"downloadLocation":if source.as_deref()==Some("registry+https://github.com/rust-lang/crates.io-index"){format!("https://crates.io/api/v1/crates/{name}/{version}/download")}else{"NOASSERTION".into()},
            "filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":package["license"].as_str().unwrap_or("NOASSERTION"),"copyrightText":"NOASSERTION",
            "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":format!("pkg:cargo/{name}@{version}")}]});
        if let Some(checksum) = checksum {
            value["checksums"] = json!([{"algorithm":"SHA256","checksumValue":checksum}]);
        }
        result.push(value);
    }
    let mut relationships = Vec::new();
    for id in metadata["workspace_members"]
        .as_array()
        .context("Cargo members")?
    {
        relationships.push(json!({"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":ids.get(id.as_str().context("Cargo member ID")?).context("missing Cargo member")?}));
    }
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .context("Cargo resolve graph")?
    {
        for dep in node["deps"].as_array().context("Cargo dependencies")? {
            relationships.push(json!({"spdxElementId":ids.get(node["id"].as_str().context("Cargo node ID")?).context("missing Cargo node")?,"relationshipType":"DEPENDS_ON",
            "relatedSpdxElement":ids.get(dep["pkg"].as_str().context("Cargo dependency ID")?).context("missing Cargo dependency")?}));
        }
    }
    let now = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()?;
    ensure!(now.status.success(), "UTC timestamp unavailable");
    let document = json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"Rldcoin Cargo resolved source inventory",
        "documentNamespace":format!("https://rldcoin.org/spdx/{commit}/{}",sha(&raw)),"creationInfo":{"created":String::from_utf8(now.stdout)?.trim(),"creators":["Tool: rld-cargo-sbom-1"]},
        "comment":format!("Source commit {commit}; source tree SHA256 {tree}. Cargo locked resolution across all targets. Not a binary linkage audit or release authorization."),
        "packages":result,"relationships":relationships});
    let raw = serde_json::to_vec_pretty(&document)?;
    durable(output, &raw)?;
    Ok(json!({"packages":result.len(),"relationships":relationships.len(),"sha256":sha(&raw)}))
}
