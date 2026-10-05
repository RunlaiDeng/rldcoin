use anyhow::{ensure, Result};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
// Fault injection exists only in the isolated test executable. It is scoped to
// one path and one thread so parallel tests cannot affect another wallet.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteBoundary {
    Created,
    PartialWrite,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}
#[cfg(test)]
thread_local! {
    static FAILURE: std::cell::RefCell<Option<(std::path::PathBuf, WriteBoundary)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub fn fail_next_atomic(path: &Path, boundary: WriteBoundary) {
    FAILURE.with(|f| {
        assert!(f.borrow().is_none(), "unconsumed atomic failure");
        *f.borrow_mut() = Some((path.to_owned(), boundary));
    });
}
#[cfg(test)]
fn checkpoint(path: &Path, boundary: WriteBoundary) -> Result<()> {
    FAILURE.with(|f| {
        let mut f = f.borrow_mut();
        if f.as_ref().is_some_and(|(p, b)| p == path && *b == boundary) {
            f.take();
            anyhow::bail!("isolated injected atomic failure: {boundary:?}");
        }
        Ok(())
    })
}
pub fn directory(path: &Path) -> Result<()> {
    if path.exists() {
        let m = fs::symlink_metadata(path)?;
        ensure!(m.is_dir() && !m.file_type().is_symlink(), "目录路径不安全");
        ensure!(
            m.permissions().mode() & 0o077 == 0,
            "钱包目录必须只有本人可访问 (0700)"
        );
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && m.len() <= limit && m.nlink() == 1,
        "文件类型或大小不安全"
    );
    let mut b = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut b)?;
    ensure!(b.len() as u64 <= limit, "文件超过大小限制");
    Ok(b)
}
pub fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap();
    let pending = path.with_extension("pending");
    if pending.symlink_metadata().is_ok() {
        fs::remove_file(&pending)?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    #[cfg(test)]
    {
        checkpoint(path, WriteBoundary::Created)?;
        let middle = bytes.len() / 2;
        f.write_all(&bytes[..middle])?;
        checkpoint(path, WriteBoundary::PartialWrite)?;
        f.write_all(&bytes[middle..])?;
        checkpoint(path, WriteBoundary::Written)?;
    }
    #[cfg(not(test))]
    f.write_all(bytes)?;
    f.sync_all()?;
    #[cfg(test)]
    checkpoint(path, WriteBoundary::FileSynced)?;
    fs::rename(pending, path)?;
    #[cfg(test)]
    checkpoint(path, WriteBoundary::Renamed)?;
    File::open(parent)?.sync_all()?;
    #[cfg(test)]
    checkpoint(path, WriteBoundary::DirectorySynced)?;
    Ok(())
}
pub fn lock(path: &Path) -> Result<File> {
    if path.symlink_metadata().is_ok() {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
            "钱包锁文件不安全"
        );
    }
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    f.try_lock()
        .map_err(|_| anyhow::anyhow!("此钱包已在另一个进程中打开"))?;
    Ok(f)
}
