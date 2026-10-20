//! Canonical absent-key insertion from an authenticated ordered-neighbor path.
//! The predecessor must already be an authenticated native map with MAX_PATH.
use super::*;
#[derive(Debug)]
pub struct CompleteSubtreeRequired;
impl std::fmt::Display for CompleteSubtreeRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "compact insertion needs complete subtree height evidence; use full native witness"
        )
    }
}
impl std::error::Error for CompleteSubtreeRequired {}
fn fold(
    c: Id,
    tag: &str,
    key: Id,
    tree: Id,
    count: u64,
    depth: u8,
    sibling: Id,
    sibling_count: u64,
) -> Result<(Id, u64)> {
    let next = count
        .checked_add(sibling_count)
        .context("insertion count exhaustion")?;
    let tree = if bit(key, depth) {
        branch_hash(c, tag, depth, key, sibling, sibling_count, tree, count)
    } else {
        branch_hash(c, tag, depth, key, tree, count, sibling, sibling_count)
    };
    Ok((tree, next))
}
/// Computes the actual new root, never accepts a caller-proposed successor root.
/// Cardinality bounds the moved subtree's height without trusting cached height.
pub fn insert_absent(
    c: Id,
    tag: &str,
    expected: Id,
    entry: &Entry,
    absence: &Absence,
) -> Result<Id> {
    verify_absent(c, tag, expected, entry.key, absence)?;
    if absence.count == 0 {
        return Ok(root_hash(c, tag, 1, leaf_hash(c, tag, entry)));
    }
    let mut selected = None;
    for member in [&absence.left, &absence.right].into_iter().flatten() {
        let split = branch_depth(member.entry.key, entry.key)?;
        if selected.as_ref().is_none_or(|(_, old)| split > *old) {
            selected = Some((member, split));
        }
    }
    let (member, split) = selected.context("insertion neighbor")?;
    let path = &member.path;
    let cut = path.depths.partition_point(|d| *d < split);
    ensure!(
        path.depths.get(cut) != Some(&split),
        "absence did not locate insertion subtree"
    );
    let (mut tree, mut count) = (leaf_hash(c, tag, &member.entry), 1u64);
    for i in (cut..path.depths.len()).rev() {
        (tree, count) = fold(
            c,
            tag,
            member.entry.key,
            tree,
            count,
            path.depths[i],
            path.siblings[i],
            path.counts[i],
        )?;
    }
    // A non-unary binary subtree with n leaves has height <= n-1. Inserting
    // above it adds one fork to every moved path. Other predecessor paths are
    // unchanged and inherit their already certified <=64 bound. Refuse when
    // this conservative proof is insufficient; do not assume a short subtree.
    if u64::try_from(cut)?
        .checked_add(count)
        .is_none_or(|h| h > MAX_PATH as u64)
    {
        return Err(CompleteSubtreeRequired.into());
    }
    let leaf = leaf_hash(c, tag, entry);
    tree = if bit(entry.key, split) {
        branch_hash(c, tag, split, entry.key, tree, count, leaf, 1)
    } else {
        branch_hash(c, tag, split, entry.key, leaf, 1, tree, count)
    };
    count = count.checked_add(1).context("insertion count exhaustion")?;
    for i in (0..cut).rev() {
        ensure!(
            bit(member.entry.key, path.depths[i]) == bit(entry.key, path.depths[i]),
            "insertion ancestor direction"
        );
        (tree, count) = fold(
            c,
            tag,
            entry.key,
            tree,
            count,
            path.depths[i],
            path.siblings[i],
            path.counts[i],
        )?;
    }
    ensure!(
        absence.count.checked_add(1) == Some(count),
        "insertion total count"
    );
    Ok(root_hash(c, tag, count, tree))
}

/// Removing a verified leaf cannot increase a certified predecessor's height.
/// Collapse its first now-unary fork, then rebuild the remaining ancestors with
/// their original depths/prefixes and authenticated sibling hashes/counts.
pub fn remove_member(c: Id, tag: &str, expected: Id, member: &Membership) -> Result<Id> {
    verify(c, tag, expected, member)?;
    let p = &member.path;
    let count = p.count.checked_sub(1).context("removal cardinality")?;
    if p.depths.is_empty() {
        ensure!(count == 0, "singleton removal count");
        return root(c, tag, &[]);
    }
    let last = p.depths.len() - 1;
    let (mut tree, mut n) = (p.siblings[last], p.counts[last]);
    for i in (0..last).rev() {
        (tree, n) = fold(
            c,
            tag,
            member.entry.key,
            tree,
            n,
            p.depths[i],
            p.siblings[i],
            p.counts[i],
        )?;
    }
    ensure!(n == count, "removal total count");
    Ok(root_hash(c, tag, count, tree))
}
