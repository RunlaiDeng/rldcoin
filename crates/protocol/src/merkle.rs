use crate::codec::{Id, hash};
use crate::record;
use anyhow::{Result, ensure};

record!(Entry {key:Id  =>  0,value:Id  =>  1});
record!(Path {index:u64  =>  0,count:u64  =>  1,siblings:Vec<Id>  =>  2});
record!(Membership {entry:Entry  =>  0,path:Path  =>  1});
record!(Absence {left:Option<Membership>  =>  0,right:Option<Membership>  =>  1,count:u64  =>  2});

fn split(n: usize) -> usize {
    1usize << ((usize::BITS - 1) - (n - 1).leading_zeros())
}
fn leaf(c: Id, tag: &str, e: &Entry) -> Id {
    hash("RLD-MAP-LEAF", c, &(tag, e))
}
fn node(c: Id, tag: &str, a: Id, b: Id) -> Id {
    hash("RLD-MAP-NODE", c, &(tag, a, b))
}
fn tree(c: Id, tag: &str, entries: &[Entry]) -> Id {
    match entries.len() {
        0 => hash("RLD-MAP-EMPTY", c, &tag),
        1 => leaf(c, tag, &entries[0]),
        n => {
            let m = split(n);
            node(
                c,
                tag,
                tree(c, tag, &entries[..m]),
                tree(c, tag, &entries[m..]),
            )
        }
    }
}
pub fn root(c: Id, tag: &str, entries: &[Entry]) -> Result<Id> {
    ensure!(
        entries.windows(2).all(|w| w[0].key < w[1].key),
        "map order/duplicate"
    );
    Ok(hash(
        "RLD-MAP-ROOT",
        c,
        &(tag, entries.len() as u64, tree(c, tag, entries)),
    ))
}
pub fn prove(c: Id, tag: &str, entries: &[Entry], index: usize) -> Result<Membership> {
    root(c, tag, entries)?;
    ensure!(index < entries.len(), "map index");
    fn walk(c: Id, tag: &str, e: &[Entry], i: usize, out: &mut Vec<Id>) {
        if e.len() == 1 {
            return;
        }
        let m = split(e.len());
        if i < m {
            walk(c, tag, &e[..m], i, out);
            out.push(tree(c, tag, &e[m..]));
        } else {
            walk(c, tag, &e[m..], i - m, out);
            out.push(tree(c, tag, &e[..m]));
        }
    }
    let mut siblings = Vec::new();
    walk(c, tag, entries, index, &mut siblings);
    Ok(Membership {
        entry: entries[index].clone(),
        path: Path {
            index: index as u64,
            count: entries.len() as u64,
            siblings,
        },
    })
}
pub fn verify(c: Id, tag: &str, expected: Id, proof: &Membership) -> Result<()> {
    ensure!(
        proof.path.count > 0
            && proof.path.index < proof.path.count
            && proof.path.siblings.len() <= 64,
        "map path bounds"
    );
    fn walk(
        c: Id,
        tag: &str,
        n: usize,
        i: usize,
        base: Id,
        s: &[Id],
        cursor: &mut usize,
    ) -> Result<Id> {
        if n == 1 {
            return Ok(base);
        }
        let m = split(n);
        let inside = walk(
            c,
            tag,
            if i < m { m } else { n - m },
            if i < m { i } else { i - m },
            base,
            s,
            cursor,
        )?;
        let side = *s
            .get(*cursor)
            .ok_or_else(|| anyhow::anyhow!("short path"))?;
        *cursor += 1;
        Ok(if i < m {
            node(c, tag, inside, side)
        } else {
            node(c, tag, side, inside)
        })
    }
    let mut cursor = 0;
    let t = walk(
        c,
        tag,
        usize::try_from(proof.path.count)?,
        usize::try_from(proof.path.index)?,
        leaf(c, tag, &proof.entry),
        &proof.path.siblings,
        &mut cursor,
    )?;
    ensure!(
        cursor == proof.path.siblings.len()
            && hash("RLD-MAP-ROOT", c, &(tag, proof.path.count, t)) == expected,
        "map proof mismatch"
    );
    Ok(())
}
pub fn verify_absent(c: Id, tag: &str, expected: Id, key: Id, p: &Absence) -> Result<()> {
    if p.count == 0 {
        ensure!(
            p.left.is_none() && p.right.is_none() && root(c, tag, &[])? == expected,
            "empty absence"
        );
        return Ok(());
    }
    for member in [&p.left, &p.right].into_iter().flatten() {
        ensure!(member.path.count == p.count, "absence count");
        verify(c, tag, expected, member)?;
    }
    match (&p.left, &p.right) {
        (Some(l), Some(r)) => ensure!(
            l.entry.key < key
                && key < r.entry.key
                && l.path.index.checked_add(1) == Some(r.path.index),
            "absence neighbors"
        ),
        (None, Some(r)) => ensure!(r.path.index == 0 && key < r.entry.key, "absence first"),
        (Some(l), None) => ensure!(
            l.path.index.checked_add(1) == Some(p.count) && l.entry.key < key,
            "absence last"
        ),
        _ => anyhow::bail!("missing absence witnesses"),
    };
    Ok(())
}
