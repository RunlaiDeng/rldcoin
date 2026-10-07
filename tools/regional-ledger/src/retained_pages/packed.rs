//! Bounded complete-page packing candidate; it grants no Native authority.
//! Flat streams retain their exact format and limits. A future signed storage
//! profile must select this representation and still replay every original
//! typed record. Hashes cannot initialize a ledger, signer lock or latest head.
use super::{decode, Page, Scope, FORMAT, PAGE};
use crate::{history::Reference, require, Hash, Result, MAX_BYTES};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_PACKED_PAGES_CANDIDATE: usize = 64;
const DOMAIN: &[u8] = b"RLD-NATIVE-COMPLETE-PAGE-PACK-CANDIDATE-V1\0";

/// Selected independently by the full replay caller, never learned from a pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedPageContextCandidateV1 {
    pub scope: Scope,
    pub first_record: u64,
    pub previous_page: Option<Hash>,
    pub previous_pack: Option<Hash>,
}
impl PackedPageContextCandidateV1 {
    fn check(&self) -> Result<()> {
        require(
            self.first_record.is_multiple_of(PAGE as u64)
                && self.previous_page.is_some() == (self.first_record != 0)
                && self.previous_pack.is_some() == (self.first_record != 0),
            "packed complete page initial offset/predecessors",
        )
    }
    fn scope_hash(&self) -> Result<Hash> {
        crate::id("complete-page-pack-candidate-scope-v1", &self.scope)
    }
}

/// Integrity description only, not Native replay, signing or storage adoption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPagePackCandidateV1 {
    pub first_record: u64,
    pub next_record: u64,
    pub complete_pages: Vec<Reference>,
    pub last_page: Hash,
}
fn optional(output: &mut Vec<u8>, value: Option<Hash>) {
    output.push(u8::from(value.is_some()));
    if let Some(hash) = value {
        output.extend_from_slice(&hash.0);
    }
}
fn header(context: &PackedPageContextCandidateV1, count: usize) -> Result<Vec<u8>> {
    context.check()?;
    require(
        count > 0 && count <= MAX_PACKED_PAGES_CANDIDATE,
        "packed complete page count bound",
    )?;
    let mut raw = DOMAIN.to_vec();
    raw.extend_from_slice(&context.scope_hash()?.0);
    raw.extend_from_slice(&context.first_record.to_be_bytes());
    optional(&mut raw, context.previous_pack);
    optional(&mut raw, context.previous_page);
    raw.extend_from_slice(&(count as u16).to_be_bytes());
    Ok(raw)
}
fn checked_pages<T: Serialize + DeserializeOwned>(
    context: &PackedPageContextCandidateV1,
    pages: &[&[u8]],
) -> Result<VerifiedPagePackCandidateV1> {
    context.check()?;
    require(
        !pages.is_empty() && pages.len() <= MAX_PACKED_PAGES_CANDIDATE,
        "packed complete page count bound",
    )?;
    let mut next_record = context.first_record;
    let mut previous = context.previous_page;
    let mut references = Vec::with_capacity(pages.len());
    for raw in pages {
        require(
            !raw.is_empty() && raw.len() <= MAX_BYTES,
            "packed original complete page byte bound",
        )?;
        let page: Page<T> = decode(raw)?;
        require(
            page.format == FORMAT
                && page.scope == context.scope
                && page.first == next_record
                && page.previous == previous
                && page.records.len() == PAGE,
            "packed original complete page domain/order/predecessor/record count",
        )?;
        next_record = next_record
            .checked_add(PAGE as u64)
            .ok_or("packed complete record counter overflow")?;
        let hash = Hash(Sha256::digest(raw).into());
        references.push(Reference {
            hash,
            bytes: raw.len(),
        });
        previous = Some(hash);
    }
    Ok(VerifiedPagePackCandidateV1 {
        first_record: context.first_record,
        next_record,
        complete_pages: references,
        last_page: previous.ok_or("packed complete final page missing")?,
    })
}

/// Preserve exact complete canonical page bytes; never a prefix, cache or summary.
/// All count/byte/typed checks precede the returned object. No disk writes occur.
pub fn encode_complete_page_pack_candidate<T: Serialize + DeserializeOwned>(
    context: &PackedPageContextCandidateV1,
    pages: &[&[u8]],
) -> Result<(Reference, Vec<u8>)> {
    let mut raw = header(context, pages.len())?;
    let mut total = raw.len();
    for page in pages {
        total = total
            .checked_add(4)
            .and_then(|n| n.checked_add(page.len()))
            .ok_or("packed complete byte length overflow")?;
        require(total <= MAX_BYTES, "packed complete object byte capacity")?;
    }
    checked_pages::<T>(context, pages)?;
    raw.reserve(total - raw.len());
    for page in pages {
        raw.extend_from_slice(&(page.len() as u32).to_be_bytes());
        raw.extend_from_slice(page);
    }
    Ok((
        Reference {
            hash: Hash(Sha256::digest(&raw).into()),
            bytes: raw.len(),
        },
        raw,
    ))
}
fn take<'a>(raw: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(n).ok_or("packed byte offset overflow")?;
    let value = raw
        .get(*offset..end)
        .ok_or("packed complete object truncated")?;
    *offset = end;
    Ok(value)
}
fn read_optional(raw: &[u8], offset: &mut usize) -> Result<Option<Hash>> {
    match take(raw, offset, 1)?[0] {
        0 => Ok(None),
        1 => Ok(Some(Hash(take(raw, offset, 32)?.try_into().unwrap()))),
        _ => Err("packed noncanonical optional predecessor".into()),
    }
}

/// Check the independently retained complete object reference before decoding.
/// A peer-supplied hash is not a current anchor. Result authenticates integrity
/// only; every decoded record still requires complete Native semantic replay.
pub fn verify_complete_page_pack_candidate<T: Serialize + DeserializeOwned>(
    context: &PackedPageContextCandidateV1,
    independently_expected: &Reference,
    raw: &[u8],
) -> Result<VerifiedPagePackCandidateV1> {
    context.check()?;
    require(
        !raw.is_empty()
            && raw.len() <= MAX_BYTES
            && independently_expected.bytes == raw.len()
            && independently_expected.hash == Hash(Sha256::digest(raw).into())
            && raw.starts_with(DOMAIN),
        "packed complete object independent reference/domain/byte bound",
    )?;
    let mut offset = DOMAIN.len();
    require(
        take(raw, &mut offset, 32)? == context.scope_hash()?.0,
        "packed complete object independent scope",
    )?;
    let first = u64::from_be_bytes(take(raw, &mut offset, 8)?.try_into().unwrap());
    let previous_pack = read_optional(raw, &mut offset)?;
    let previous_page = read_optional(raw, &mut offset)?;
    require(
        first == context.first_record
            && previous_pack == context.previous_pack
            && previous_page == context.previous_page,
        "packed complete object independent offset/predecessors",
    )?;
    let count = u16::from_be_bytes(take(raw, &mut offset, 2)?.try_into().unwrap()) as usize;
    require(
        count > 0 && count <= MAX_PACKED_PAGES_CANDIDATE,
        "packed complete page count bound",
    )?;
    let mut pages = Vec::with_capacity(count);
    for _ in 0..count {
        let n = u32::from_be_bytes(take(raw, &mut offset, 4)?.try_into().unwrap()) as usize;
        require(
            n > 0 && n <= MAX_BYTES,
            "packed original complete page byte bound",
        )?;
        pages.push(take(raw, &mut offset, n)?);
    }
    require(offset == raw.len(), "packed complete object trailing bytes")?;
    checked_pages::<T>(context, &pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(first: u64) -> PackedPageContextCandidateV1 {
        PackedPageContextCandidateV1 {
            scope: Scope {
                implementation: crate::implementation().unwrap(),
                currency: Hash([1; 32]),
                region: Hash([2; 32]),
                admission: Hash([3; 32]),
                purpose: super::super::Purpose::Ledger,
                origin: Hash([4; 32]),
            },
            first_record: first,
            previous_page: (first != 0).then_some(Hash([5; 32])),
            previous_pack: (first != 0).then_some(Hash([6; 32])),
        }
    }
    fn pages(context: &PackedPageContextCandidateV1, n: usize) -> Vec<Vec<u8>> {
        let mut previous = context.previous_page;
        (0..n)
            .map(|i| {
                let first = context.first_record + (i * PAGE) as u64;
                let page = Page {
                    format: FORMAT.into(),
                    scope: context.scope.clone(),
                    first,
                    previous,
                    records: (first..first + PAGE as u64).collect::<Vec<_>>(),
                };
                let raw = super::super::bytes(&page).unwrap();
                previous = Some(Hash(Sha256::digest(&raw).into()));
                raw
            })
            .collect()
    }
    fn reference(raw: &[u8]) -> Reference {
        Reference {
            hash: Hash(Sha256::digest(raw).into()),
            bytes: raw.len(),
        }
    }
    #[test]
    fn all64_complete_original_pages_preserve_bytes_and_independent_context() {
        // Synthetic typed records only, not signed Native blocks/history.
        let c = context(4096 * PAGE as u64);
        let original = pages(&c, 64);
        let slices = original.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let (r, raw) = encode_complete_page_pack_candidate::<u64>(&c, &slices).unwrap();
        let v = verify_complete_page_pack_candidate::<u64>(&c, &r, &raw).unwrap();
        assert_eq!(v.first_record, c.first_record);
        assert_eq!(v.next_record, c.first_record + 1024);
        assert_eq!(v.complete_pages.len(), 64);
        for (p, r) in original.iter().zip(v.complete_pages) {
            assert_eq!(r, reference(p));
        }
        assert_eq!(original, pages(&c, 64));
        assert!(raw.len() < MAX_BYTES);
    }
    #[test]
    fn count_scope_current_reference_order_and_corrupt_complete_page_refuse() {
        let c = context(0);
        let original = pages(&c, 3);
        let slices = original.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let (r, raw) = encode_complete_page_pack_candidate::<u64>(&c, &slices).unwrap();
        for changed in [&raw[..raw.len() - 1], b"wrong".as_slice()] {
            assert!(verify_complete_page_pack_candidate::<u64>(&c, &r, changed).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(
            verify_complete_page_pack_candidate::<u64>(&c, &reference(&trailing), &trailing)
                .is_err()
        );
        let mut other = c.clone();
        other.scope.region = Hash([8; 32]);
        assert!(verify_complete_page_pack_candidate::<u64>(&other, &r, &raw).is_err());
        other = c.clone();
        other.previous_pack = Some(Hash([8; 32]));
        assert!(verify_complete_page_pack_candidate::<u64>(&other, &r, &raw).is_err());
        let mut reordered = slices.clone();
        reordered.swap(0, 1);
        assert!(encode_complete_page_pack_candidate::<u64>(&c, &reordered).is_err());
        assert!(encode_complete_page_pack_candidate::<u64>(&c, &vec![slices[0]; 65]).is_err());
        let mut bad: Page<u64> = decode(&original[1]).unwrap();
        bad.previous = Some(Hash([8; 32]));
        let changed = super::super::bytes(&bad).unwrap();
        assert!(
            encode_complete_page_pack_candidate::<u64>(&c, &[slices[0], &changed, slices[2]])
                .is_err()
        );
        bad = decode(&original[1]).unwrap();
        bad.records.pop();
        let changed = super::super::bytes(&bad).unwrap();
        assert!(encode_complete_page_pack_candidate::<u64>(&c, &[slices[0], &changed]).is_err());
        // Correct outer hash cannot hide a malformed/oversized typed page.
        let mut malformed = header(&c, 1).unwrap();
        malformed.extend_from_slice(&2u32.to_be_bytes());
        malformed.extend_from_slice(b"{}");
        assert!(
            verify_complete_page_pack_candidate::<u64>(&c, &reference(&malformed), &malformed)
                .is_err()
        );
        let mut unknown = raw.clone();
        unknown[DOMAIN.len() + 32 + 8] = 2;
        assert!(
            verify_complete_page_pack_candidate::<u64>(&c, &reference(&unknown), &unknown).is_err()
        );
    }
    #[test]
    fn byte_capacity_counter_overflow_and_empty_pack_refuse_without_result() {
        let c = context(0);
        assert!(encode_complete_page_pack_candidate::<u64>(&c, &[]).is_err());
        let mut records = vec![String::new(); PAGE];
        records[0] = "x".repeat(MAX_BYTES / 2);
        let first = super::super::bytes(&Page {
            format: FORMAT.into(),
            scope: c.scope.clone(),
            first: 0,
            previous: None,
            records: records.clone(),
        })
        .unwrap();
        let second = super::super::bytes(&Page {
            format: FORMAT.into(),
            scope: c.scope.clone(),
            first: PAGE as u64,
            previous: Some(reference(&first).hash),
            records,
        })
        .unwrap();
        assert!(first.len() < MAX_BYTES && second.len() < MAX_BYTES);
        assert!(encode_complete_page_pack_candidate::<String>(&c, &[&first, &second]).is_err());
        let original = pages(&c, 1);
        let mut near = context(u64::MAX - 15);
        near.first_record = u64::MAX - 15;
        let raw = super::super::bytes(&Page {
            format: FORMAT.into(),
            scope: near.scope.clone(),
            first: near.first_record,
            previous: near.previous_page,
            records: vec![0u64; PAGE],
        })
        .unwrap();
        assert!(encode_complete_page_pack_candidate::<u64>(&near, &[&raw]).is_err());
        assert_eq!(pages(&c, 1), original);
    }
}

/// Fresh immutable archive candidate; existing Native stores do not adopt it.
pub mod archive;

/// Separate bounded lossless byte representation; existing archives do not adopt it.
pub mod lossless;
