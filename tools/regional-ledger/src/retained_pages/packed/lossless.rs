//! Strictly bounded lossless retention of a complete original canonical pack.
//! Both complete references and the Native storage context are caller selected.
//! Recovered bytes carry no ledger/signing authority; Native replay is mandatory.
use super::*;
use miniz_oxide::{
    deflate::compress_to_vec,
    inflate::{
        core::{decompress, inflate_flags, DecompressorOxide},
        TINFLStatus,
    },
};
const DOMAIN: &[u8] = b"RLD-NATIVE-LOSSLESS-COMPLETE-PACK-CANDIDATE-V1\0";
const CODEC: u8 = 1; // miniz_oxide0.8.9, raw DEFLATE, fixed level6.
const LEVEL: u8 = 6;

pub struct VerifiedLosslessPackCandidate {
    pub original_pack: Vec<u8>,
    pub complete: VerifiedPagePackCandidateV1,
}
fn reference(raw: &[u8]) -> Reference {
    Reference {
        hash: Hash(Sha256::digest(raw).into()),
        bytes: raw.len(),
    }
}
fn decoded_bound(original: &Reference) -> Result<()> {
    require(
        original.bytes > 0 && original.bytes <= MAX_BYTES,
        "lossless independently decoded object byte bound",
    )
}
fn frame(original: &Reference, compressed: &[u8]) -> Result<Vec<u8>> {
    decoded_bound(original)?;
    let size = DOMAIN
        .len()
        .checked_add(1 + 4 + 32)
        .and_then(|n| n.checked_add(compressed.len()))
        .ok_or("lossless encoded length overflow")?;
    require(size <= MAX_BYTES, "lossless encoded object byte bound")?;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(DOMAIN);
    out.push(CODEC);
    out.extend_from_slice(&(original.bytes as u32).to_be_bytes());
    out.extend_from_slice(&original.hash.0);
    out.extend_from_slice(compressed);
    Ok(out)
}
/// The complete original typed pack verifies before encoding; no disk mutation.
pub fn encode_lossless_complete_pack_candidate<T: Serialize + DeserializeOwned>(
    context: &PackedPageContextCandidateV1,
    independently_original: &Reference,
    original: &[u8],
) -> Result<(Reference, Vec<u8>)> {
    decoded_bound(independently_original)?;
    verify_complete_page_pack_candidate::<T>(context, independently_original, original)?;
    let raw = frame(independently_original, &compress_to_vec(original, LEVEL))?;
    Ok((reference(&raw), raw))
}
/// Authenticate the WHOLE encoded object before parsing or inflating. Allocate
/// only the caller-pinned decoded length; require exact stream consumption and
/// canonical fixed-codec bytes before the original typed Native page checks.
pub fn verify_lossless_complete_pack_candidate<T: Serialize + DeserializeOwned>(
    context: &PackedPageContextCandidateV1,
    independently_original: &Reference,
    independently_encoded: &Reference,
    encoded: &[u8],
) -> Result<VerifiedLosslessPackCandidate> {
    decoded_bound(independently_original)?;
    require(
        !encoded.is_empty()
            && encoded.len() <= MAX_BYTES
            && independently_encoded.bytes == encoded.len()
            && independently_encoded.hash == reference(encoded).hash
            && encoded.starts_with(DOMAIN),
        "lossless complete encoded reference/domain/byte bound",
    )?;
    let mut offset = DOMAIN.len();
    require(
        take(encoded, &mut offset, 1)? == [CODEC],
        "lossless unknown codec",
    )?;
    let declared = u32::from_be_bytes(take(encoded, &mut offset, 4)?.try_into().unwrap()) as usize;
    let digest = take(encoded, &mut offset, 32)?;
    require(
        declared == independently_original.bytes && digest == independently_original.hash.0,
        "lossless independent decoded reference differs",
    )?;
    let compressed = &encoded[offset..];
    let mut original = vec![0u8; independently_original.bytes];
    let mut decoder = Box::<DecompressorOxide>::default();
    let (status, consumed, produced) = decompress(
        &mut decoder,
        compressed,
        &mut original,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    require(
        status == TINFLStatus::Done && consumed == compressed.len() && produced == original.len(),
        "lossless exact bounded decode length/stream",
    )?;
    require(
        reference(&original) == *independently_original,
        "lossless original complete digest differs",
    )?;
    require(
        compress_to_vec(&original, LEVEL) == compressed,
        "lossless noncanonical compressed stream",
    )?;
    let complete =
        verify_complete_page_pack_candidate::<T>(context, independently_original, &original)?;
    Ok(VerifiedLosslessPackCandidate {
        original_pack: original,
        complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> PackedPageContextCandidateV1 {
        PackedPageContextCandidateV1 {
            scope: Scope {
                implementation: crate::implementation().unwrap(),
                currency: Hash([1; 32]),
                region: Hash([2; 32]),
                admission: Hash([3; 32]),
                purpose: super::super::super::Purpose::Ledger,
                origin: Hash([4; 32]),
            },
            first_record: 0,
            previous_page: None,
            previous_pack: None,
        }
    }
    fn original() -> (PackedPageContextCandidateV1, Reference, Vec<u8>) {
        let context = context();
        let mut previous = None;
        let mut pages = vec![];
        for i in 0..MAX_PACKED_PAGES_CANDIDATE {
            let first = (i * PAGE) as u64;
            let raw = serde_json::to_vec(&Page {
                format: FORMAT.into(),
                scope: context.scope.clone(),
                first,
                previous,
                records: (first..first + PAGE as u64).collect::<Vec<_>>(),
            })
            .unwrap();
            previous = Some(reference(&raw).hash);
            pages.push(raw);
        }
        let (r, raw) = encode_complete_page_pack_candidate::<u64>(
            &context,
            &pages.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
        (context, r, raw)
    }
    #[test]
    fn complete64_pages_recover_every_original_byte_under_independent_references() {
        let (ctx, inner, raw) = original();
        let (outer, wire) =
            encode_lossless_complete_pack_candidate::<u64>(&ctx, &inner, &raw).unwrap();
        let decoded =
            verify_lossless_complete_pack_candidate::<u64>(&ctx, &inner, &outer, &wire).unwrap();
        assert_eq!(decoded.original_pack, raw);
        assert_eq!(decoded.complete.next_record, 1024);
        assert_eq!(decoded.complete.complete_pages.len(), 64);
        assert!(wire.len() < raw.len());
        let mut other = ctx.clone();
        other.scope.currency = Hash([9; 32]);
        assert!(
            verify_lossless_complete_pack_candidate::<u64>(&other, &inner, &outer, &wire).is_err()
        );
        let mut badinner = inner.clone();
        badinner.hash = Hash([9; 32]);
        assert!(
            verify_lossless_complete_pack_candidate::<u64>(&ctx, &badinner, &outer, &wire).is_err()
        );
        let mut badouter = outer.clone();
        badouter.hash = Hash([9; 32]);
        assert!(
            verify_lossless_complete_pack_candidate::<u64>(&ctx, &inner, &badouter, &wire).is_err()
        );
    }
    #[test]
    fn authenticated_truncation_trailing_unknown_codec_and_alternate_deflate_refuse() {
        let (ctx, inner, raw) = original();
        let (_, wire) = encode_lossless_complete_pack_candidate::<u64>(&ctx, &inner, &raw).unwrap();
        let mut trailing = wire.clone();
        trailing.push(0);
        let mut codec = wire.clone();
        codec[DOMAIN.len()] = 2;
        let mut domain = wire.clone();
        domain[0] ^= 1;
        let alternate = frame(&inner, &compress_to_vec(&raw, 0)).unwrap();
        for malformed in [
            wire[..wire.len() - 1].to_vec(),
            trailing,
            codec,
            domain,
            alternate,
        ] {
            assert!(verify_lossless_complete_pack_candidate::<u64>(
                &ctx,
                &inner,
                &reference(&malformed),
                &malformed
            )
            .is_err());
        }
    }
    #[test]
    fn expansion_over_caller_length_or_original8mib_refuses_without_partial_bytes() {
        let ctx = context();
        let large = vec![0u8; MAX_BYTES + 1];
        let compressed = compress_to_vec(&large, LEVEL);
        let small = Reference {
            hash: Hash([8; 32]),
            bytes: 16,
        };
        let wire = frame(&small, &compressed).unwrap();
        let err =
            verify_lossless_complete_pack_candidate::<u64>(&ctx, &small, &reference(&wire), &wire)
                .err()
                .unwrap();
        assert_eq!(err, "lossless exact bounded decode length/stream");
        let oversized = Reference {
            hash: reference(&large).hash,
            bytes: large.len(),
        };
        assert!(encode_lossless_complete_pack_candidate::<u64>(&ctx, &oversized, &large).is_err());
        assert!(verify_lossless_complete_pack_candidate::<u64>(
            &ctx,
            &oversized,
            &reference(&wire),
            &wire
        )
        .is_err());
        let (_, mut inner, raw) = original();
        inner.bytes -= 1;
        assert!(encode_lossless_complete_pack_candidate::<u64>(&ctx, &inner, &raw).is_err());
    }
}
