//! Exact bounded RFC1950 carriage codec; neither bytes nor checksums are authority.
use crate::{
    contact_crypto::{buffer, output_with, Buffer},
    require, wallet_client, Result,
};
use miniz_oxide::{
    deflate::core::{
        compress, create_comp_flags_from_zip_params, CompressorOxide, TDEFLFlush, TDEFLStatus,
    },
    inflate::{
        core::{decompress, inflate_flags, DecompressorOxide},
        TINFLStatus,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const FORMAT: &str = "RLD-NATIVE-CONTACT-SPOOL-CODEC-V1";
const CODEC: &str = "RLD-CONTACT-SPOOL-ZLIB-V1";
const MAGIC: &[u8] = b"RLD-CONTACT-SPOOL-ZLIB-V1\0";
const HEADER: usize = MAGIC.len() + 8 + 32;
const MAX: usize = 20 * 1024 * 1024;
const CONTROL: usize = 8192;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Encode {
        limit: usize,
        size_bytes: usize,
        sha256: String,
    },
    Decode {
        limit: usize,
        size_bytes: usize,
        sha256: String,
    },
    Header {
        limit: usize,
        size_bytes: usize,
        sha256: String,
        encoded_size: usize,
    },
}
fn limit(value: usize) -> Result<()> {
    require(value > 0 && value <= MAX, "invalid spool codec limit")
}
fn expanded(header: &[u8], encoded: usize, bound: usize) -> Result<usize> {
    limit(bound)?;
    require(
        header.len() == HEADER && header.starts_with(MAGIC),
        "spool codec version/header differs",
    )?;
    require(
        encoded > HEADER && encoded <= bound,
        "encoded spool bound exceeded",
    )?;
    let size = u64::from_be_bytes(header[MAGIC.len()..MAGIC.len() + 8].try_into().unwrap());
    require(
        size > 0 && size <= bound as u64,
        "expanded spool bound exceeded",
    )?;
    Ok(size as usize)
}
struct Payload<'a> {
    bytes: &'a [u8],
    digest: [u8; 32],
}
impl<'a> Payload<'a> {
    fn checked(bytes: &'a [u8], size: usize, expected: &str) -> Result<Self> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        require(
            bytes.len() == size && hex::encode(digest) == expected,
            "native spool codec payload binding differs",
        )?;
        Ok(Self { bytes, digest })
    }
}
fn encode(payload: &Payload<'_>, bound: usize) -> Result<Vec<u8>> {
    let raw = payload.bytes;
    limit(bound)?;
    require(
        !raw.is_empty() && raw.len() <= bound,
        "expanded spool bound exceeded",
    )?;
    require(bound > HEADER, "encoded spool bound exceeded")?;
    let flags = create_comp_flags_from_zip_params(1, 15, 0);
    let mut compressor = Box::new(CompressorOxide::new(flags));
    // Exactly one refusal byte; no compression-driven unbounded vector growth.
    let mut compressed = vec![0; bound - HEADER + 1];
    let mut consumed = 0;
    let mut produced = 0;
    loop {
        let (status, input, output) = compress(
            &mut compressor,
            &raw[consumed..],
            &mut compressed[produced..],
            TDEFLFlush::Finish,
        );
        consumed += input;
        produced += output;
        require(
            consumed <= raw.len() && produced < compressed.len(),
            "encoded spool bound exceeded",
        )?;
        if status == TDEFLStatus::Done {
            require(consumed == raw.len(), "spool encoder incomplete input")?;
            break;
        }
        require(
            status == TDEFLStatus::Okay && input + output > 0,
            "spool encoder refused",
        )?;
    }
    compressed.truncate(produced);
    let mut out = Vec::with_capacity(HEADER + produced);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(raw.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload.digest);
    out.extend_from_slice(&compressed);
    require(out.len() <= bound, "encoded spool bound exceeded")?;
    Ok(out)
}
fn decode(data: &[u8], bound: usize) -> Result<(Vec<u8>, [u8; 32])> {
    let size = expanded(data.get(..HEADER).unwrap_or(&[]), data.len(), bound)?;
    let mut out = vec![0; size + 1];
    let mut decoder = Box::<DecompressorOxide>::default();
    let compressed = &data[HEADER..];
    let (status, consumed, produced) = decompress(
        &mut decoder,
        compressed,
        &mut out,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER,
    );
    require(
        status == TINFLStatus::Done && consumed == compressed.len() && produced == size,
        "incomplete or trailing spool stream",
    )?;
    out.truncate(size);
    let digest: [u8; 32] = Sha256::digest(&out).into();
    require(
        digest.as_slice() == &data[MAGIC.len() + 8..HEADER],
        "expanded spool bytes differ",
    )?;
    Ok((out, digest))
}
pub(crate) fn execute(control: &[u8], raw: &[u8]) -> Result<(Value, Vec<u8>)> {
    let value = crate::wallet_http::decode_unique_with_limit(control, CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&value, CONTROL)? == control,
        "native spool codec noncanonical control",
    )?;
    let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let (result, result_digest) = match request {
        Request::Info => {
            require(raw.is_empty(), "native spool codec unexpected payload")?;
            return Ok((
                json!({"format":FORMAT,"codec":CODEC,"max_bytes":MAX,"max_control":CONTROL,"header_size":HEADER,"level":1,"window_bits":15,"ledger_authority":false,"authenticated":false}),
                vec![],
            ));
        }
        Request::Encode {
            limit,
            size_bytes,
            sha256,
        } => {
            let payload = Payload::checked(raw, size_bytes, &sha256)?;
            let encoded = encode(&payload, limit)?;
            let digest: [u8; 32] = Sha256::digest(&encoded).into();
            (encoded, digest)
        }
        Request::Decode {
            limit,
            size_bytes,
            sha256,
        } => {
            Payload::checked(raw, size_bytes, &sha256)?;
            decode(raw, limit)?
        }
        Request::Header {
            limit,
            size_bytes,
            sha256,
            encoded_size,
        } => {
            Payload::checked(raw, size_bytes, &sha256)?;
            let size = expanded(raw, encoded_size, limit)?;
            return Ok((
                json!({"format":FORMAT,"expanded_size":size,"ledger_authority":false,"authenticated":false}),
                vec![],
            ));
        }
    };
    Ok((
        json!({"format":FORMAT,"size_bytes":result.len(),"sha256":hex::encode(result_digest),"ledger_authority":false,"authenticated":false}),
        result,
    ))
}
#[repr(C)]
pub struct CodecOutput {
    pub receipt: Buffer,
    pub payload: Buffer,
}
/// # Safety
/// Pointers declare immutable readable bytes for the whole call. Null payload
/// is allowed only for zero length. Release both unchanged returned buffers once
/// with rld_contact_crypto_free from this library; no executable addresses enter.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_spool_codec(
    input: *const u8,
    len: usize,
    payload: *const u8,
    size: usize,
) -> CodecOutput {
    let control_ok = !input.is_null() && len > 0 && len <= CONTROL;
    let valid = control_ok && size <= MAX && (size == 0 || !payload.is_null());
    let control = if control_ok {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    let raw = if valid && size > 0 {
        unsafe { std::slice::from_raw_parts(payload, size) }
    } else {
        &[]
    };
    let checked = std::panic::catch_unwind(|| {
        require(valid, "native spool codec ABI bounds differ")?;
        execute(control, raw)
    })
    .unwrap_or_else(|_| Err("native spool codec panic refused".into()));
    let (result, bytes) = match checked {
        Ok((value, bytes)) => (Ok(value), bytes),
        Err(error) => (Err(error), vec![]),
    };
    CodecOutput {
        receipt: buffer(output_with(control, || result)),
        payload: buffer(bytes),
    }
}
