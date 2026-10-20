use anyhow::{Result, bail, ensure};
use minicbor::{
    Decode, Decoder, Encode, Encoder,
    data::{Tag, Type},
    encode::Write,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(pub [u8; 32]);
impl Id {
    pub const ZERO: Self = Self([0; 32]);
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(
            hex::decode(s)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("expected 32 bytes"))?,
        ))
    }
}
impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}
impl<C> Encode<C> for Id {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?;
        Ok(())
    }
}
impl<'b, C> Decode<'b, C> for Id {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.bytes()?.try_into().map_err(|_| {
            minicbor::decode::Error::message("ID length")
        })?))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);
impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(
            hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?,
        ))
    }
}
impl<C> Encode<C> for Blob {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?;
        Ok(())
    }
}
impl<'b, C> Decode<'b, C> for Blob {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.bytes()?.to_vec()))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(pub u128);
impl Amount {
    pub fn add(self, other: Self) -> Result<Self> {
        Ok(Self(
            self.0
                .checked_add(other.0)
                .filter(|v| *v <= crate::CAP)
                .ok_or_else(|| anyhow::anyhow!("amount overflow"))?,
        ))
    }
    pub fn sub(self, other: Self) -> Result<Self> {
        Ok(Self(
            self.0
                .checked_sub(other.0)
                .ok_or_else(|| anyhow::anyhow!("insufficient amount"))?,
        ))
    }
}
impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = String::deserialize(d)?
            .parse::<u128>()
            .map_err(serde::de::Error::custom)?;
        if v > crate::CAP {
            return Err(serde::de::Error::custom("above cap"));
        }
        Ok(Self(v))
    }
}
impl<C> Encode<C> for Amount {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        if self.0 <= u64::MAX as u128 {
            e.u64(self.0 as u64)?;
        } else {
            let b = self.0.to_be_bytes();
            let n = b.iter().position(|v| *v != 0).unwrap_or(15);
            e.tag(Tag::new(2))?.bytes(&b[n..])?;
        }
        Ok(())
    }
}
impl<'b, C> Decode<'b, C> for Amount {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let n = if d.datatype()? == Type::Tag {
            if d.tag()? != Tag::new(2) {
                return Err(minicbor::decode::Error::message("amount tag"));
            }
            let b = d.bytes()?;
            if b.is_empty() || b.len() > 16 || b[0] == 0 {
                return Err(minicbor::decode::Error::message("amount encoding"));
            }
            let mut out = [0; 16];
            out[16 - b.len()..].copy_from_slice(b);
            let n = u128::from_be_bytes(out);
            if n <= u64::MAX as u128 {
                return Err(minicbor::decode::Error::message("nonminimal amount"));
            }
            n
        } else {
            d.u64()? as u128
        };
        if n > crate::CAP {
            return Err(minicbor::decode::Error::message("above cap"));
        }
        Ok(Self(n))
    }
}

/// Fixed-order records; JSON is an operator envelope, never the signing encoding.
#[macro_export]
macro_rules! record {
 ($name:ident { $($field:ident : $ty:ty   =>   $index:literal),* $(,)? })   =>   {
  #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, minicbor::Encode, minicbor::Decode)]
  #[serde(deny_unknown_fields)] #[cbor(array)]
  pub struct $name { $(#[n($index)] pub $field:$ty),* }
 };
}

pub fn encode<T: Encode<()>>(value: &T) -> Vec<u8> {
    minicbor::to_vec(value).expect("Vec encoding cannot fail")
}
pub fn tagged<T: Encode<()>>(tag: &str, currency: Id, value: &T) -> Vec<u8> {
    let body = encode(value);
    let mut d = Decoder::new(&body);
    let (fields, offset) = if d.datatype().expect("encoded value") == Type::Array {
        let n = d.array().expect("encoded array").expect("definite array");
        (n, d.position())
    } else {
        (1, 0)
    };
    let mut e = Encoder::new(Vec::new());
    e.array(fields + 3)
        .expect("Vec")
        .str(tag)
        .expect("Vec")
        .str(crate::PROTOCOL)
        .expect("Vec");
    currency.encode(&mut e, &mut ()).expect("Vec");
    let mut out = e.into_writer();
    out.extend_from_slice(&body[offset..]);
    out
}
pub fn hash<T: Encode<()>>(tag: &str, currency: Id, value: &T) -> Id {
    Id::digest(&tagged(tag, currency, value))
}
pub fn decode<T: for<'a> Decode<'a, ()> + Encode<()>>(bytes: &[u8], limit: usize) -> Result<T> {
    ensure!(bytes.len() <= limit, "encoded object too large");
    preflight(bytes)?;
    let mut d = Decoder::new(bytes);
    let v = T::decode(&mut d, &mut ())?;
    ensure!(
        d.position() == bytes.len() && encode(&v) == bytes,
        "noncanonical/trailing/unknown fields"
    );
    Ok(v)
}
/// Bound allocation before a derived decoder sees adversarial lengths.
fn preflight(bytes: &[u8]) -> Result<()> {
    fn item(b: &[u8], p: &mut usize, depth: usize, count: &mut usize) -> Result<()> {
        ensure!(depth <= 32, "CBOR depth");
        *count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("count"))?;
        ensure!(*count <= b.len(), "CBOR item count");
        let h = *b.get(*p).ok_or_else(|| anyhow::anyhow!("truncated CBOR"))?;
        *p += 1;
        let ai = h & 31;
        let major = h >> 5;
        ensure!(ai <= 27, "indefinite/reserved CBOR");
        let n = if ai < 24 {
            ai as u64
        } else {
            let len = 1usize << (ai - 24);
            let end = p
                .checked_add(len)
                .ok_or_else(|| anyhow::anyhow!("CBOR length"))?;
            ensure!(end <= b.len(), "truncated length");
            let mut n = 0u64;
            for v in &b[*p..end] {
                n = (n << 8) | *v as u64
            }
            *p = end;
            ensure!(
                n >= match ai {
                    24 => 24,
                    25 => 256,
                    26 => 65536,
                    _ => 4294967296,
                },
                "nonminimal CBOR"
            );
            n
        };
        match major {
            0 => {}
            2 | 3 => {
                let len = usize::try_from(n)?;
                let end = p
                    .checked_add(len)
                    .ok_or_else(|| anyhow::anyhow!("CBOR size"))?;
                ensure!(end <= b.len(), "truncated string");
                if major == 3 {
                    ensure!(
                        b[*p..end].iter().all(u8::is_ascii),
                        "non-ASCII protocol text"
                    )
                }
                *p = end;
            }
            4 => {
                ensure!(
                    n <= 1_000_000 && n as usize <= b.len().saturating_sub(*p),
                    "array bound"
                );
                for _ in 0..n {
                    item(b, p, depth + 1, count)?;
                }
            }
            6 => {
                ensure!(n == 2, "unknown tag");
                item(b, p, depth + 1, count)?;
            }
            7 => ensure!(
                h == 0xf4 || h == 0xf5 || h == 0xf6,
                "unsupported simple value"
            ),
            _ => bail!("negative/map/floating protocol value"),
        }
        Ok(())
    }
    let mut pos = 0;
    item(bytes, &mut pos, 0, &mut 0)?;
    ensure!(pos == bytes.len(), "trailing CBOR");
    Ok(())
}

pub fn sorted_unique<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| w[0] < w[1])
}
