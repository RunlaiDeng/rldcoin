//! Exact bounded serialization length only. Never a digest or authority.
use serde::Serialize;
use std::io::{self, Write};

struct Counter {
    bytes: usize,
    limit: usize,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limit);
        match next {
            Some(next) => {
                self.bytes = next;
                Ok(bytes.len())
            }
            None => Err(io::Error::other("encoded evidence exceeds bound")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn check<T: Serialize>(domain: &str, value: &T) -> crate::Result<usize> {
    // The unchanged encoder prefixes DOMAIN, ':', domain and NUL.
    let bytes = crate::DOMAIN
        .len()
        .checked_add(domain.len())
        .and_then(|n| n.checked_add(2));
    let bytes = bytes
        .filter(|n| *n <= crate::MAX_BYTES)
        .ok_or("encoded evidence exceeds bound")?;
    let mut counter = Counter {
        bytes,
        limit: crate::MAX_BYTES,
    };
    serde_json::to_writer(&mut counter, value).map_err(|e| e.to_string())?;
    Ok(counter.bytes)
}

// Only the test executable can select the old independent Vec encoder.
#[cfg(test)]
thread_local! {
    static ORIGINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn original_for_test() -> bool {
    ORIGINAL.with(std::cell::Cell::get)
}
#[cfg(test)]
pub(crate) fn with_original_for_test<T>(original: bool, work: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            ORIGINAL.with(|cell| cell.set(self.0));
        }
    }
    let _reset = Reset(ORIGINAL.with(|cell| cell.replace(original)));
    work()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::{SerializeMap, SerializeStruct};
    fn compare<T: Serialize>(domain: &str, value: &T) {
        let original = serde_json::to_vec(value).map(|raw| {
            let mut bytes = format!("{}:{domain}\0", crate::DOMAIN).into_bytes();
            bytes.extend(raw);
            bytes
        });
        match original {
            Ok(bytes) if bytes.len() <= crate::MAX_BYTES => {
                assert_eq!(check(domain, value).unwrap(), bytes.len())
            }
            _ => assert!(check(domain, value).is_err()),
        }
    }
    #[test]
    fn exact_json_shapes_escapes_numbers_and_enum_encodings() {
        let values = [
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(false),
            serde_json::json!({"empty":[],"object":{},"array":[null,true,0,-1,1.25]}),
            serde_json::json!({"unicode":"中\u{0}\\\"\n\r\t\u{7f}","max":u64::MAX,"min":i64::MIN}),
        ];
        for domain in ["evidence", "", "中\0"] {
            for value in &values {
                compare(domain, value);
            }
            compare(domain, &f64::NAN);
            compare(domain, &f64::INFINITY);
            compare(domain, &vec![0u8, 255]);
            compare(domain, &(1u8, "tuple", None::<u8>));
            compare(domain, &Some("optional"));
        }
        #[derive(Serialize)]
        enum Enum {
            Unit,
            Newtype(String),
            Tuple(u8, bool),
            Struct { field: Vec<String> },
        }
        for value in [
            Enum::Unit,
            Enum::Newtype("signed bytes".into()),
            Enum::Tuple(1, true),
            Enum::Struct {
                field: vec!["a".into(), "中".into()],
            },
        ] {
            compare("evidence", &value);
        }
    }
    #[test]
    fn exact_limit_and_one_byte_over_refuse_without_overflow() {
        let prefix = crate::DOMAIN.len() + "evidence".len() + 2;
        for length in [
            0,
            1,
            crate::MAX_BYTES - prefix - 3,
            crate::MAX_BYTES - prefix - 2,
            crate::MAX_BYTES - prefix - 1,
        ] {
            compare("evidence", &"x".repeat(length));
        }
        let mut counter = Counter {
            bytes: usize::MAX - 1,
            limit: usize::MAX,
        };
        assert!(counter.write(b"xx").is_err());
        assert_eq!(counter.bytes, usize::MAX - 1);
        assert_eq!(counter.write(b"x").unwrap(), 1);
        assert_eq!(counter.bytes, usize::MAX);
        assert!(counter.write(b"x").is_err());
        assert_eq!(counter.bytes, usize::MAX);
        let mut counter = Counter { bytes: 0, limit: 1 };
        assert!(counter.write(b"xx").is_err());
        assert_eq!(counter.bytes, 0);
    }
    #[test]
    fn serialization_errors_and_unsupported_keys_never_become_sizes() {
        struct Bad;
        impl Serialize for Bad {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(
                    "deliberate malformed serialization",
                ))
            }
        }
        struct InvalidKey;
        impl Serialize for InvalidKey {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(&vec![1, 2], &0)?;
                map.end()
            }
        }
        struct BadTail;
        impl Serialize for BadTail {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut value = serializer.serialize_struct("BadTail", 2)?;
                value.serialize_field("valid", &"x".repeat(crate::MAX_BYTES))?;
                value.serialize_field("invalid", &Bad)?;
                value.end()
            }
        }
        compare("evidence", &Bad);
        compare("evidence", &InvalidKey);
        compare("evidence", &BadTail);
        // Parsing remains the original independent JSON decoder; counting is
        // only invoked on typed values and cannot admit malformed wire bytes.
        for raw in [b"[".as_slice(), b"{\"x\":}", b"null trailing", b"\"\xff\""] {
            assert!(serde_json::from_slice::<serde_json::Value>(raw).is_err());
        }
    }
}
