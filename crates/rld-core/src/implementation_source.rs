//! Build-embedded source identity. This is self-description, not publisher trust,
//! migration support, hermetic-build evidence or permission to sign an upgrade.
include!(concat!(env!("OUT_DIR"), "/implementation-source.rs"));

pub fn manifest_json() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/implementation-source.json"))
}
