pub mod applied;
pub mod codec;
pub mod consensus;
pub mod crypto;
pub mod merkle;
pub mod model;
pub mod proof;
pub mod state;
pub mod work;

pub const PROTOCOL: &str = "RLD-PAYMENT-CTRL-1";
pub const ENCODING: &str = "RLD-CBOR-1";
pub const PAPER_SHA256: &str = "30ad8bfeca1a5da98ebd92f5f1acda56348f6d9686508d3da6180c873d4487e8";
pub const ATOMS: u128 = 1_000_000_000_000_000_000_000_000;
pub const CAP: u128 = 21_000_000 * ATOMS;
pub const ROOTS: u32 = 4096;
pub const SLOTS: u32 = 1_000_000;
pub const REWARD: u128 = 5_126_953_125_000_000_000_000;
pub const KEY_COUNT: u32 = 65_536;
pub const MAX_CAPSULE: usize = 16 * 1024 * 1024;
pub const MAX_RECEIPT: usize = 1024 * 1024;

pub mod table;
