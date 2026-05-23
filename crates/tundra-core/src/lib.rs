pub mod crypto;
pub mod frame;
pub mod kem;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Upstream,
    Downstream,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid magic")]
    InvalidMagic,
    #[error("authentication failed")]
    AuthFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("stream not found: {0}")]
    StreamNotFound(u32),
    #[error("stream reset by peer")]
    StreamReset,
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("kem error: {0}")]
    Kem(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

pub const MAGIC: u32 = 0x544E4452;
pub const MAX_FRAME_SIZE: usize = 65535;
pub const MAX_STREAMS: u32 = 1 << 31;
