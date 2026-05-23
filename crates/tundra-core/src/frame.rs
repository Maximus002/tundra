use crate::{ProtocolError, Result, MAGIC};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxCommand {
    NewStream = 0,
    Data = 1,
    Close = 2,
    Ping = 3,
    Pong = 4,
    Auth = 5,
    AuthAck = 6,
    Padding = 7,
    Challenge = 8,
    KeyConfirm = 9,
}

impl MuxCommand {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NewStream),
            1 => Some(Self::Data),
            2 => Some(Self::Close),
            3 => Some(Self::Ping),
            4 => Some(Self::Pong),
            5 => Some(Self::Auth),
            6 => Some(Self::AuthAck),
            7 => Some(Self::Padding),
            8 => Some(Self::Challenge),
            9 => Some(Self::KeyConfirm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MuxHeader {
    pub command: MuxCommand,
    pub stream_id: u32,
    pub length: u16,
}

/// Wire layout: [magic:4][cmd:1][stream_id:4][length:2][payload:length]
/// Total overhead: 11 bytes
const HEADER_WIRE_SIZE: usize = 7; // cmd(1) + stream_id(4) + length(2)
const FRAME_WIRE_OVERHEAD: usize = 4 + HEADER_WIRE_SIZE; // magic + header = 11

impl MuxHeader {
    pub fn encode(&self) -> [u8; HEADER_WIRE_SIZE] {
        let cmd = self.command as u8;
        let sid = self.stream_id;
        let len = self.length;
        [
            cmd,
            (sid >> 24) as u8,
            (sid >> 16) as u8,
            (sid >> 8) as u8,
            sid as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }

    pub fn decode(buf: &[u8; HEADER_WIRE_SIZE]) -> Result<Self> {
        let cmd = MuxCommand::from_u8(buf[0])
            .ok_or(ProtocolError::InvalidMagic)?;
        let sid = ((buf[1] as u32) << 24)
            | ((buf[2] as u32) << 16)
            | ((buf[3] as u32) << 8)
            | (buf[4] as u32);
        let length = ((buf[5] as u16) << 8) | (buf[6] as u16);
        Ok(Self { command: cmd, stream_id: sid, length })
    }
}

pub struct Frame {
    pub header: MuxHeader,
    pub payload: Vec<u8>,
}

pub const HANDSHAKE_PAD_SIZE: usize = 1400;

impl Frame {
    pub fn new(command: MuxCommand, stream_id: u32, payload: Vec<u8>) -> Self {
        assert!(payload.len() <= u16::MAX as usize, "frame payload too large");
        let length = payload.len() as u16;
        Self {
            header: MuxHeader { command, stream_id, length },
            payload,
        }
    }

    pub fn new_handshake(command: MuxCommand, stream_id: u32, payload: Vec<u8>) -> Self {
        let target = HANDSHAKE_PAD_SIZE.saturating_sub(FRAME_WIRE_OVERHEAD);
        let mut padded = payload;
        if padded.len() < target {
            padded.resize(target, 0);
        }
        Self::new(command, stream_id, padded)
    }

    pub fn new_padded(command: MuxCommand, stream_id: u32, data: Vec<u8>, total_payload_len: usize) -> Self {
        let real_len = data.len() as u16;
        let target = total_payload_len.max(2 + data.len());
        let mut payload = Vec::with_capacity(target);
        payload.extend_from_slice(&real_len.to_le_bytes());
        payload.extend_from_slice(&data);
        if payload.len() < target {
            payload.resize(target, 0);
        }
        let length = payload.len() as u16;
        Self {
            header: MuxHeader { command, stream_id, length },
            payload,
        }
    }

    pub fn real_data(&self) -> &[u8] {
        if self.payload.len() < 2 {
            return &self.payload;
        }
        let real_len = u16::from_le_bytes([self.payload[0], self.payload[1]]) as usize;
        if real_len + 2 <= self.payload.len() {
            return &self.payload[2..2 + real_len];
        }
        &self.payload
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.payload
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_WIRE_OVERHEAD + self.payload.len());
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < FRAME_WIRE_OVERHEAD {
            return Err(ProtocolError::FrameTooLarge(data.len()));
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        let header_bytes: [u8; HEADER_WIRE_SIZE] =
            [data[4], data[5], data[6], data[7], data[8], data[9], data[10]];
        let header = MuxHeader::decode(&header_bytes)?;
        let payload_end = FRAME_WIRE_OVERHEAD + header.length as usize;
        if payload_end > data.len() {
            return Err(ProtocolError::FrameTooLarge(data.len()));
        }
        let payload = data[FRAME_WIRE_OVERHEAD..payload_end].to_vec();
        Ok(Self { header, payload })
    }

    pub fn wire_overhead() -> usize {
        FRAME_WIRE_OVERHEAD
    }

    pub fn min_wire_size() -> usize {
        FRAME_WIRE_OVERHEAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = Frame::new(MuxCommand::Data, 42, b"hello".to_vec());
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.header.command, MuxCommand::Data);
        assert_eq!(decoded.header.stream_id, 42);
        assert_eq!(decoded.header.length, 5);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn padded_frame_roundtrip() {
        let frame = Frame::new_padded(MuxCommand::Data, 7, b"hello".to_vec(), 64);
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.header.command, MuxCommand::Data);
        assert_eq!(decoded.header.stream_id, 7);
        assert_eq!(decoded.real_data(), b"hello");
        assert_eq!(decoded.payload.len(), 64);
        assert_eq!(decoded.header.length as usize, 64);
    }

    #[test]
    fn new_stream_frame() {
        let frame = Frame::new(MuxCommand::NewStream, 0, b"example.com:443".to_vec());
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.header.command, MuxCommand::NewStream);
        assert_eq!(decoded.payload, b"example.com:443");
    }

    #[test]
    fn large_stream_id() {
        let frame = Frame::new(MuxCommand::Data, 0xDEADBEEF, b"test".to_vec());
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.header.stream_id, 0xDEADBEEF);
    }

    #[test]
    fn frame_invalid_magic() {
        let data = [0xFF; 11];
        assert!(Frame::decode(&data).is_err());
    }

    #[test]
    fn real_data_without_prefix() {
        let frame = Frame::new(MuxCommand::NewStream, 0, b"example.com:80".to_vec());
        assert_eq!(frame.real_data(), b"example.com:80");
    }

    #[test]
    fn header_length_matches_payload() {
        let frame = Frame::new(MuxCommand::Ping, 0, vec![0xAB; 200]);
        assert_eq!(frame.header.length, 200);
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.header.length, 200);
    }

    #[test]
    fn empty_payload() {
        let frame = Frame::new(MuxCommand::Close, 999, vec![]);
        assert_eq!(frame.header.length, 0);
        let encoded = frame.encode();
        assert_eq!(encoded.len(), 11);
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.header.command, MuxCommand::Close);
        assert!(decoded.payload.is_empty());
    }
}
