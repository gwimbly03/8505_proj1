//! S10207 UDP covert channel: encode/decode, PRNG masking, integrity
//! signature, and packet crafting for UDP request and response.
//!
//! # Covert Channel Field Usage
//! ----------------------------
//! ## UDP Request Packet (Sender → Receiver):
//!   - IP Identification: PRNG seed / packet counter (covert data carrier)
//!   - UDP Source Port: masked covert word (data + control code)
//!   - UDP Destination Port: channel identifier (fixed or randomized)
//!   - UDP Length: fixed value (8 + payload)
//!   - UDP Checksum: optional (can be zeroed for IPv4)
//!
//! ## UDP Response Packet (Receiver → Sender):
//!   - IP Identification: 0 (unused)
//!   - UDP Source Port: channel identifier
//!   - UDP Destination Port: signature for ACK validation (covert acknowledgment)
//!   - UDP Length: fixed value (8 bytes, no payload)
//!   - UDP Checksum: optional (can be zeroed for IPv4)
//!
//! # Security Notes
//! ----------------
//! ⚠️  xorshift32 PRNG is NOT cryptographically secure.
//!     Use only for obfuscation, not confidentiality.
//!
//! ⚠️  Raw socket access requires CAP_NET_RAW or root privileges.
//!
//! ⚠️  UDP packets may be rate-limited by ICMP responses.
//!     Use iptables to suppress ICMP unreachable messages.

use std::net::Ipv4Addr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, Ipv4Flags};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub enum CovertError {
    InvalidPacket,
    CheckFailed,
    BufferOverflow,
    SequenceMismatch,
    InvalidControlCode(u8),
    ParseError(&'static str),
}

impl std::fmt::Display for CovertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CovertError::InvalidPacket => write!(f, "invalid packet"),
            CovertError::CheckFailed => write!(f, "check failed"),
            CovertError::BufferOverflow => write!(f, "buffer overflow"),
            CovertError::SequenceMismatch => write!(f, "sequence mismatch"),
            CovertError::InvalidControlCode(c) => write!(f, "invalid control code: 0x{c:02x}"),
            CovertError::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for CovertError {}

// -----------------------------------------------------------------------------
// Control codes (4 bits, MSBs of 32-bit word)
// -----------------------------------------------------------------------------
/// Control codes for the covert channel (bits 28–31 of the embedded word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlCode {
    /// Normal data chunk.
    Data = 0b0001,
    /// EOT at position 0.
    EotPos0 = 0b0010,
    EotPos1 = 0b0011,
    EotPos2 = 0b0100,
    EotPos3 = 0b0101,
    /// Delete last 4 chars (error correction).
    DeleteLast4 = 0b0110,
    /// Delete last 3 chars and EOT.
    DeleteLast3Eot = 0b0111,
    /// Fatal error.
    FatalError = 0b1000,
}

const EOT_CHAR: u8 = 0x04;
const PAD_CHAR: u8 = 0x00;

/// IP Identification value the receiver sends in UDP response to abort the transaction.
pub const REJECT_IP_ID: u16 = 0xFFFF;

impl ControlCode {
    pub fn from_bits(bits: u8) -> Result<Self, CovertError> {
        match bits & 0x0f {
            0b0001 => Ok(ControlCode::Data),
            0b0010 => Ok(ControlCode::EotPos0),
            0b0011 => Ok(ControlCode::EotPos1),
            0b0100 => Ok(ControlCode::EotPos2),
            0b0101 => Ok(ControlCode::EotPos3),
            0b0110 => Ok(ControlCode::DeleteLast4),
            0b0111 => Ok(ControlCode::DeleteLast3Eot),
            0b1000 => Ok(ControlCode::FatalError),
            b => Err(CovertError::InvalidControlCode(b)),
        }
    }

    pub fn to_bits(self) -> u8 {
        self as u8
    }

    pub fn eot_position(self) -> Option<usize> {
        match self {
            ControlCode::EotPos0 => Some(0),
            ControlCode::EotPos1 => Some(1),
            ControlCode::EotPos2 => Some(2),
            ControlCode::EotPos3 => Some(3),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------------------
// PRNG (xorshift32)
// -----------------------------------------------------------------------------
/// Deterministic PRNG. Same on sender and receiver; zero seed avoided.
///
/// ⚠️  SECURITY WARNING: xorshift32 is NOT cryptographically secure.
///     It provides obfuscation against casual inspection but should not
///     be relied upon for confidentiality against determined adversaries.
pub fn prng(mut x: u32) -> u32 {
    if x == 0 {
        x = 0xdeadbeef;
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}

// -----------------------------------------------------------------------------
// Encode / decode 32-bit word
// -----------------------------------------------------------------------------
const CONTROL_MASK: u32 = 0xF000_0000;
const CONTROL_SHIFT: u32 = 28;

/// Pack 4×7-bit chars + control into a 32-bit word.
pub fn encode_chunk(chars: [u8; 4], control: ControlCode) -> u32 {
    let c0 = (chars[0] & 0x7f) as u32;
    let c1 = (chars[1] & 0x7f) as u32;
    let c2 = (chars[2] & 0x7f) as u32;
    let c3 = (chars[3] & 0x7f) as u32;
    (c0 | (c1 << 7) | (c2 << 14) | (c3 << 21)) | ((control.to_bits() as u32) << CONTROL_SHIFT)
}

/// Extract control and four 7-bit chars from a 32-bit word.
pub fn decode_word(word: u32) -> Result<(ControlCode, [u8; 4]), CovertError> {
    let control_bits = ((word & CONTROL_MASK) >> CONTROL_SHIFT) as u8;
    let control = ControlCode::from_bits(control_bits)?;
    let c0 = (word & 0x7f) as u8;
    let c1 = ((word >> 7) & 0x7f) as u8;
    let c2 = ((word >> 14) & 0x7f) as u8;
    let c3 = ((word >> 21) & 0x7f) as u8;
    Ok((control, [c0, c1, c2, c3]))
}

// -----------------------------------------------------------------------------
// Masking and signature
// -----------------------------------------------------------------------------
/// Mask a raw covert word using IP ID as PRNG seed.
/// Used by sender to obfuscate UDP source port.
pub fn mask_word(raw_word: u32, ip_id: u16) -> u32 {
    raw_word ^ prng(ip_id as u32)
}

/// Unmask a received UDP source port using IP ID as PRNG seed.
/// Used by receiver to recover the original covert word.
pub fn unmask_word(src_port: u32, ip_id: u16) -> u32 {
    src_port ^ prng(ip_id as u32)
}

/// Full 32-bit signature; low 16 bits go in UDP Response Destination Port field.
pub fn compute_signature(ip_id: u16, raw_word: u32) -> u32 {
    prng((ip_id as u32).wrapping_add(raw_word))
}

/// Extract 16-bit signature for UDP Response Destination Port field.
pub fn signature_ip_id(ip_id: u16, raw_word: u32) -> u16 {
    (compute_signature(ip_id, raw_word) & 0xffff) as u16
}

// -----------------------------------------------------------------------------
// Packet crafting
// -----------------------------------------------------------------------------
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const PACKET_LEN: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;

/// Build IPv4+UDP request packet with covert data embedded.
///
/// # Important
/// Must be sent via Layer 3 socket (Protocol::Ipv4), NOT Layer 4 (Protocol::Udp).
/// Layer 4 sockets will overwrite the IP header and break the covert channel.
///
/// # Kernel Compatibility
/// To prevent kernel from modifying UDP packets:
/// - Use iptables raw table: `iptables -t raw -A OUTPUT -j NOTRACK`
/// - Disable rp_filter: `sysctl -w net.ipv4.conf.all.rp_filter=0`
/// - Disable checksum offloading: `ethtool -K eth0 tx off`
pub fn build_udp_request_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    base_port: u16,
    ip_id: u16,
    masked_word: u32,
) -> [u8; PACKET_LEN] {
    let mut buf = [0u8; PACKET_LEN];
    let (ip_buf, udp_buf) = buf.split_at_mut(IPV4_HEADER_LEN);

    // Craft UDP header first (needed for checksum calculation)
    {
        let mut udp = MutableUdpPacket::new(udp_buf).expect("udp buffer too small");
        // Covert data hidden in source port (lower 16 bits of masked_word)
        let src_port = (masked_word & 0xFFFF) as u16;
        udp.set_source(src_port);
        udp.set_destination(base_port);
        udp.set_length(UDP_HEADER_LEN as u16);
        udp.set_checksum(0); // Zero checksum for IPv4 (optional)
    }

    // Craft IPv4 header
    {
        let mut ip = MutableIpv4Packet::new(ip_buf).expect("ip buffer too small");
        ip.set_version(4);
        ip.set_header_length(5); // 20 bytes
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(PACKET_LEN as u16);
        ip.set_identification(ip_id); // Covert channel carrier
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_checksum(0); // Temporary, will be calculated below
    }

    // Calculate and set IP checksum
    let ip_cs = pnet::packet::ipv4::checksum(&Ipv4Packet::new(ip_buf).expect("ip view"));
    MutableIpv4Packet::new(ip_buf).unwrap().set_checksum(ip_cs);

    // Calculate and set UDP checksum (includes pseudo-header)
    let udp_cs = pnet::packet::udp::ipv4_checksum(
        &UdpPacket::new(udp_buf).unwrap(),
        &src_ip,
        &dst_ip,
    );
    MutableUdpPacket::new(udp_buf).unwrap().set_checksum(udp_cs);

    buf
}

/// Build IPv4+UDP response packet for receiver acknowledgment.
///
/// # Covert Channel Usage
/// The acknowledgment signature is embedded in the UDP Destination Port field.
///
/// # Kernel Compatibility
/// UDP packets without established connections may trigger ICMP responses.
/// Use iptables to suppress ICMP unreachable messages.
pub fn build_udp_response_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16, // Contains covert signature
) -> [u8; PACKET_LEN] {
    let mut buf = [0u8; PACKET_LEN];
    let (ip_buf, udp_buf) = buf.split_at_mut(IPV4_HEADER_LEN);

    // UDP Header
    {
        let mut udp_pkt = MutableUdpPacket::new(udp_buf).unwrap();
        udp_pkt.set_source(src_port);
        udp_pkt.set_destination(dst_port); // Covert signature here
        udp_pkt.set_length(UDP_HEADER_LEN as u16);
        udp_pkt.set_checksum(0); // Zero checksum for IPv4
    }

    // IPv4 Header
    {
        let mut ip_pkt = MutableIpv4Packet::new(ip_buf).unwrap();
        ip_pkt.set_version(4);
        ip_pkt.set_header_length(5);
        ip_pkt.set_total_length(PACKET_LEN as u16);
        ip_pkt.set_identification(0); // Unused in response
        ip_pkt.set_flags(Ipv4Flags::DontFragment);
        ip_pkt.set_fragment_offset(0);
        ip_pkt.set_ttl(64);
        ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_pkt.set_source(src_ip);
        ip_pkt.set_destination(dst_ip);
        ip_pkt.set_checksum(0);
    }

    let ip_cs = pnet::packet::ipv4::checksum(&Ipv4Packet::new(ip_buf).unwrap());
    MutableIpv4Packet::new(ip_buf).unwrap().set_checksum(ip_cs);

    let udp_cs = pnet::packet::udp::ipv4_checksum(
        &UdpPacket::new(udp_buf).unwrap(),
        &src_ip,
        &dst_ip,
    );
    MutableUdpPacket::new(udp_buf).unwrap().set_checksum(udp_cs);

    buf
}

// -----------------------------------------------------------------------------
// Parse UDP Request and Response
// -----------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ParsedUdpRequest {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_id: u16,
}

/// Parse IPv4 packet as UDP request. Returns None if not UDP.
pub fn parse_udp_request_from_ipv4_packet(ip_buf: &[u8]) -> Option<ParsedUdpRequest> {
    let ip = Ipv4Packet::new(ip_buf)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }
    let udp = UdpPacket::new(ip.payload())?;
    Some(ParsedUdpRequest {
        src_ip: ip.get_source(),
        dst_ip: ip.get_destination(),
        src_port: udp.get_source(),
        dst_port: udp.get_destination(),
        ip_id: ip.get_identification(),
    })
}

/// Extract acknowledgment signature from UDP response packet Destination Port field.
pub fn parse_udp_response_signature(packet: &[u8]) -> Option<u16> {
    let ipv4 = Ipv4Packet::new(packet)?;
    let udp = UdpPacket::new(ipv4.payload())?;
    // Retrieve signature from the UDP Destination Port field
    Some(udp.get_destination())
}

// -----------------------------------------------------------------------------
// Sender state
// -----------------------------------------------------------------------------
/// Chunk bytes (7-bit only) into 4-char chunks with EOT in last chunk.
pub fn prepare_chunks_bytes(bytes: &[u8]) -> Vec<(ControlCode, [u8; 4])> {
    let mut chunks = Vec::new();
    let bytes: Vec<u8> = bytes.iter().map(|&b| b & 0x7f).collect();
    let mut i = 0;
    while i < bytes.len() {
        let mut arr = [PAD_CHAR; 4];
        let mut n = 0;
        while n < 4 && i < bytes.len() {
            arr[n] = bytes[i];
            n += 1;
            i += 1;
        }
        if i >= bytes.len() {
            arr[n.min(3)] = EOT_CHAR;
            let ctrl = match n {
                1 => ControlCode::EotPos1,
                2 => ControlCode::EotPos2,
                3 | 4 => ControlCode::EotPos3,
                _ => ControlCode::EotPos0,
            };
            chunks.push((ctrl, arr));
        } else {
            chunks.push((ControlCode::Data, arr));
        }
    }
    if chunks.is_empty() {
        chunks.push((ControlCode::EotPos0, [EOT_CHAR, PAD_CHAR, PAD_CHAR, PAD_CHAR]));
    }
    chunks
}

/// Chunk message into 4-char chunks with EOT in last chunk.
pub fn prepare_chunks(message: &str) -> Vec<(ControlCode, [u8; 4])> {
    let mut chunks = Vec::new();
    let bytes: Vec<u8> = message.bytes().map(|b| b & 0x7f).collect();
    let mut i = 0;
    while i < bytes.len() {
        let mut arr = [PAD_CHAR; 4];
        let mut n = 0;
        while n < 4 && i < bytes.len() {
            arr[n] = bytes[i];
            n += 1;
            i += 1;
        }
        if i >= bytes.len() {
            arr[n.min(3)] = EOT_CHAR;
            let ctrl = match n {
                1 => ControlCode::EotPos1,
                2 => ControlCode::EotPos2,
                3 | 4 => ControlCode::EotPos3,
                _ => ControlCode::EotPos0,
            };
            chunks.push((ctrl, arr));
        } else {
            chunks.push((ControlCode::Data, arr));
        }
    }
    if chunks.is_empty() {
        chunks.push((ControlCode::EotPos0, [EOT_CHAR, PAD_CHAR, PAD_CHAR, PAD_CHAR]));
    }
    chunks
}

/// Sender state: chunks, index, next IP ID.
pub struct SenderState {
    pub chunks: Vec<(ControlCode, [u8; 4])>,
    pub index: usize,
    pub next_ip_id: u16,
}

impl SenderState {
    pub fn new(message: &str) -> Self {
        SenderState {
            chunks: prepare_chunks(message),
            index: 0,
            next_ip_id: 1,
        }
    }

    /// Build sender state from raw bytes (7-bit safe).
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        SenderState {
            chunks: prepare_chunks_bytes(bytes),
            index: 0,
            next_ip_id: 1,
        }
    }

    pub fn has_next(&self) -> bool {
        self.index < self.chunks.len()
    }

    /// Return (ip_id, raw_word, masked_word) for current chunk.
    pub fn chunk_to_send(&mut self) -> Option<(u16, u32, u32)> {
        let (control, chars) = self.chunks.get(self.index)?.clone();
        let ip_id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        let raw_word = encode_chunk(chars, control);
        let masked_word = mask_word(raw_word, ip_id);
        Some((ip_id, raw_word, masked_word))
    }

    /// Call after UDP response signature verified for current chunk.
    pub fn ack(&mut self) {
        self.index += 1;
    }
}

// -----------------------------------------------------------------------------
// Receiver state
// -----------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverAction {
    Append,
    Complete,
    DeleteLast4,
    DeleteLast3Eot,
    Fatal,
}

/// Apply decoded (control, chars) to buffer.
pub fn decode_and_apply(
    buffer: &mut Vec<u8>,
    control: ControlCode,
    chars: [u8; 4],
) -> Result<ReceiverAction, CovertError> {
    match control {
        ControlCode::FatalError => return Ok(ReceiverAction::Fatal),
        ControlCode::DeleteLast4 => {
            buffer.truncate(buffer.len().saturating_sub(4));
            return Ok(ReceiverAction::DeleteLast4);
        }
        ControlCode::DeleteLast3Eot => {
            buffer.truncate(buffer.len().saturating_sub(3));
            buffer.push(EOT_CHAR);
            return Ok(ReceiverAction::Complete);
        }
        _ => {}
    }
    let eot_pos = control.eot_position();
    for (i, &c) in chars.iter().enumerate() {
        if Some(i) == eot_pos && c == EOT_CHAR {
            return Ok(ReceiverAction::Complete);
        }
        if Some(i) == eot_pos {
            break;
        }
        if c != PAD_CHAR {
            buffer.push(c);
        }
    }
    Ok(ReceiverAction::Append)
}

/// Receiver state: buffer and completion flag.
pub struct ReceiverState {
    pub buffer: Vec<u8>,
    pub complete: bool,
}

impl ReceiverState {
    pub fn new() -> Self {
        ReceiverState {
            buffer: Vec::new(),
            complete: false,
        }
    }

    /// Apply one chunk; returns action and 16-bit signature for UDP response.
    pub fn apply_chunk(&mut self, ip_id: u16, raw_word: u32) -> Result<(ReceiverAction, u16), CovertError> {
        let (control, chars) = decode_word(raw_word)?;
        let action = decode_and_apply(&mut self.buffer, control, chars)?;
        if matches!(action, ReceiverAction::Complete | ReceiverAction::Fatal) {
            self.complete = true;
        }
        Ok((action, signature_ip_id(ip_id, raw_word)))
    }

    pub fn message_str(&self) -> Result<String, CovertError> {
        std::str::from_utf8(&self.buffer)
            .map(String::from)
            .map_err(|_| CovertError::ParseError("invalid UTF-8"))
    }
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_deterministic() {
        assert_eq!(prng(1), prng(1));
        assert_eq!(prng(0), prng(0));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let chars = [b'T', b'E', b'S', b'T'];
        let word = encode_chunk(chars, ControlCode::Data);
        let (c, arr) = decode_word(word).unwrap();
        assert_eq!(c, ControlCode::Data);
        assert_eq!(arr, chars);
    }

    #[test]
    fn mask_unmask_roundtrip() {
        let raw = 0x1234_5678u32;
        let ip_id = 0xabcu16;
        assert_eq!(unmask_word(mask_word(raw, ip_id), ip_id), raw);
    }

    #[test]
    fn signature_ip_id_match() {
        let ip_id = 0x1234u16;
        let word = 0xdeadbeefu32;
        assert_eq!(signature_ip_id(ip_id, word), (compute_signature(ip_id, word) & 0xffff) as u16);
    }

    #[test]
    fn prepare_chunks_empty() {
        let c = prepare_chunks("");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].1[0], EOT_CHAR);
    }

    #[test]
    fn prepare_chunks_short() {
        let c = prepare_chunks("AB");
        assert!(!c.is_empty());
        assert_eq!(c[0].1[0], b'A');
        assert_eq!(c[0].1[1], b'B');
    }
}
