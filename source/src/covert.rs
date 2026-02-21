//! S10207 TCP storage covert channel: encode/decode, PRNG masking, integrity
//! signature, and packet crafting for SYN and RST/ACK.

use std::net::Ipv4Addr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, Ipv4Flags};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
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

/// IP Identification value the victim sends in RST/ACK to abort the transaction.
/// The sender must treat such a reply as `CovertStreamError::Rejected` and stop immediately.
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
pub fn prng(mut x: u32) -> u32 {
    if x == 0 {
        x = 0xdead_beef;
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

pub fn mask_word(raw_word: u32, ip_id: u16) -> u32 {
    raw_word ^ prng(ip_id as u32)
}

pub fn unmask_word(seq: u32, ip_id: u16) -> u32 {
    seq ^ prng(ip_id as u32)
}

/// Full 32-bit signature; low 16 bits go in RST/ACK IP Identification.
pub fn compute_signature(ip_id: u16, raw_word: u32) -> u32 {
    prng((ip_id as u32).wrapping_add(raw_word))
}

pub fn signature_ip_id(ip_id: u16, raw_word: u32) -> u16 {
    (compute_signature(ip_id, raw_word) & 0xffff) as u16
}

// -----------------------------------------------------------------------------
// Packet crafting
// -----------------------------------------------------------------------------

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const PACKET_LEN: usize = IPV4_HEADER_LEN + TCP_HEADER_LEN;

/// Build IPv4+TCP SYN. Caller sends the buffer via raw socket.
pub fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ip_id: u16,
    masked_seq: u32,
) -> [u8; PACKET_LEN] {
    let mut buf = [0u8; PACKET_LEN];
    let (ip_buf, tcp_buf) = buf.split_at_mut(IPV4_HEADER_LEN);

    {
        let mut tcp = MutableTcpPacket::new(tcp_buf).expect("tcp");
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(masked_seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_urgent_ptr(0);
        tcp.set_checksum(0);
    }
    {
        let mut ip = MutableIpv4Packet::new(ip_buf).expect("ip");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(PACKET_LEN as u16);
        ip.set_identification(ip_id);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_checksum(0);
    }

    let ip_cs = pnet::packet::ipv4::checksum(&Ipv4Packet::new(ip_buf).expect("ip view"));
    MutableIpv4Packet::new(ip_buf).unwrap().set_checksum(ip_cs);

    let tcp_cs = pnet::packet::util::ipv4_checksum(
        tcp_buf,
        8,
        &[],
        &src_ip,
        &dst_ip,
        IpNextHeaderProtocols::Tcp,
    );
    MutableTcpPacket::new(tcp_buf).unwrap().set_checksum(tcp_cs);

    buf
}

pub fn build_syn_ack_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> [u8; 40] {
    let mut buf = [0u8; 40];
    let (ip_buf, tcp_buf) = buf.split_at_mut(20);

    {
        let mut tcp = MutableTcpPacket::new(tcp_buf).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        tcp.set_window(64240);
        tcp.set_urgent_ptr(0);
        tcp.set_checksum(0);
    }

    {
        let mut ip = MutableIpv4Packet::new(ip_buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_identification(0);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_checksum(0);
    }

    let ip_cs = pnet::packet::ipv4::checksum(&Ipv4Packet::new(ip_buf).unwrap());
    MutableIpv4Packet::new(ip_buf).unwrap().set_checksum(ip_cs);

    let tcp_cs = pnet::packet::tcp::ipv4_checksum(
        &TcpPacket::new(tcp_buf).unwrap(),
        &src_ip,
        &dst_ip,
    );
    MutableTcpPacket::new(tcp_buf).unwrap().set_checksum(tcp_cs);

    buf
}

/// Parameters for RST/ACK reply (receiver side).
#[derive(Clone)]
pub struct RstAckParams {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ack_number: u32,
    pub ip_id: u16,
}

/// Build IPv4+TCP RST/ACK. Receiver uses this to reply to a SYN.
pub fn build_rst_ack_packet(params: &RstAckParams) -> Vec<u8> {
    let mut buffer = [0u8; 40]; 
    
    // IPv4 Header
    {
        let mut ip_pkt = MutableIpv4Packet::new(&mut buffer).unwrap();
        ip_pkt.set_version(4);
        ip_pkt.set_header_length(5);
        ip_pkt.set_total_length(40);
        
        // We set this to 0 and let the TCP window carry the weight
        ip_pkt.set_identification(0); 
        ip_pkt.set_flags(0); 
        ip_pkt.set_ttl(64);
        ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_pkt.set_source(params.src_ip);
        ip_pkt.set_destination(params.dst_ip);
        
        let checksum = pnet::packet::ipv4::checksum(&ip_pkt.to_immutable());
        ip_pkt.set_checksum(checksum);
    }

    // TCP Header
    {
        let mut tcp_pkt = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
        tcp_pkt.set_source(params.src_port);
        tcp_pkt.set_destination(params.dst_port);
        tcp_pkt.set_acknowledgement(params.ack_number);
        tcp_pkt.set_flags(TcpFlags::RST | TcpFlags::ACK);
        
        // --- COVERT SIGNATURE MOVED HERE ---
        tcp_pkt.set_window(params.ip_id); 
        
        tcp_pkt.set_sequence(0);
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_pkt.to_immutable(), &params.src_ip, &params.dst_ip);
        tcp_pkt.set_checksum(checksum);
    }
    buffer.to_vec()
}

// -----------------------------------------------------------------------------
// Parse SYN and RST/ACK
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ParsedSyn {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_id: u16,
    pub seq: u32,
}

/// Parse IPv4 packet as TCP SYN. Returns None if not SYN or not TCP.
pub fn parse_syn_from_ipv4_packet(ip_buf: &[u8]) -> Option<ParsedSyn> {
    let ip = Ipv4Packet::new(ip_buf)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp = TcpPacket::new(ip.payload())?;
    let syn = tcp.get_flags() & TcpFlags::SYN != 0;
    let ack = tcp.get_flags() & TcpFlags::ACK != 0;
    if !syn || ack {
        return None;
    }
    Some(ParsedSyn {
        src_ip: ip.get_source(),
        dst_ip: ip.get_destination(),
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        ip_id: ip.get_identification(),
        seq: tcp.get_sequence(),
    })
}

pub fn parse_rst_ack_signature(packet: &[u8]) -> Option<u16> {
    let ipv4 = Ipv4Packet::new(packet)?;
    let tcp = TcpPacket::new(ipv4.payload())?;

    let flags = tcp.get_flags();
    if (flags & TcpFlags::RST) != 0 && (flags & TcpFlags::ACK) != 0 {
        // Retrieve signature from the Window field instead of IP Identification
        return Some(tcp.get_window());
    }
    None
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

    /// Return (ip_id, raw_word, masked_seq) for current chunk; increments next_ip_id only.
    /// Call again for retransmit (new ip_id, same logical chunk). Call ack() after RST/ACK verified.
    pub fn chunk_to_send(&mut self) -> Option<(u16, u32, u32)> {
        let (control, chars) = self.chunks.get(self.index)?.clone();
        let ip_id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        let raw_word = encode_chunk(chars, control);
        let masked_seq = mask_word(raw_word, ip_id);
        Some((ip_id, raw_word, masked_seq))
    }

    /// Call after RST/ACK signature verified for current chunk.
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

    /// Apply one chunk; returns action and 16-bit signature for RST/ACK IP ID.
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
        let word = 0xdead_beefu32;
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
