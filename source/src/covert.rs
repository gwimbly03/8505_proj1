use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender};
use std::net::Ipv4Addr;

pub struct CovertChannel {
    tx: TransportSender,
    target_ip: Ipv4Addr,
}

impl CovertChannel {
    pub fn new(target_ip: Ipv4Addr) -> Self {
        // We use Layer3 so we can manipulate the IPv4 header directly
        let (tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .expect("Failed to open raw socket. Run as root/sudo.");
        Self { tx, target_ip }
    }

    pub fn send_byte(&mut self, byte: u8) {
        let mut buffer = [0u8; 20]; 
        let mut packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(20);
        packet.set_ttl(64);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        packet.set_destination(self.target_ip);
        
        // Setting a source IP (even a fake one) helps with packet validity
        packet.set_source(Ipv4Addr::new(127, 0, 0, 1)); 
        
        // The core of the covert channel:
        // We cast the u8 byte to u16 to fit the IPID field.
        packet.set_identification(byte as u16); 

        let _ = self.tx.send_to(packet, std::net::IpAddr::V4(self.target_ip));
    }
}
