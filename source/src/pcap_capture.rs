use chrono::Local;
use pcap::{Capture, Device};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
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

            println!("[*] PCAP capture started: {}", filename);

            let mut cap = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .timeout(1000)
                .open()
                .unwrap();

            let mut dump = cap.savefile(&filename).unwrap();

            while flag.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(packet) => {
                        dump.write(&packet);
                    }
                    Err(_) => {} // timeout / no packet
                }
            }

            println!("[*] PCAP capture stopped");
        });

        Self { running }
    }
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

