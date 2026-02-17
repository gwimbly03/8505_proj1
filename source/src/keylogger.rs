use evdev::{Device, EventSummary, KeyCode};
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use std::io;

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

        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(" ")
        }
    }
}

/// Find the first keyboard device
fn find_keyboard() -> io::Result<(Device, String)> {
    for entry in fs::read_dir("/dev/input")? {
        let path = entry?.path();

        if !path.to_string_lossy().contains("event") {
            continue;
        }

        if let Ok(device) = Device::open(&path) {
            if let Some(keys) = device.supported_keys() {
                if keys.contains(KeyCode::KEY_A)
                    && keys.contains(KeyCode::KEY_ENTER)
                    && keys.contains(KeyCode::KEY_LEFTSHIFT)
                {
                    return Ok((device, path.to_string_lossy().to_string()));
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No keyboard device found",
    ))
}

/// 🔧 Proper Parallels Remapping
fn parallels_remap(key: KeyCode) -> KeyCode {
    match key {
        // Parallels swaps Meta and Alt
        KeyCode::KEY_LEFTMETA => KeyCode::KEY_LEFTALT,
        KeyCode::KEY_RIGHTMETA => KeyCode::KEY_RIGHTALT,
        KeyCode::KEY_LEFTALT => KeyCode::KEY_LEFTMETA,
        KeyCode::KEY_RIGHTALT => KeyCode::KEY_RIGHTMETA,
        _ => key,
    }
}

pub fn run() -> io::Result<()> {
    // Find the keyboard
    let (mut device, path) = find_keyboard()?;

    println!("Capturing key events from: {}", path);
    println!("Device name: {}", device.name().unwrap_or("Unknown"));
    println!("Device path: {}", path);

    let id = device.input_id();
    println!(
        "Device ID: bus=0x{:?} vendor=0x{:04x} product=0x{:04x} version=0x{:04x}",
        id.bus_type(), // <--- cast enum to u16
        id.vendor(),
        id.product(),
        id.version()
    );

    println!();
    println!("Press Ctrl+C to stop...");
    println!("===========================================================================");
    println!("{:<15} {:<10} {:<20} {:<10} {:<20}",
        "RelTime", "Type", "Code", "Value", "Modifiers");
    println!("===========================================================================");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    let start_time = Instant::now();
    let mut modifiers = Modifiers::default();
    let mut printed_since_syn = false;

    // ✅ Fully event-driven
    while running.load(Ordering::SeqCst) {
        for ev in device.fetch_events()? {
            let rel = start_time.elapsed();
            let rel_str = format!(
                "+{:>3}.{:06}",
                rel.as_secs(),
                rel.subsec_micros()
            );

            match ev.destructure() {
                EventSummary::Key(_, raw_key, value) => {
                    // 🔧 Apply Parallels fix BEFORE using key
                    let key = parallels_remap(raw_key);

                    let value_str = match value {
                        0 => "RELEASE",
                        1 => "PRESS",
                        2 => "REPEAT",
                        _ => "UNKNOWN",
                    };

                    println!("{:<15} {:<10} {:<20} {:<10} [{}]",
                        rel_str,
                        "EV_KEY",
                        format!("{:?}", key),
                        value_str,
                        modifiers.display()
                    );

                    modifiers.update(key, value);
                    printed_since_syn = true;
                }

                EventSummary::Synchronization(..) if printed_since_syn => {
                    println!("{:<15} {:<10} {:<20} {:<10} [---event boundary---]",
                        rel_str,
                        "EV_SYN",
                        "SYN_REPORT",
                        "0"
                    );
                    printed_since_syn = false;
                }

                _ => {}
            }
        }
    }

    println!("\nCapture stopped.");
    Ok(())
}

fn main() -> io::Result<()> {
    run()
}

