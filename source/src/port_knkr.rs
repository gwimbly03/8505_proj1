use std::io;
use std::net::{Ipv4Addr, IpAddr};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};

pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        (self.state >> 32) as u32
    }

    pub fn gen_port(&mut self) -> u16 {
        1024 + (self.next_u32() % (65535 - 1024)) as u16
    }
}

pub struct KnockSession {
    stop_flag: Arc<AtomicBool>,
}

impl KnockSession {
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

fn generate_seed(ip: &str) -> u64 {
    let ip_part = ip.bytes().fold(0u64, |a, b| a.wrapping_mul(131).wrapping_add(b as u64));
    let time_part = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    ip_part ^ time_part
}

fn send_syn(dest_ip: Ipv4Addr, dest_port: u16) -> io::Result<()> {
    let (mut tx, _) = transport_channel(1024, Layer3(IpNextHeaderProtocols::Tcp))?;

    let mut buffer = [0u8; 40];
    let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();

    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(40);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(Ipv4Addr::UNSPECIFIED); // kernel chooses
    ip.set_destination(dest_ip);

    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(40000 + (dest_port % 2000));
    tcp.set_destination(dest_port);
    tcp.set_sequence(0);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(64240);
    tcp.set_data_offset(5);

    tx.send_to(ip, IpAddr::V4(dest_ip))?;
    Ok(())
}

pub fn port_knock() -> io::Result<KnockSession> {
    print!("Enter victim IP (default = 0.0.0.0): ");
    io::Write::flush(&mut io::stdout())?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let ip_str = input.trim();

    let ip: Ipv4Addr = if ip_str.is_empty() {
        "0.0.0.0".parse().unwrap()
    } else {
        ip_str.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid IPv4 address"))?
    };

    let seed = generate_seed(&ip.to_string());
    let mut rng = SimpleRng::new(seed);
    let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];

    println!("[*] Knock sequence: {:?}", knocks);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let ip_clone = ip.clone();

    thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            for port in knocks.iter() {
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(800) {
                    if let Err(e) = send_syn(ip_clone, *port) {
                        eprintln!("[!] Failed sending SYN to {}:{}: {}", ip_clone, port, e);
                    }
                    thread::sleep(Duration::from_millis(150));
                }
                thread::sleep(Duration::from_millis(300));
            }
        }
    });

    Ok(KnockSession { stop_flag })
}

