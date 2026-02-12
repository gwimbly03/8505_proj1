use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::MutablePacket;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};

use rand::rngs::StdRng;
use rand::{SeedableRng, Rng};


const KNOCK_COUNT: usize = 3;

/* =========================
 * SEED + RNG
 * ========================= */

fn seed_from_ip(ip: &str) -> u64 {
    ip.bytes().fold(0u64, |acc, b| acc.wrapping_mul(131).wrapping_add(b as u64))
}

fn time_entropy() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn generate_seed(ip: &str) -> u64 {
    seed_from_ip(ip) ^ time_entropy()
}

fn generate_port(rng: &mut StdRng) -> u16 {
    rng.gen_range(1024..=65535)
}


/* =========================
 * KNOCK SEQUENCE
 * ========================= */

fn generate_knock_sequence(ip: &str) -> Vec<u16> {
    let seed = generate_seed(ip);
    let mut rng = StdRng::seed_from_u64(seed);

    (0..KNOCK_COUNT)
        .map(|_| generate_port(&mut rng))
        .collect()
}

/* =========================
 * RAW TCP SYN SENDER
 * ========================= */

fn send_syn(dest_ip: Ipv4Addr, dest_port: u16) -> io::Result<()> {
    let (mut tx, _) = transport_channel(
        1024,
        Layer3(IpNextHeaderProtocols::Tcp),
    )?;

    let mut buffer = [0u8; 40];

    let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(Ipv4Addr::new(127, 0, 0, 1));
    ip_packet.set_destination(dest_ip);

    let mut tcp_packet =
        MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();

    tcp_packet.set_source(40000 + (dest_port % 2000));
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);

    tx.send_to(ip_packet, IpAddr::V4(dest_ip))?;
    Ok(())
}

/* =========================
 * PUBLIC ENTRY POINT
 * ========================= */

pub fn port_knock() -> io::Result<()> {
    print!("Enter victim IP (blank = 0.0.0.0): ");
    io::Write::flush(&mut io::stdout())?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let ip_str = input.trim();
    let ip = if ip_str.is_empty() {
        Ipv4Addr::new(0, 0, 0, 0)
    } else {
        ip_str.parse().expect("Invalid IPv4 address")
    };

    let knocks = generate_knock_sequence(&ip.to_string());

    println!("[*] Knock sequence: {:?}", knocks);

    for port in knocks {
        send_syn(ip, port)?;
        println!("[+] Knocked port {}", port);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    println!("[✓] Port knock complete");
    Ok(())
}

