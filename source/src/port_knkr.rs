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
    pub stop_flag: Arc<AtomicBool>,
    pub control_port: u16, // The port "allowed" to run services on
}

impl KnockSession {
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// Generates a seed based on IP and current time (synced by minute)
// This allows both sides to agree on a seed if their clocks are roughly synced
pub fn generate_seed(ip: &Ipv4Addr) -> u64 {
    let ip_u32: u32 = (*ip).into();
    let time_step = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() / 60; // Changes every minute
    (ip_u32 as u64) ^ time_step
}

pub fn port_knock(ip: Ipv4Addr) -> io::Result<KnockSession> {
    let seed = generate_seed(&ip);
    let mut rng = SimpleRng::new(seed);
    
    // Generate the 3-port sequence
    let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
    // Generate the "allowed" port for the session
    let control_port = rng.gen_port();

    println!("[*] Secret knock sequence: {:?}", knocks);
    println!("[*] Targeted control port: {}", control_port);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            for port in knocks.iter() {
                if stop_clone.load(Ordering::SeqCst) { break; }
                
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(800) {
                    let _ = send_syn(ip, *port);
                    thread::sleep(Duration::from_millis(150));
                }
                thread::sleep(Duration::from_millis(300));
            }
        }
    });

    Ok(KnockSession { stop_flag, control_port })
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
    ip.set_destination(dest_ip);

    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(40000 + (dest_port % 2000));
    tcp.set_destination(dest_port);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_data_offset(5);

    tx.send_to(ip, IpAddr::V4(dest_ip))?;
    Ok(())
}
