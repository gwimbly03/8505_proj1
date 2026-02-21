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

// --- RNG Implementation (Unchanged) ---
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

// --- Updated Session Struct ---
pub struct KnockSession {
    pub stop_flag: Arc<AtomicBool>,
    pub tx_port: u16, // Port we SEND to (Target's Listener)
    pub rx_port: u16, // Port we LISTEN on (Target sends here)
}

impl KnockSession {
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

pub fn generate_seed(ip: &Ipv4Addr, offset: i64) -> u64 {
    let ip_u32: u32 = (*ip).into();
    // Use 1-minute windows for the seed, allowing for the offset to handle drift
    let time_step = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 / 60) + offset;
    
    (ip_u32 as u64) ^ (time_step as u64)
}

pub fn port_knock(ip: Ipv4Addr) -> io::Result<KnockSession> {
    let seed = generate_seed(&ip, 0);
    let mut rng = SimpleRng::new(seed);
    
    // 1. Generate the 3-port knock sequence
    let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
    
    // 2. Generate Command & Response ports deterministically
    let tx_port = rng.gen_port(); // The port the Target will listen on
    let rx_port = rng.gen_port(); // The port the Target will send back to

    println!("[*] Secret Knock: {:?}", knocks);
    println!("[*] Derived Channels -> TX: {} | RX: {}", tx_port, rx_port);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    // Spawn background knocker
    thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            for port in knocks.iter() {
                if stop_clone.load(Ordering::SeqCst) { break; }
                
                let start = Instant::now();
                // Knock duration logic
                while start.elapsed() < Duration::from_millis(800) {
                    let _ = send_syn(ip, *port);
                    thread::sleep(Duration::from_millis(150));
                }
                thread::sleep(Duration::from_millis(300));
            }
        }
    });

    Ok(KnockSession { stop_flag, tx_port, rx_port })
}

fn send_syn(dest_ip: Ipv4Addr, dest_port: u16) -> io::Result<()> {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))?;
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
