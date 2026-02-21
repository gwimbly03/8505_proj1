use std::io;
use std::net::{Ipv4Addr, IpAddr};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
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

// NOTE: Added `src_ip` as a parameter to calculate valid checksums.
pub fn port_knock(src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> io::Result<KnockSession> {
    let time_step = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 60;
    println!("[*] Current Time Window (mins since epoch): {}", time_step); // Helps debug clock drift
    
    let seed = generate_seed(&dest_ip, 0);
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
                    // Generate dynamic source port and sequence number to avoid predictable tracking
                    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
                    let dynamic_src_port = (40000 + (nanos % 20000)) as u16;
                    let seq_num = nanos;

                    let _ = send_syn(src_ip, dest_ip, *port, dynamic_src_port, seq_num);
                    thread::sleep(Duration::from_millis(150));
                }
                thread::sleep(Duration::from_millis(300));
            }
        }
    });

    Ok(KnockSession { stop_flag, tx_port, rx_port })
}

fn send_syn(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, dest_port: u16, src_port: u16, seq: u32) -> io::Result<()> {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))?;
    let mut buffer = [0u8; 40]; // 20 bytes IP + 20 bytes TCP
    
    let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(40);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(src_ip);
    ip.set_destination(dest_ip);

    // Build TCP inside the IP payload
    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dest_port);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(64240); // Added window size for better realism
    tcp.set_data_offset(5);
    tcp.set_sequence(seq);

    // 1. Calculate and set TCP checksum (Requires IP source and destination)
    let tcp_checksum = tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dest_ip);
    tcp.set_checksum(tcp_checksum);
    
    // 2. Calculate and set IP checksum (Only covers IP header)
    let ip_checksum = ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(ip_checksum);

    tx.send_to(ip, IpAddr::V4(dest_ip))?;
    Ok(())
}
