use std::io;
use std::net::{Ipv4Addr, IpAddr};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportSender};

// --- RNG Implementation ---
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

// --- Session Struct ---
pub struct KnockSession {
    pub stop_flag: Arc<AtomicBool>,
    pub tx_port: u16, // Port the Target listens on (Covert DST)
    pub rx_port: u16, // Port the Target replies to (Covert SRC)
}

impl KnockSession {
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

pub fn generate_seed(ip: &Ipv4Addr, offset: i64) -> u64 {
    let ip_u32: u32 = (*ip).into();
    let time_step = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 / 60) + offset;
    
    (ip_u32 as u64) ^ (time_step as u64)
}

/// Initializes the knocking sequence and returns the ports needed for covert.rs
pub fn port_knock(target_ip: Ipv4Addr) -> io::Result<KnockSession> {
    let seed = generate_seed(&target_ip, 0);
    let mut rng = SimpleRng::new(seed);
    
    let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
    let tx_port = rng.gen_port(); 
    let rx_port = rng.gen_port(); 

    println!("[+] Knocking Sequence: {:?}", knocks);
    println!("[+] Covert Channel -> Target Listener: {} | Local Listener: {}", tx_port, rx_port);

    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))?;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            for &port in &knocks {
                if stop_clone.load(Ordering::SeqCst) { break; }
                
                let start = Instant::now();
                // Send a burst of SYNs to the knock port
                while start.elapsed() < Duration::from_millis(500) {
                    let _ = send_raw_syn(&mut tx, target_ip, port);
                    thread::sleep(Duration::from_millis(100));
                }
                thread::sleep(Duration::from_millis(200));
            }
            break;
        }
    });

    Ok(KnockSession { stop_flag, tx_port, rx_port })
}

fn send_raw_syn(tx: &mut TransportSender, dest_ip: Ipv4Addr, dest_port: u16) -> io::Result<()> {
    let mut buffer = [0u8; 40];
    let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(40);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_destination(dest_ip);
    // Source IP is usually filled by kernel or needs setting if not routing locally
    // For raw sockets, setting source helps consistency
    // ip.set_source(...); 

    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(54321); 
    tcp.set_destination(dest_port);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_data_offset(5);
    tcp.set_checksum(0); // Kernel often recalculates or ignores for raw

    // Fix: Pass reference to packet, not value
    tx.send_to(&ip, IpAddr::V4(dest_ip))?;
    Ok(())
}
