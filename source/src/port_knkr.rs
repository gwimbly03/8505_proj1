use std::io;
use std::net::{Ipv4Addr, IpAddr};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket; // Required for payload_mut()
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use pnet::datalink;

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

pub struct KnockSession {
    pub stop_flag: Arc<AtomicBool>,
    pub tx_port: u16, 
    pub rx_port: u16, 
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

fn find_local_ip() -> Option<Ipv4Addr> {
    datalink::interfaces().into_iter().find(|iface| {
        iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty()
    }).and_then(|iface| {
        iface.ips.iter().find_map(|ip| {
            if let IpAddr::V4(v4) = ip.ip() { Some(v4) } else { None }
        })
    })
}

pub fn port_knock(target_ip: Ipv4Addr) -> io::Result<KnockSession> {
    let seed = generate_seed(&target_ip, 0);
    let mut rng = SimpleRng::new(seed);
    
    let knocks = [rng.gen_port(), rng.gen_port(), rng.gen_port()];
    let tx_port = rng.gen_port(); 
    let rx_port = rng.gen_port(); 

    let local_ip = find_local_ip().expect("Could not determine local IP");

    println!("[*] Target: {} | Knock Sequence: {:?}", target_ip, knocks);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            for port in knocks.iter() {
                if stop_clone.load(Ordering::SeqCst) { break; }
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(500) {
                    let _ = send_syn(local_ip, target_ip, *port);
                    thread::sleep(Duration::from_millis(100));
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    });

    Ok(KnockSession { stop_flag, tx_port, rx_port })
}

fn send_syn(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, dest_port: u16) -> io::Result<()> {
    let (mut tx, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))?;
    let mut buffer = [0u8; 40];
    let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();

    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(40);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(src_ip);
    ip.set_destination(dest_ip);

    // FIXED: Borrow the payload from 'ip' instead of borrowing 'buffer' again
    {
        let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
        tcp.set_source(40000 + (dest_port % 2000));
        tcp.set_destination(dest_port);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_data_offset(5);

        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dest_ip);
        tcp.set_checksum(checksum);
    }

    tx.send_to(ip, IpAddr::V4(dest_ip))?;
    Ok(())
}
