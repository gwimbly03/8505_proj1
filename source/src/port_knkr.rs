use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{SeedableRng, Rng};


use time::{OffsetDateTime, format_description};

pub struct PortKnocker {
    stop: Arc<AtomicBool>,
}

impl PortKnocker {
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    fn generate_port(seed: u64) -> u16 {
        let mut rng = StdRng::seed_from_u64(seed);

        let port = (rng.next_u32() % (65535 - 1024 + 1)) + 1024;
        port as u16
    }

    fn prompt(msg: &str) -> String {
        print!("{}", msg);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    fn timestamp() -> String {
        let now = OffsetDateTime::now_utc();
        let fmt = format_description::parse(
            "[year]-[month]-[day] [hour]:[minute]:[second]",
        )
        .unwrap();

        now.format(&fmt).unwrap()
    }

    pub fn start(&self) -> io::Result<()> {
        let mut bind_ip =
            Self::prompt("Enter bind IP [default: 0.0.0.0]: ");
        if bind_ip.is_empty() {
            bind_ip = "0.0.0.0".to_string();
        }

        let seed: u64 = Self::prompt("Enter shared seed: ")
            .parse()
            .expect("Invalid seed");

        let port = Self::generate_port(seed);

        let addr: SocketAddr = format!("{}:{}", bind_ip, port)
            .parse()
            .expect("Invalid address");

        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;

        println!(
            "\nPort knocker listening on {} (seed-derived port {})\n",
            addr, port
        );

        let stop_signal = self.stop.clone();
        ctrlc::set_handler(move || {
            stop_signal.store(true, Ordering::SeqCst);
        })
        .expect("Failed to install Ctrl-C handler");

        let mut buf = vec![0u8; 2048];

        while !self.stop.load(Ordering::SeqCst) {
            match socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    println!(
                        "{} knock dst_port={} src={} bytes={}",
                        Self::timestamp(),
                        port,
                        src,
                        n
                    );
                }
                Err(e)
                    if e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => {
                    eprintln!("recv_from error: {}", e);
                    break;
                }
            }
        }

        println!("Port knocker stopped.\n");
        self.stop.store(false, Ordering::SeqCst);
        Ok(())
    }
}

