use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

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
        ).unwrap();
        now.format(&fmt).unwrap()
    }

    pub fn start(&self) -> io::Result<()> {
        let bind_ip = Self::prompt("Enter bind IP (e.g. 0.0.0.0): ");
        let port: u16 = Self::prompt("Enter UDP port to listen on: ")
            .parse()
            .expect("Invalid port");

        let addr: SocketAddr = format!("{}:{}", bind_ip, port)
            .parse()
            .expect("Invalid address");

        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;

        println!("\nPort knocker listening on {}\n", addr);

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
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
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

