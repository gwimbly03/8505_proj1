mod port_knkr;

use port_knkr::PortKnocker;
use std::io::{self, Write};

fn print_menu() {
    println!("=== Victim Control Menu ===");
    println!("1) Start port knocker");
    println!("2) Exit");
    print!("Select option: ");
    io::stdout().flush().unwrap();
}

fn main() -> io::Result<()> {
    let knocker = PortKnocker::new();

    loop {
        print_menu();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => {
                knocker.start()?;
            }
            "2" => {
                println!("Exiting.");
                break;
            }
            _ => {
                println!("Invalid selection.\n");
            }
        }
    }

    Ok(())
}

