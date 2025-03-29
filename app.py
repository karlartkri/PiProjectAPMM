#!/usr/bin/env python3
import os
import netifaces
import logging
import time
import sys
import signal
import socket
import struct
import threading
import fcntl
import termios
import traceback
from datetime import datetime

# Configure logging with more detailed format
logging.basicConfig(
    filename='pi_controller.log',
    level=logging.DEBUG,  # Changed to DEBUG for more detailed logs
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Add console handler for immediate feedback
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Configuration
HOTSPOT_SSID = "PiZero_Hotspot"
HOTSPOT_PASSWORD = "pi123456"
INTERFACE = "wlan0"
DHCP_RANGE = "192.168.4.2,192.168.4.20"
NETWORK_MASK = "255.255.255.0"
GATEWAY_IP = "192.168.4.1"

# Network interface flags
IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_RUNNING = 0x40
IFF_MULTICAST = 0x1000

# WiFi frame types
FRAME_TYPE_MANAGEMENT = 0x00
FRAME_TYPE_CONTROL = 0x01
FRAME_TYPE_DATA = 0x02

# WiFi frame subtypes
FRAME_SUBTYPE_BEACON = 0x08
FRAME_SUBTYPE_PROBE_REQ = 0x04
FRAME_SUBTYPE_PROBE_RESP = 0x05
FRAME_SUBTYPE_AUTH = 0x0B
FRAME_SUBTYPE_ASSOC_REQ = 0x00
FRAME_SUBTYPE_ASSOC_RESP = 0x01

# WiFi capabilities
WIFI_CAP_ESS = 0x01
WIFI_CAP_PRIVACY = 0x02
WIFI_CAP_SHORT_PREAMBLE = 0x04
WIFI_CAP_PBCC = 0x08
WIFI_CAP_CHANNEL_AGILITY = 0x10
WIFI_CAP_SPECTRUM_MGMT = 0x20
WIFI_CAP_QOS = 0x40
WIFI_CAP_SHORT_SLOT = 0x80
WIFI_CAP_APSD = 0x100
WIFI_CAP_RADIOMETRY = 0x200
WIFI_CAP_DSSS_OFDM = 0x400
WIFI_CAP_DELAYED_BLOCK_ACK = 0x800
WIFI_CAP_IMMEDIATE_BLOCK_ACK = 0x1000

class WiFiFrame:
    """Basic WiFi frame structure"""
    def __init__(self):
        self.frame_control = 0
        self.duration = 0
        self.addr1 = b'\x00' * 6  # Destination
        self.addr2 = b'\x00' * 6  # Source
        self.addr3 = b'\x00' * 6  # BSSID
        self.seq_ctrl = 0
        self.addr4 = b'\x00' * 6  # Optional
        self.payload = b''

    def pack(self):
        """Pack frame into bytes"""
        return struct.pack('<H', self.frame_control) + \
               struct.pack('<H', self.duration) + \
               self.addr1 + self.addr2 + self.addr3 + \
               struct.pack('<H', self.seq_ctrl) + \
               self.addr4 + self.payload

    @staticmethod
    def unpack(data):
        """Unpack bytes into WiFi frame"""
        frame = WiFiFrame()
        frame.frame_control = struct.unpack('<H', data[0:2])[0]
        frame.duration = struct.unpack('<H', data[2:4])[0]
        frame.addr1 = data[4:10]
        frame.addr2 = data[10:16]
        frame.addr3 = data[16:22]
        frame.seq_ctrl = struct.unpack('<H', data[22:24])[0]
        frame.addr4 = data[24:30]
        frame.payload = data[30:]
        return frame

class PiController:
    def __init__(self):
        self.hotspot_active = False
        self.monitor_mode_active = False
        self.running = True
        self.clients = set()
        self.raw_socket = None
        self.monitor_socket = None
        self.beacon_interval = 0.1
        self.last_beacon_time = 0
        self.error_count = 0
        self.last_error_time = 0
        self.error_threshold = 5  # Max errors before restart
        self.error_window = 60  # Time window in seconds
        self.setup_signal_handlers()
        self.check_system_requirements()
        logger.info("PiController initialized successfully")

    def check_system_requirements(self):
        """Check if required system capabilities are available"""
        try:
            # Check for raw socket support
            self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.raw_socket.close()
        except Exception as e:
            logger.error(f"System requirements not met: {str(e)}")
            print("Error: System does not support required network capabilities.")
            sys.exit(1)

    def setup_signal_handlers(self):
        """Setup handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Shutdown signal received. Cleaning up...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """Cleanup resources before exit"""
        try:
            if self.monitor_mode_active:
                self.toggle_monitor_mode(False)
            if self.hotspot_active:
                self.stop_hotspot()
            if self.raw_socket:
                self.raw_socket.close()
            if self.monitor_socket:
                self.monitor_socket.close()
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    def check_root(self):
        """Check if the script is running with root privileges"""
        if os.geteuid() != 0:
            raise Exception("This program must be run as root (sudo)")

    def check_interface(self):
        """Verify if the wireless interface exists and is up"""
        try:
            ifaces = netifaces.interfaces()
            if INTERFACE not in ifaces:
                return False
            addrs = netifaces.ifaddresses(INTERFACE)
            return netifaces.AF_INET in addrs
        except Exception as e:
            logger.error(f"Error checking interface: {str(e)}")
            return False

    def configure_interface(self):
        """Configure network interface for AP mode using raw sockets"""
        try:
            # Create raw socket for interface configuration
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Get interface flags
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            
            # Set interface up
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags | IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            # Configure IP address
            ip = struct.unpack('>I', socket.inet_aton(GATEWAY_IP))[0]
            mask = struct.unpack('>I', socket.inet_aton(NETWORK_MASK))[0]
            
            ifreq = struct.pack('16sH2I', INTERFACE.encode(), 0, ip, mask)
            fcntl.ioctl(sock.fileno(), 0x8915, ifreq)
            
            sock.close()
            
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
        except Exception as e:
            raise Exception(f"Failed to configure interface: {str(e)}")

    def setup_hotspot(self):
        """Configure and start the WiFi hotspot"""
        try:
            if not self.check_interface():
                return False, "Wireless interface not found or not up"

            # Configure network interface
            self.configure_interface()
            
            # Start DHCP server
            self.start_dhcp_server()
            
            # Start beacon frame transmitter
            self.start_beacon_transmitter()
            
            # Start frame handler for both AP and monitor mode
            self.start_frame_handler()
            
            self.hotspot_active = True
            return True, "Hotspot started successfully"
        except Exception as e:
            logger.error(f"Error setting up hotspot: {str(e)}")
            return False, f"Error starting hotspot: {str(e)}"

    def start_dhcp_server(self):
        """Start DHCP server thread"""
        def dhcp_server():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('0.0.0.0', 67))
                
                while self.hotspot_active:
                    data, addr = sock.recvfrom(1024)
                    response = self.create_dhcp_response(data)
                    sock.sendto(response, addr)
            except Exception as e:
                logger.error(f"DHCP server error: {str(e)}")
            finally:
                sock.close()

        thread = threading.Thread(target=dhcp_server, daemon=True)
        thread.start()

    def create_dhcp_response(self, request):
        """Create DHCP response packet"""
        response = bytearray(request[:236])  # Copy header
        response[0] = 2  # Response type
        response[236:240] = struct.pack('>I', int(GATEWAY_IP.replace('.', '')))
        return bytes(response)

    def create_beacon_frame(self):
        """Create WiFi beacon frame with complete information"""
        frame = WiFiFrame()
        frame.frame_control = (FRAME_TYPE_MANAGEMENT << 2) | FRAME_SUBTYPE_BEACON
        frame.addr1 = b'\xff' * 6  # Broadcast
        
        # Konvertera MAC-adressen korrekt
        mac_str = "00:11:22:33:44:55"
        mac_bytes = bytes.fromhex(mac_str.replace(':', ''))
        frame.addr2 = mac_bytes  # BSSID
        frame.addr3 = mac_bytes  # BSSID
        frame.seq_ctrl = 0
        
        # Timestamp (8 bytes)
        timestamp = int(time.time() * 1000000)  # Microseconds
        beacon_interval = 100  # 100 TU (102.4ms)
        capabilities = WIFI_CAP_ESS | WIFI_CAP_PRIVACY | WIFI_CAP_SHORT_PREAMBLE
        
        # Build beacon payload
        payload = struct.pack('<Q', timestamp)  # Timestamp
        payload += struct.pack('<H', beacon_interval)  # Beacon interval
        payload += struct.pack('<H', capabilities)  # Capabilities
        
        # SSID element
        ssid_bytes = HOTSPOT_SSID.encode()
        payload += struct.pack('BB', 0, len(ssid_bytes)) + ssid_bytes
        
        # Supported rates
        rates = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]  # 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps
        payload += struct.pack('BB', 1, len(rates)) + bytes(rates)
        
        # Current channel
        payload += struct.pack('BBB', 3, 1, 7)  # Channel 7
        
        # RSN (WPA2) element
        rsn = struct.pack('<H', 0x30)  # Version
        rsn += struct.pack('<H', 0x01)  # Group cipher suite (CCMP)
        rsn += struct.pack('<H', 0x01)  # Pairwise cipher suite count
        rsn += struct.pack('<H', 0x00)  # Pairwise cipher suite (CCMP)
        rsn += struct.pack('<H', 0x01)  # AKM suite count
        rsn += struct.pack('<H', 0x02)  # AKM suite (PSK)
        rsn += struct.pack('<H', 0x00)  # RSN capabilities
        
        payload += struct.pack('BB', 48, len(rsn)) + rsn  # RSN element
        
        frame.payload = payload
        return frame

    def start_beacon_transmitter(self):
        """Start beacon frame transmitter thread with improved error handling"""
        def beacon_transmitter():
            consecutive_errors = 0
            try:
                self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                self.raw_socket.bind((INTERFACE, 0))
                logger.info("Beacon transmitter started successfully")
                
                while self.hotspot_active:
                    try:
                        current_time = time.time()
                        if current_time - self.last_beacon_time >= self.beacon_interval:
                            frame = self.create_beacon_frame()
                            self.raw_socket.send(frame.pack())
                            self.last_beacon_time = current_time
                            consecutive_errors = 0  # Reset error counter on success
                        time.sleep(0.01)
                    except Exception as e:
                        consecutive_errors += 1
                        self.log_error(f"Beacon transmission error (attempt {consecutive_errors}): {str(e)}")
                        if consecutive_errors >= 3:
                            logger.critical("Too many consecutive beacon errors, restarting transmitter")
                            break
                        time.sleep(0.1)  # Wait before retry
            except Exception as e:
                self.log_error(f"Beacon transmitter fatal error: {str(e)}")
            finally:
                if self.raw_socket:
                    self.raw_socket.close()
                logger.info("Beacon transmitter stopped")

        thread = threading.Thread(target=beacon_transmitter, daemon=True)
        thread.start()

    def start_frame_handler(self):
        """Start frame handler thread with improved error handling"""
        def frame_handler():
            consecutive_errors = 0
            try:
                self.monitor_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                self.monitor_socket.bind((INTERFACE, 0))
                logger.info("Frame handler started successfully")
                
                while self.hotspot_active or self.monitor_mode_active:
                    try:
                        data = self.monitor_socket.recv(2048)
                        if len(data) >= 24:
                            frame = WiFiFrame.unpack(data)
                            self.handle_frame(frame)
                            consecutive_errors = 0  # Reset error counter on success
                    except socket.timeout:
                        continue
                    except Exception as e:
                        consecutive_errors += 1
                        self.log_error(f"Frame handling error (attempt {consecutive_errors}): {str(e)}")
                        if consecutive_errors >= 3:
                            logger.critical("Too many consecutive frame handling errors, restarting handler")
                            break
                        time.sleep(0.1)  # Wait before retry
            except Exception as e:
                self.log_error(f"Frame handler fatal error: {str(e)}")
            finally:
                if self.monitor_socket:
                    self.monitor_socket.close()
                logger.info("Frame handler stopped")

        thread = threading.Thread(target=frame_handler, daemon=True)
        thread.start()

    def handle_frame(self, frame):
        """Handle received WiFi frames with improved error handling"""
        try:
            frame_type = (frame.frame_control >> 2) & 0x0F
            frame_subtype = frame.frame_control & 0x0F
            
            if frame_type == FRAME_TYPE_MANAGEMENT:
                if frame_subtype == FRAME_SUBTYPE_PROBE_REQ:
                    self.handle_probe_request(frame)
                elif frame_subtype == FRAME_SUBTYPE_AUTH:
                    self.handle_auth_request(frame)
                elif frame_subtype == FRAME_SUBTYPE_ASSOC_REQ:
                    self.handle_assoc_request(frame)
            
            if self.monitor_mode_active:
                self.log_frame(frame)
        except Exception as e:
            self.log_error(f"Error handling frame: {str(e)}")

    def handle_probe_request(self, frame):
        """Handle probe request frames with improved response"""
        if self.hotspot_active:
            response = self.create_probe_response(frame)
            try:
                self.raw_socket.send(response.pack())
            except Exception as e:
                logger.error(f"Error sending probe response: {str(e)}")

    def handle_auth_request(self, frame):
        """Handle authentication request frames with improved response"""
        if self.hotspot_active:
            response = self.create_auth_response(frame)
            try:
                self.raw_socket.send(response.pack())
            except Exception as e:
                logger.error(f"Error sending auth response: {str(e)}")

    def handle_assoc_request(self, frame):
        """Handle association request frames with improved response"""
        if self.hotspot_active:
            response = self.create_assoc_response(frame)
            try:
                self.raw_socket.send(response.pack())
                self.clients.add(frame.addr2)
                logger.info(f"Client associated: {frame.addr2.hex(':')}")
            except Exception as e:
                logger.error(f"Error sending assoc response: {str(e)}")

    def create_probe_response(self, request):
        """Create probe response frame with complete information"""
        response = WiFiFrame()
        response.frame_control = (FRAME_TYPE_MANAGEMENT << 2) | FRAME_SUBTYPE_PROBE_RESP
        response.addr1 = request.addr2  # Destination is the requester
        
        # Konvertera MAC-adressen korrekt
        mac_str = "00:11:22:33:44:55"
        mac_bytes = bytes.fromhex(mac_str.replace(':', ''))
        response.addr2 = mac_bytes  # Source
        response.addr3 = mac_bytes  # BSSID
        
        response.seq_ctrl = 0
        response.payload = self.create_beacon_frame().payload
        return response

    def create_auth_response(self, request):
        """Create authentication response frame"""
        response = WiFiFrame()
        response.frame_control = (FRAME_TYPE_MANAGEMENT << 2) | FRAME_SUBTYPE_AUTH
        response.addr1 = request.addr2
        response.addr2 = request.addr3
        response.addr3 = request.addr2
        response.seq_ctrl = 0
        
        # Authentication response payload
        response.payload = struct.pack('<H', 0)  # Authentication algorithm (Open System)
        response.payload += struct.pack('<H', 0)  # Authentication sequence number
        response.payload += struct.pack('<H', 0)  # Status code (Success)
        return response

    def create_assoc_response(self, request):
        """Create association response frame"""
        response = WiFiFrame()
        response.frame_control = (FRAME_TYPE_MANAGEMENT << 2) | FRAME_SUBTYPE_ASSOC_RESP
        response.addr1 = request.addr2
        response.addr2 = request.addr3
        response.addr3 = request.addr2
        response.seq_ctrl = 0
        
        # Association response payload
        response.payload = struct.pack('<H', 0)  # Capabilities
        response.payload += struct.pack('<H', 0)  # Status code (Success)
        response.payload += struct.pack('<H', 1)  # Association ID
        return response

    def log_frame(self, frame):
        """Enhanced frame logging with more details"""
        try:
            frame_type = (frame.frame_control >> 2) & 0x0F
            frame_subtype = frame.frame_control & 0x0F
            
            type_str = {
                FRAME_TYPE_MANAGEMENT: "Management",
                FRAME_TYPE_CONTROL: "Control",
                FRAME_TYPE_DATA: "Data"
            }.get(frame_type, "Unknown")
            
            subtype_str = {
                FRAME_SUBTYPE_BEACON: "Beacon",
                FRAME_SUBTYPE_PROBE_REQ: "Probe Request",
                FRAME_SUBTYPE_PROBE_RESP: "Probe Response",
                FRAME_SUBTYPE_AUTH: "Authentication",
                FRAME_SUBTYPE_ASSOC_REQ: "Association Request",
                FRAME_SUBTYPE_ASSOC_RESP: "Association Response"
            }.get(frame_subtype, "Unknown")
            
            logger.debug(f"Frame Details:")
            logger.debug(f"Type: {type_str} - {subtype_str}")
            logger.debug(f"From: {frame.addr2.hex(':')}")
            logger.debug(f"To: {frame.addr1.hex(':')}")
            logger.debug(f"BSSID: {frame.addr3.hex(':')}")
            logger.debug(f"Sequence: {frame.seq_ctrl}")
            logger.debug(f"Payload length: {len(frame.payload)}")
        except Exception as e:
            self.log_error(f"Error logging frame: {str(e)}")

    def stop_hotspot(self):
        """Stop the WiFi hotspot"""
        try:
            self.hotspot_active = False
            time.sleep(1)  # Wait for threads to stop
            
            # Reset interface using raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Get interface flags
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            
            # Bring interface down
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags & ~IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            # Bring interface up
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags | IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            sock.close()
            
            # Disable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0')
            
            return True, "Hotspot stopped successfully"
        except Exception as e:
            logger.error(f"Error stopping hotspot: {str(e)}")
            return False, f"Error stopping hotspot: {str(e)}"

    def toggle_monitor_mode(self, enable=True):
        """Enable or disable monitor mode using raw sockets"""
        try:
            if not self.check_interface():
                return False, "Wireless interface not found or not up"

            # Create raw socket for interface configuration
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Get interface flags
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            
            # Bring interface down
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags & ~IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            time.sleep(1)

            if enable:
                # Set monitor mode using raw socket
                self.monitor_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                self.monitor_socket.bind((INTERFACE, 0))
                self.monitor_socket.close()

            # Bring interface up
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags | IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            sock.close()
            
            self.monitor_mode_active = enable
            return True, f"Monitor mode {'enabled' if enable else 'disabled'}"
        except Exception as e:
            logger.error(f"Error toggling monitor mode: {str(e)}")
            return False, f"Error changing monitor mode: {str(e)}"

    def get_status(self):
        """Get current status of all features"""
        return {
            'hotspot': 'O' if self.hotspot_active else 'X',
            'monitor': 'O' if self.monitor_mode_active else 'X'
        }

    def display_menu(self):
        """Display the main menu"""
        status = self.get_status()
        os.system('clear')
        print("\n=== Pi Zero W Controller ===")
        print(f"Hotspot Status: [{status['hotspot']}]")
        print(f"Monitor Mode: [{status['monitor']}]")
        print("\nOptions:")
        print("1. Toggle Hotspot")
        print("2. Toggle Monitor Mode")
        print("3. Show Log")
        print("4. Exit")
        print("\nSelect an option (1-4): ")

    def show_log(self):
        """Display recent log entries"""
        try:
            if not os.path.exists('pi_controller.log'):
                print("\nNo log file found.")
                input("\nPress Enter to continue...")
                return

            with open('pi_controller.log', 'r') as f:
                print("\n=== Recent Log Entries ===")
                for line in f.readlines()[-10:]:
                    print(line.strip())
            input("\nPress Enter to continue...")
        except Exception as e:
            print(f"Error reading log: {str(e)}")
            input("\nPress Enter to continue...")

    def log_error(self, error_msg, exc_info=True):
        """Enhanced error logging with error tracking"""
        current_time = time.time()
        
        # Reset error count if outside error window
        if current_time - self.last_error_time > self.error_window:
            self.error_count = 0
        
        self.error_count += 1
        self.last_error_time = current_time
        
        # Log detailed error information
        logger.error(f"ERROR: {error_msg}", exc_info=exc_info)
        
        # Log system state
        logger.debug(f"Current state - Hotspot: {self.hotspot_active}, Monitor: {self.monitor_mode_active}")
        logger.debug(f"Error count: {self.error_count}/{self.error_threshold}")
        
        # Check if we need to restart
        if self.error_count >= self.error_threshold:
            logger.critical("Error threshold reached, initiating restart")
            self.handle_critical_error()

    def handle_critical_error(self):
        """Handle critical errors by attempting recovery"""
        try:
            logger.info("Attempting system recovery...")
            
            # Stop all services
            if self.hotspot_active:
                self.stop_hotspot()
            if self.monitor_mode_active:
                self.toggle_monitor_mode(False)
            
            # Reset interface
            self.reset_interface()
            
            # Reset error counters
            self.error_count = 0
            self.last_error_time = 0
            
            logger.info("System recovery completed")
        except Exception as e:
            logger.critical(f"Recovery failed: {str(e)}", exc_info=True)
            self.cleanup()
            sys.exit(1)

    def reset_interface(self):
        """Reset network interface to default state"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Get current flags
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            
            # Bring interface down
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags & ~IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            time.sleep(1)
            
            # Bring interface up
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags | IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            sock.close()
            logger.info("Network interface reset successfully")
        except Exception as e:
            self.log_error(f"Failed to reset interface: {str(e)}")

    def run(self):
        """Main application loop"""
        try:
            self.check_root()
            while self.running:
                self.display_menu()
                choice = input().strip()
                
                if choice == '1':
                    if self.hotspot_active:
                        success, message = self.stop_hotspot()
                    else:
                        success, message = self.setup_hotspot()
                    print(f"\n{message}")
                    time.sleep(2)
                
                elif choice == '2':
                    success, message = self.toggle_monitor_mode(not self.monitor_mode_active)
                    print(f"\n{message}")
                    time.sleep(2)
                
                elif choice == '3':
                    self.show_log()
                
                elif choice == '4':
                    self.cleanup()
                    self.running = False
                
                else:
                    print("\nInvalid option. Please try again.")
                    time.sleep(1)
        
        except Exception as e:
            logger.error(f"Critical error: {str(e)}")
            print(f"\nCritical error occurred. Check pi_controller.log for details.")
            self.cleanup()
            sys.exit(1)

if __name__ == '__main__':
    controller = PiController()
    controller.run() 