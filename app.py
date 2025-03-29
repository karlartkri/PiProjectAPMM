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
import psutil

# ANSI Color Codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
END = '\033[0m'

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
        self.error_threshold = 5
        self.error_window = 60
        self.backup_dir = "system_backups"
        self.setup_signal_handlers()
        self.check_system_requirements()
        self.create_backup_dir()
        self.create_system_backup()
        
        # Verifiera systemtillstånd
        if not self.verify_system_state():
            logger.warning("System state verification failed, attempting recovery")
            self.handle_critical_error()
        
        logger.info("PiController initialized successfully")

    def check_system_requirements(self):
        """Check system requirements with improved error handling"""
        try:
            # Check root privileges
            if os.geteuid() != 0:
                raise Exception("Root privileges required")

            # Check interface existence
            if INTERFACE not in netifaces.interfaces():
                raise Exception(f"Interface {INTERFACE} not found")

            # Check raw socket support
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                sock.close()
            except Exception as e:
                raise Exception(f"Raw socket support not available: {str(e)}")

            # Check interface capabilities
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            sock.close()

            logger.info("System requirements met")
        except Exception as e:
            self.log_error(f"System requirements not met: {str(e)}")
            raise

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
        """Configure network interface for AP mode with improved error handling"""
        try:
            # Create raw socket for interface configuration
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Get interface flags
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            
            # Bring interface down first
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags & ~IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            time.sleep(1)  # Wait for interface to come down
            
            # Configure IP address
            ip = struct.unpack('>I', socket.inet_aton(GATEWAY_IP))[0]
            mask = struct.unpack('>I', socket.inet_aton(NETWORK_MASK))[0]
            
            ifreq = struct.pack('16sH2I', INTERFACE.encode(), 0, ip, mask)
            fcntl.ioctl(sock.fileno(), 0x8915, ifreq)
            
            # Bring interface up
            ifreq = struct.pack('16sH', INTERFACE.encode(), flags | IFF_UP)
            fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
            
            # Wait for interface to come up
            time.sleep(2)
            
            # Verify interface is up
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            if not (flags & IFF_UP):
                raise Exception("Interface failed to come up")
            
            sock.close()
            
            # Enable IP forwarding
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1')
            except Exception as e:
                self.log_error(f"Failed to enable IP forwarding: {str(e)}")
                # Continue anyway as this is not critical
                
            logger.info("Interface configured successfully")
        except Exception as e:
            self.log_error(f"Failed to configure interface: {str(e)}")
            raise

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
        """Start DHCP server thread with improved error handling"""
        def dhcp_server():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', 67))
                logger.info("DHCP server started successfully")
                
                while self.hotspot_active:
                    try:
                        data, addr = sock.recvfrom(1024)
                        if len(data) >= 236:  # Minimum DHCP packet size
                            response = self.create_dhcp_response(data)
                            if response:
                                sock.sendto(response, addr)
                                logger.debug(f"Sent DHCP response to {addr}")
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.log_error(f"DHCP server error: {str(e)}")
                        time.sleep(0.1)  # Kort paus vid fel
            except Exception as e:
                self.log_error(f"DHCP server fatal error: {str(e)}")
            finally:
                sock.close()
                logger.info("DHCP server stopped")

        thread = threading.Thread(target=dhcp_server, daemon=True)
        thread.start()

    def create_dhcp_response(self, request):
        """Create DHCP response packet with complete configuration"""
        try:
            # Kopiera DHCP header
            response = bytearray(request[:236])
            
            # Sätt response type
            response[0] = 2  # DHCP Offer
            
            # Sätt server IP (vår gateway)
            response[236:240] = struct.pack('>I', int(GATEWAY_IP.replace('.', '')))
            
            # Sätt client IP (från DHCP range)
            client_ip = "192.168.4.2"  # Första IP i range
            response[244:248] = struct.pack('>I', int(client_ip.replace('.', '')))
            
            # Sätt lease time (24 timmar)
            response[252:256] = struct.pack('>I', 86400)
            
            # Lägg till DHCP options
            options = bytearray()
            
            # Subnet mask
            options.extend([1, 4, 255, 255, 255, 0])
            
            # Router (gateway)
            options.extend([3, 4])
            options.extend(struct.pack('>I', int(GATEWAY_IP.replace('.', ''))))
            
            # DNS server
            options.extend([6, 4])
            options.extend(struct.pack('>I', int(GATEWAY_IP.replace('.', ''))))
            
            # DHCP server identifier
            options.extend([54, 4])
            options.extend(struct.pack('>I', int(GATEWAY_IP.replace('.', ''))))
            
            # End marker
            options.append(255)
            
            response.extend(options)
            
            logger.debug(f"Created DHCP response for client {client_ip}")
            return bytes(response)
        except Exception as e:
            self.log_error(f"Error creating DHCP response: {str(e)}")
            return None

    def create_beacon_frame(self):
        """Create WiFi beacon frame with complete information"""
        frame = WiFiFrame()
        frame.frame_control = (FRAME_TYPE_MANAGEMENT << 2) | FRAME_SUBTYPE_BEACON
        frame.addr1 = b'\xff' * 6  # Broadcast
        
        # Använd en enklare MAC-adress
        mac_bytes = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
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
            retry_delay = 0.1  # Start with 100ms delay
            
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
                            consecutive_errors = 0
                            retry_delay = 0.1  # Reset delay on success
                            logger.debug("Sent beacon frame successfully")
                        time.sleep(0.01)
                    except Exception as e:
                        consecutive_errors += 1
                        self.log_error(f"Beacon transmission error (attempt {consecutive_errors}): {str(e)}")
                        
                        # Exponential backoff
                        retry_delay = min(retry_delay * 2, 1.0)
                        time.sleep(retry_delay)
                        
                        if consecutive_errors >= 3:
                            logger.critical("Too many consecutive beacon errors, restarting transmitter")
                            self.reset_interface()
                            break
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
        
        # Använd samma MAC-adress som i beacon
        mac_bytes = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
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
        """Get current status of all features with colors"""
        return {
            'hotspot': f"{GREEN}O{END}" if self.hotspot_active else f"{RED}X{END}",
            'monitor': f"{GREEN}O{END}" if self.monitor_mode_active else f"{RED}X{END}"
        }

    def display_menu(self):
        """Display the main menu with colors"""
        status = self.get_status()
        os.system('clear')
        print(f"\n{BOLD}{CYAN}=== Pi Zero W Controller ==={END}")
        print(f"{BOLD}Hotspot Status:{END} [{status['hotspot']}]")
        print(f"{BOLD}Monitor Mode:{END} [{status['monitor']}]")
        print(f"\n{WHITE}Options:{END}")
        print(f"{YELLOW}1.{END} Toggle Hotspot")
        print(f"{YELLOW}2.{END} Toggle Monitor Mode")
        print(f"{YELLOW}3.{END} Show Log")
        print(f"{YELLOW}4.{END} System Backup")
        print(f"{YELLOW}5.{END} Restore System")
        print(f"{YELLOW}6.{END} Exit")
        print(f"\n{BLUE}Select an option (1-6):{END} ")

    def show_log(self):
        """Display recent log entries with colors"""
        try:
            if not os.path.exists('pi_controller.log'):
                print(f"\n{RED}No log file found.{END}")
                input(f"\n{BLUE}Press Enter to continue...{END}")
                return

            with open('pi_controller.log', 'r') as f:
                print(f"\n{BOLD}{CYAN}=== Recent Log Entries ==={END}")
                for line in f.readlines()[-10:]:
                    if "ERROR" in line or "CRITICAL" in line:
                        print(f"{RED}{line.strip()}{END}")
                    elif "WARNING" in line:
                        print(f"{YELLOW}{line.strip()}{END}")
                    elif "INFO" in line:
                        print(f"{GREEN}{line.strip()}{END}")
                    else:
                        print(f"{WHITE}{line.strip()}{END}")
            input(f"\n{BLUE}Press Enter to continue...{END}")
        except Exception as e:
            print(f"{RED}Error reading log: {str(e)}{END}")
            input(f"\n{BLUE}Press Enter to continue...{END}")

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

    def verify_system_state(self):
        """Verify system state and configuration"""
        try:
            # Kontrollera nätverksgränssnitt
            if INTERFACE not in netifaces.interfaces():
                raise Exception(f"Interface {INTERFACE} not found")
            
            # Kontrollera IP-konfiguration
            addrs = netifaces.ifaddresses(INTERFACE)
            if netifaces.AF_INET not in addrs:
                raise Exception("No IP configuration found")
            
            # Kontrollera raw socket-stöd
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                sock.close()
            except Exception as e:
                raise Exception(f"Raw socket support not available: {str(e)}")
            
            # Kontrollera systemfiler
            critical_files = [
                "/etc/network/interfaces",
                "/etc/dhcpcd.conf",
                "/etc/wpa_supplicant/wpa_supplicant.conf",
                "/etc/hostapd/hostapd.conf",
                "/etc/dnsmasq.conf"
            ]
            
            for file in critical_files:
                if not os.path.exists(file):
                    logger.warning(f"Critical file missing: {file}")
            
            # Kontrollera systemresurser
            if psutil.cpu_percent() > 90:
                logger.warning("High CPU usage detected")
            if psutil.virtual_memory().percent > 90:
                logger.warning("High memory usage detected")
            
            logger.info("System state verified successfully")
            return True
        except Exception as e:
            self.log_error(f"System state verification failed: {str(e)}")
            return False

    def handle_critical_error(self):
        """Handle critical errors with improved recovery"""
        try:
            logger.info("Attempting system recovery...")
            
            # Stop all services gracefully
            if self.hotspot_active:
                self.stop_hotspot()
            if self.monitor_mode_active:
                self.toggle_monitor_mode(False)
            
            # Wait for services to stop
            time.sleep(2)
            
            # Reset interface
            self.reset_interface()
            
            # Wait for interface to stabilize
            time.sleep(2)
            
            # Reset error counters
            self.error_count = 0
            self.last_error_time = 0
            
            # Verify system state
            if not self.verify_system_state():
                raise Exception("System state verification failed after recovery")
            
            # Create emergency backup
            self.create_system_backup()
            
            logger.info("System recovery completed")
        except Exception as e:
            logger.critical(f"Recovery failed: {str(e)}", exc_info=True)
            self.cleanup()
            sys.exit(1)

    def reset_interface(self):
        """Reset network interface with improved error handling"""
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
            
            # Wait for interface to come up
            time.sleep(2)
            
            # Verify interface is up
            ifreq = struct.pack('16sH', INTERFACE.encode(), 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
            if not (flags & IFF_UP):
                raise Exception("Interface failed to come up after reset")
            
            sock.close()
            logger.info("Network interface reset successfully")
        except Exception as e:
            self.log_error(f"Failed to reset interface: {str(e)}")
            raise

    def create_backup_dir(self):
        """Create backup directory if it doesn't exist"""
        try:
            if not os.path.exists(self.backup_dir):
                os.makedirs(self.backup_dir)
                logger.info(f"Created backup directory: {self.backup_dir}")
        except Exception as e:
            self.log_error(f"Failed to create backup directory: {str(e)}")

    def create_system_backup(self):
        """Create a backup of critical system files"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(self.backup_dir, f"system_backup_{timestamp}.tar.gz")
            
            # Lista över kritiska filer att säkerhetskopiera
            critical_files = [
                "/etc/network/interfaces",
                "/etc/dhcpcd.conf",
                "/etc/wpa_supplicant/wpa_supplicant.conf",
                "/etc/hostapd/hostapd.conf",
                "/etc/dnsmasq.conf"
            ]
            
            # Skapa temporär katalog för backup
            temp_dir = os.path.join(self.backup_dir, "temp_backup")
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            # Kopiera kritiska filer
            for file in critical_files:
                if os.path.exists(file):
                    dest = os.path.join(temp_dir, os.path.basename(file))
                    with open(file, 'r') as src, open(dest, 'w') as dst:
                        dst.write(src.read())
            
            # Skapa tar-arkiv
            import tarfile
            with tarfile.open(backup_file, "w:gz") as tar:
                tar.add(temp_dir, arcname="")
            
            # Städa upp temporär katalog
            import shutil
            shutil.rmtree(temp_dir)
            
            logger.info(f"Created system backup: {backup_file}")
            
            # Behåll bara de 5 senaste backuperna
            self.cleanup_old_backups()
            
        except Exception as e:
            self.log_error(f"Failed to create system backup: {str(e)}")

    def cleanup_old_backups(self):
        """Keep only the 5 most recent backups"""
        try:
            backups = sorted([f for f in os.listdir(self.backup_dir) if f.startswith("system_backup_")])
            if len(backups) > 5:
                for old_backup in backups[:-5]:
                    os.remove(os.path.join(self.backup_dir, old_backup))
                    logger.info(f"Removed old backup: {old_backup}")
        except Exception as e:
            self.log_error(f"Failed to cleanup old backups: {str(e)}")

    def restore_system_backup(self, backup_file):
        """Restore system from backup"""
        try:
            if not os.path.exists(backup_file):
                raise Exception(f"Backup file not found: {backup_file}")
            
            # Skapa temporär katalog för återställning
            temp_dir = os.path.join(self.backup_dir, "temp_restore")
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            # Extrahera backup
            import tarfile
            with tarfile.open(backup_file, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            # Återställ filer
            for file in os.listdir(temp_dir):
                src = os.path.join(temp_dir, file)
                dst = os.path.join("/etc", file)
                
                # Skapa backup av existerande fil
                if os.path.exists(dst):
                    backup_dst = f"{dst}.backup"
                    with open(dst, 'r') as src_file, open(backup_dst, 'w') as dst_file:
                        dst_file.write(src_file.read())
                
                # Kopiera ny fil
                with open(src, 'r') as src_file, open(dst, 'w') as dst_file:
                    dst_file.write(src_file.read())
            
            # Städa upp
            import shutil
            shutil.rmtree(temp_dir)
            
            logger.info(f"System restored from backup: {backup_file}")
            return True, "System restored successfully"
            
        except Exception as e:
            self.log_error(f"Failed to restore system backup: {str(e)}")
            return False, f"Failed to restore system: {str(e)}"

    def run(self):
        """Main application loop with improved error handling"""
        try:
            self.check_root()
            while self.running:
                try:
                    self.display_menu()
                    choice = input().strip()
                    
                    if choice == '1':
                        if self.hotspot_active:
                            success, message = self.stop_hotspot()
                            print(f"\n{GREEN if success else RED}{message}{END}")
                        else:
                            # Verifiera systemtillstånd innan start
                            if not self.verify_system_state():
                                print(f"\n{RED}System state verification failed. Attempting recovery...{END}")
                                self.handle_critical_error()
                            success, message = self.setup_hotspot()
                            print(f"\n{GREEN if success else RED}{message}{END}")
                        time.sleep(2)
                    
                    elif choice == '2':
                        if not self.verify_system_state():
                            print(f"\n{RED}System state verification failed. Attempting recovery...{END}")
                            self.handle_critical_error()
                        success, message = self.toggle_monitor_mode(not self.monitor_mode_active)
                        print(f"\n{GREEN if success else RED}{message}{END}")
                        time.sleep(2)
                    
                    elif choice == '3':
                        self.show_log()
                    
                    elif choice == '4':
                        self.create_system_backup()
                        print(f"\n{GREEN}System backup created successfully{END}")
                        input(f"\n{BLUE}Press Enter to continue...{END}")
                    
                    elif choice == '5':
                        print(f"\n{BOLD}{CYAN}Available Backups:{END}")
                        backups = sorted([f for f in os.listdir(self.backup_dir) if f.startswith("system_backup_")])
                        for i, backup in enumerate(backups, 1):
                            print(f"{YELLOW}{i}.{END} {backup}")
                        
                        try:
                            backup_choice = int(input(f"\n{BLUE}Select backup to restore (1-{len(backups)}):{END} "))
                            if 1 <= backup_choice <= len(backups):
                                backup_file = os.path.join(self.backup_dir, backups[backup_choice-1])
                                success, message = self.restore_system_backup(backup_file)
                                print(f"\n{GREEN if success else RED}{message}{END}")
                                
                                # Verifiera systemtillstånd efter återställning
                                if success and not self.verify_system_state():
                                    print(f"\n{RED}System state verification failed after restore. Attempting recovery...{END}")
                                    self.handle_critical_error()
                            else:
                                print(f"\n{RED}Invalid backup selection{END}")
                        except ValueError:
                            print(f"\n{RED}Invalid input{END}")
                        input(f"\n{BLUE}Press Enter to continue...{END}")
                    
                    elif choice == '6':
                        print(f"\n{YELLOW}Shutting down...{END}")
                        self.cleanup()
                        self.running = False
                    
                    else:
                        print(f"\n{RED}Invalid option. Please try again.{END}")
                        time.sleep(1)
                
                except Exception as e:
                    self.log_error(f"Error in main loop: {str(e)}")
                    print(f"\n{RED}An error occurred. Check pi_controller.log for details.{END}")
                    time.sleep(2)
        
        except Exception as e:
            logger.error(f"Critical error: {str(e)}")
            print(f"\n{RED}Critical error occurred. Check pi_controller.log for details.{END}")
            self.cleanup()
            sys.exit(1)

if __name__ == '__main__':
    controller = PiController()
    controller.run() 