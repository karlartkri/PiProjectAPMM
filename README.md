# Pi Zero W Controller

A Python application for managing WiFi hotspot and monitor mode on Raspberry Pi Zero W, implemented using raw sockets for complete control over network communication.

## Features

- WiFi hotspot creation without external tools
- Monitor mode support
- Terminal-based interface
- Detailed logging and error tracking
- Automatic error recovery
- DHCP server implementation
- Raw socket-based network communication

## Requirements

- Raspberry Pi Zero W
- Python 3.x
- Root privileges (sudo)
- Linux kernel with raw socket support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/pi-project.git
cd pi-project
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Run the application with root privileges:
```bash
sudo python3 app.py
```

## Usage

The application provides a terminal-based interface with the following options:

1. Toggle Hotspot - Start/stop WiFi hotspot
2. Toggle Monitor Mode - Enable/disable monitor mode
3. Show Log - Display recent log entries
4. Exit - Clean shutdown

## Logging and Error Handling

### Log Files

The application maintains detailed logs in `pi_controller.log` with the following information:

- Timestamp
- Log level (DEBUG, INFO, ERROR, CRITICAL)
- File and line number
- Detailed message
- Stack traces for errors

### Log Levels

- **DEBUG**: Detailed frame information, system state
- **INFO**: Normal operations, client connections
- **ERROR**: Non-critical errors, retry attempts
- **CRITICAL**: System failures, recovery attempts

### Error Recovery

The system includes automatic error recovery:

- Tracks error frequency within a 60-second window
- Automatically restarts services after 5 consecutive errors
- Resets network interface when needed
- Graceful shutdown on critical failures

### Common Issues and Solutions

1. **AP Disappears After 15 Seconds**
   - Check log file for beacon transmission errors
   - Verify interface configuration
   - Monitor error count in logs

2. **Monitor Mode Not Working**
   - Check interface permissions
   - Verify raw socket support
   - Review error logs for specific failures

3. **Client Connection Issues**
   - Check DHCP server logs
   - Verify beacon frame transmission
   - Monitor authentication/association frames

## Debugging

### View Logs in Real-time

```bash
tail -f pi_controller.log
```

### Check System State

```bash
# Check interface status
ifconfig wlan0

# Check system logs
dmesg | grep wlan0
```

### Common Error Messages

1. **"System requirements not met"**
   - Verify root privileges
   - Check raw socket support
   - Review kernel configuration

2. **"Failed to configure interface"**
   - Check interface permissions
   - Verify network configuration
   - Review system logs

3. **"Error threshold reached"**
   - Check error logs for pattern
   - Verify system resources
   - Review network configuration

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 