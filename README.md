# LightPacket - A Comprehensive Packet Manipulation Library

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/adamboulaaz92-jpg/LightPacket)

![](images/LightPacket-Logo.png)

## Overview

**LightPacket** is a cross-platform packet manipulation library designed for building, parsing, and sending network packets at Layer 2. It provides a clean Python interface for constructing custom packets, parsing captured data, and interacting with network interfaces using libpcap/Npcap.

### Key Features

- **Cross-Platform Support**: Works on both Linux (libpcap) and Windows (Npcap)
- **Layer 2 Packet Construction**: Build Ethernet, ARP, LLC, SNAP, and Dot3 packets
- **Automatic Layer Detection**: Parse raw bytes into structured packet objects
- **Packet Stacking**: Chain multiple protocol layers together
- **Interface Detection**: Automatically detect and use default network interfaces
- **Rich Packet Representation**: Human-readable packet displays with color support
- **Send/Receive Capabilities**: Send and receive packets at Layer 2
- **Custom Packet Parsing**: Extensible parser architecture
- **Comprehensive Error Handling**: Custom error classes with detailed messages
- **MAC Address Utilities**: Flexible MAC address handling

---

## Architecture Overview

```
LightPacket/
├── __init__.py                 # Package entry point
├── BaseLayer.py                # Core layer abstraction
├── Raw.py                      # Raw data layer
├── EthernetII.py               # Ethernet layer
├── Arp.py                      # ARP layer
├── Dot3.py                     # IEEE 802.3 layer
├── LLC.py                      # Logical Link Control layer
├── Snap.py                     # SNAP layer
├── Detect_layer.py             # Automatic protocol detection
├── Consts.py                   # Protocol constants
├── Version.py                  # Version information
├── Decoration/                 
│   └── Colors.py              # ANSI color formatting
├── Interfaces/                 # Platform-specific network interfaces
│   ├── LinuxInterfaces.py     # Linux interface enumeration
│   ├── LibpcapInterfacesLin.py # libpcap interface handling
│   ├── WinInterfaces.py       # Windows interface enumeration
│   └── NpcapInterfacesWin.py  # Npcap interface handling
├── Layers/                    # Helper layer components
│   ├── L2Socket.py           # Windows L2 socket
│   ├── L2SocketL.py          # Linux L2 socket
│   ├── Mac.py                # MAC address utilities
│   ├── IPtoa.py              # IP address utilities
│   └── IS_LLC.py             # LLC detection utility
├── Logger/                    # Logging and error handling
│   ├── LightLogger.py        # Custom logger with color support
│   └── Errors.py             # Custom error classes
├── LightPacketWin.py          # Windows API wrapper
└── LightPacketLin.py          # Linux API wrapper
```

---

## Installation

### Prerequisites

**Linux:**
```bash
sudo apt-get install libpcap-dev    # Debian/Ubuntu
sudo dnf install libpcap-devel      # RHEL/CentOS/Fedora
sudo pacman -S libpcap              # Arch
sudo zypper install libpcap1        # OpenSUSE/SUSE
sudo apk add libpcap-dev            # Alpine
sudo emerge net-libs/libpcap        # Gentoo
sudo xbps-install -S libpcap-devel  # Void
sudo tce-load -wi libpcap           # Tiny Core  
```

**Windows:**
- Windows 10 / Windows 11
- Install [Npcap](https://npcap.com/) (run in WinPcap API-compatible mode)
- Ensure Python 3.8+ is installed

### Install from Source

```bash
git clone https://github.com/adamboulaaz92-jpg/LightPacket.git
cd LightPacket
python setup.py install
```

### Dependencies

```bash
# For interface detection (recommended)
pip install netifaces

# For Linux socket operations
pip install pyroute2  # optional
```

---

## Core Classes and Functions

### BaseLayer Class (`BaseLayer.py`)

The foundation for all protocol layers.

| Attribute | Description |
|-----------|-------------|
| `payload` | Next layer in the packet stack |
| `_raw_payload` | Raw bytes payload |

| Method | Description |
|--------|-------------|
| `build()` | Convert layer to bytes (implemented by subclasses) |
| `set_payload()` | Set the next layer |
| `get_payload_bytes()` | Get payload as bytes |
| `copy()` | Create a deep copy of the layer |
| `show()` | Display layer information |
| `__truediv__()` | Stack layers using `/` operator |
| `__rtruediv__()` | Reverse stacking |

**Example:**
```python
from LightPacket import Ethernet, Arp

# Stack layers using division operator
packet = Ethernet() / Arp()
```

---

### Layer Construction Functions

#### EthernetLayer (`EthernetII.py`)

```python
def Ethernet(src: Union[str, bytes] = None, 
             dst: Union[str, bytes] = BROADCAST_MAC,
             ethertype: Union[str, bytes] = None) -> EthernetLayer
```

**Parameters:**
- `src`: Source MAC address (auto-detected if None)
- `dst`: Destination MAC address
- `ethertype`: EtherType value (auto-detected for ARP/IPv4)

**Example:**
```python
from LightPacket import Ethernet

# Create Ethernet layer with default settings
eth = Ethernet()

# Create with custom MAC addresses
eth = Ethernet(
    src='00:11:22:33:44:55',
    dst='ff:ff:ff:ff:ff:ff',
    ethertype=0x0806  # ARP
)
```

---

#### ArpLayer (`Arp.py`)

```python
def Arp(hwtype: int = None, ptype: int = None, 
        maclen: int = None, plen: int = None, 
        opcode: int = None, macsrc: Union[str, bytes] = None,
        ipsrc: str = None, macdst: Union[str, bytes] = None, 
        ipdst: str = None) -> ArpLayer
```

**Parameters:**
- `hwtype`: Hardware type (default: 1 for Ethernet)
- `ptype`: Protocol type (default: 0x0800 for IPv4)
- `maclen`: MAC address length (default: 6)
- `plen`: Protocol address length (default: 4)
- `opcode`: Operation code (1=request, 2=reply)
- `macsrc`: Source MAC address
- `ipsrc`: Source IP address
- `macdst`: Destination MAC address
- `ipdst`: Destination IP address

**Example:**
```python
from LightPacket import Arp

# Create ARP request
arp = Arp(
    opcode=1,
    ipsrc='192.168.1.10',
    ipdst='192.168.1.1'
)

# Create ARP reply
arp_reply = Arp(
    opcode=2,
    macsrc='00:11:22:33:44:55',
    ipsrc='192.168.1.1',
    macdst='aa:bb:cc:dd:ee:ff',
    ipdst='192.168.1.10'
)
```

---

#### LLC Layer (`LLC.py`)

```python
def LLC(dsap: Union[str, bytes] = SAP_LLC_SNAP,
        ssap: Union[str, bytes] = SAP_LLC_SNAP,
        control: Union[str, bytes] = LLC_UI) -> LLCLayer
```

**Parameters:**
- `dsap`: Destination Service Access Point
- `ssap`: Source Service Access Point
- `control`: Control field

**Constants:**
- `SAP_LLC_SNAP = 0xAA`
- `LLC_UI = 0x03` (Unnumbered Information)

**Example:**
```python
from LightPacket import LLC

llc = LLC(dsap=0xAA, ssap=0xAA, control=0x03)
```

---

#### SNAP Layer (`Snap.py`)

```python
def SNAP(oui: Union[str, bytes] = 0x000000,
         pid: Union[str, bytes] = ARP) -> SNAPLayer
```

**Parameters:**
- `oui`: Organizationally Unique Identifier
- `pid`: Protocol ID

**Example:**
```python
from LightPacket import SNAP

snap = SNAP(oui=0x000000, pid=0x0806)  # ARP over SNAP
```

---

#### Dot3Layer (`Dot3.py`)

```python
def Dot3(dst: Union[str, bytes] = BROADCAST_MAC,
         src: Union[str, bytes] = None, 
         length: int = 0) -> Dot3Layer
```

**Parameters:**
- `dst`: Destination MAC address
- `src`: Source MAC address
- `length`: Frame length (auto-calculated)

---

#### RawLayer (`Raw.py`)

```python
def Raw(payload: bytes = b'Test LightPacket Raw Layer') -> RawLayer
```

**Parameters:**
- `payload`: Raw bytes payload

**Example:**
```python
from LightPacket import Raw

raw = Raw(b'\x01\x02\x03\x04')
```

---

## Packet Building Examples

### Basic Packet Construction

```python
from LightPacket import Ethernet, Arp, Raw

# Build an ARP request packet
packet = Ethernet() / Arp()
packet_bytes = packet.build()

# Build packet with custom MAC addresses
eth = Ethernet(
    src='00:11:22:33:44:55',
    dst='ff:ff:ff:ff:ff:ff',
    ethertype=0x0806
)
arp = Arp(
    opcode=1,
    ipsrc='192.168.1.10',
    ipdst='192.168.1.1'
)
packet = eth / arp

# Build with raw payload
eth = Ethernet()
raw = Raw(b'Custom data')
packet = eth / raw
```

### Stacking Multiple Layers

```python
from LightPacket import Ethernet, Dot3, LLC, SNAP, Arp

# Ethernet over LLC over SNAP
packet = Ethernet() / LLC() / SNAP() / Arp()

# Dot3 with LLC
packet = Dot3() / LLC()
```

---

## Packet Parsing

### DetectLayer (`Detect_layer.py`)

Automatically detects and parses packet layers.

```python
from LightPacket import DetectLayer

# Parse raw packet bytes
raw_bytes = b'\xff\xff...'  # your raw packet bytes
parsed = DetectLayer().start(raw_bytes, verbose=True)

# Access parsed fields
if 'Ethernet' in parsed:
    print(parsed['Ethernet']['src'])
if 'ARP' in parsed:
    print(parsed['ARP']['src_ip'])
```

### Individual Layer Parsers

Each layer has its own parser class:

```python
from LightPacket import EthernetParser, ArpParser, LLCParser

# Parse Ethernet layer
result = EthernetParser.load_as_ethernet_layer(raw_bytes, verbose=True)

# Parse ARP layer
result = ArpParser.load_as_arp_layer(raw_bytes, verbose=True)

# Parse LLC layer
result = LLCParser.load_as_llc_layer(raw_bytes, verbose=True)
```

---

## L2Socket - Packet Sending and Receiving

### Linux (`L2SocketL.py`)

```python
from LightPacket import L2Socket

# Create socket on default interface
socket = L2Socket()

# Create socket on specific interface
socket = L2Socket(iface='eth0', promisc=True, snaplen=65535)
```

### Windows (`L2Socket.py`)

```python
from LightPacket import L2pcapSocket

# Create socket on default interface
socket = L2pcapSocket()

# Create socket on specific interface
socket = L2pcapSocket(iface=r'\Device\NPF_{GUID}', promisc=True)
```

### Socket Methods

| Method | Description |
|--------|-------------|
| `sendl2(packet)` | Send a Layer 2 packet |
| `recvl2(count=1, timeout=1.0)` | Receive packets |
| `srp1(packet, timeout=3.0, filter_str=None)` | Send and receive one response |
| `srp(packet, timeout=3.0, count=1, filter_str=None)` | Send and receive multiple responses |
| `set_filter(filter_str)` | Set BPF filter |
| `close()` | Close the socket |

**Example:**
```python
from LightPacket import L2Socket, Ethernet, Arp

# Create socket
sock = L2Socket()

# Build ARP request
packet = Ethernet() / Arp(
    opcode=1,
    ipsrc='192.168.1.10',
    ipdst='192.168.1.1'
)

# Send and receive response
response = sock.srp1(packet, timeout=3.0, filter_str='arp')

if response:
    print(f"Received: {response.hex()}")

# Close socket
sock.close()
```

### Advanced Socket Usage

```python
# Send packet and receive multiple responses
responses = sock.srp(
    packet, 
    timeout=5.0, 
    count=5, 
    filter_str='arp and src host 192.168.1.1'
)

# Capture packets
packets = sock.recvl2(count=10, timeout=5.0)

# Set filter to capture only ARP packets
sock.set_filter('arp')
packets = sock.recvl2(count=5)
```

---

## Interface Management

### Linux Interfaces (`LinuxInterfaces.py`)

```python
from LightPacket import LinuxNetworkInterfaces

# Get all interfaces
interfaces = LinuxNetworkInterfaces()

# List interfaces
for name, iface in interfaces.items():
    print(f"{name}: {iface['ips_v4']}")

# Get default interface
default = interfaces.default_interface()
print(default['name'], default['mac'])

# Display interfaces
interfaces.show()
```

**Functions:**
- `get_default_interface_mac_linux()` - Get default interface MAC
- `get_default_interface_ip_linux()` - Get default interface IP
- `get_default_gateway_ipv4_linux()` - Get default IPv4 gateway
- `get_default_gateway_ipv6_linux()` - Get default IPv6 gateway
- `get_default_interface_name_linux()` - Get default interface name

### Windows Interfaces (`WinInterfaces.py`)

```python
from LightPacket import NetworkInterfaces

# Get all interfaces
interfaces = NetworkInterfaces()

# Get default interface
default = interfaces.default_interface()
print(default['name'], default['guid'])

# Get Npcap interface name
from LightPacket import get_default_interface_npcap_name_windows
npcap_name = get_default_interface_npcap_name_windows()
```

**Functions:**
- `get_default_interface_mac_windows()` - Get default interface MAC
- `get_default_interface_ip_windows()` - Get default interface IP
- `get_default_gateway_ipv4_windows()` - Get default IPv4 gateway
- `get_default_gateway_ipv6_windows()` - Get default IPv6 gateway
- `get_default_interface_npcap_name_windows()` - Get Npcap device name

---

## Constants (`Consts.py`)

### EtherType Values

```python
from LightPacket import ETHERTYPE, IPv4, ARP, IPv6, VLAN

# Access dictionary
print(ETHERTYPE[0x0800])  # (IPv4)

# Use constants
ethertype = IPv4  # 0x0800
ethertype = ARP   # 0x0806
ethertype = IPv6  # 0x86DD
```

### MAC Address Constants

```python
from LightPacket import BROADCAST_MAC, NULL_MAC

broadcast = BROADCAST_MAC  # 'ff:ff:ff:ff:ff:ff'
null_mac = NULL_MAC        # '00:00:00:00:00:00'
```

### LLC/SNAP Constants

```python
from LightPacket import SAP_LLC_SNAP, LLC_UI

dsap = SAP_LLC_SNAP  # 0xAA
control = LLC_UI     # 0x03
```

### SAP Values Dictionary

```python
from LightPacket import SAP_VALUES

print(SAP_VALUES[0xAA])  # "SNAP (Subnetwork Access Protocol)"
```

---

## MAC Address Utilities (`Mac.py`)

```python
from LightPacket import MacAddress

# Create from string
mac = MacAddress('00:11:22:33:44:55')

# Create from bytes
mac = MacAddress(b'\x00\x11\x22\x33\x44\x55')

# Convert to string
mac_str = str(mac)  # '00:11:22:33:44:55'

# Convert to bytes
mac_bytes = bytes(mac)  # b'\x00\x11\x22\x33\x44\x55'
```

---

## IP Address Utilities (`IPtoa.py`)

```python
from LightPacket import inet_aton, inet_ntoa, ipv6_bytes_to_str, ipv6_str_to_bytes

# IPv4
ip_bytes = inet_aton('192.168.1.1')  # b'\xc0\xa8\x01\x01'
ip_str = inet_ntoa(b'\xc0\xa8\x01\x01')  # '192.168.1.1'

# IPv6
ip_bytes = ipv6_str_to_bytes('2001:db8::1')
ip_str = ipv6_bytes_to_str(ip_bytes)
```

---

## Packet Display and Debugging

### Show Packet Structure

```python
# Create a packet
packet = Ethernet() / Arp()

# Display packet structure with colors
packet.show()

# Output:
# --- [ EthernetLayer ] ---
#    dst=ff:ff:ff:ff:ff:ff
#    src=auto-detected-mac
#    type=0x0806 (ARP)
#    \
#       --- [ ArpLayer ] ---
#          hwtype=1
#          ptype=0x0800
#          maclen=6
#          plen=4
#          opcode=1
#          macsrc=auto-detected-mac
#          ipsrc=auto-detected-ip
#          macdst=ff:ff:ff:ff:ff:ff
#          ipdst=auto-detected-gateway
```

### Layer Representation

```python
# Print layer object
print(Ethernet())
# <Ethernet dst=ff:ff:ff:ff:ff:ff src=aa:bb:cc:dd:ee:ff type=0x0806 (ARP) len=14 (bytes)>

print(Arp())
# <Arp opcode=1 plen=4 ptype=0x0800 maclen=6 hwtype=1 macsrc=aa:bb:cc:dd:ee:ff ipsrc=192.168.1.10 macdst=ff:ff:ff:ff:ff:ff ipdst=192.168.1.1>

print(Raw(b'\x01\x02\x03'))
# <Raw payload=b'\x01\x02\x03' len=3>
```

---

## Error Handling

### Custom Error Classes (`Errors.py`)

```python
from LightPacket.Logger.Errors import (
    LightPacketError,
    InvalidDataLengthError,
    InvalidMacAddressError,
    InvalidIPAddressError,
    InvalidDataTypeError
)

try:
    mac = MacAddress('invalid_mac')
except InvalidMacAddressError as e:
    print(f"MAC Error: {e}")
```

### Logger Usage (`LightLogger.py`)

```python
from LightPacket.Logger.LightLogger import Logger, ErrorCode, WarningCode

logger = Logger()

# Raise error
logger.error(
    message="Invalid MAC address",
    error_code=ErrorCode.INVALID_MAC
)

# Log warning
logger.warning(
    message="Non-hexadecimal value",
    warning_code=WarningCode.NONHEXVALUE
)
```

**Error Codes:**
- `E001`: Invalid MAC Address
- `E002`: Invalid Data Type
- `E003`: Invalid Data Length
- `E004`: Invalid IP Address

**Warning Codes:**
- `W001`: Non-Hexadecimal Value

---

## Complete Usage Examples

### ARP Scanner

```python
from LightPacket import L2Socket, Ethernet, Arp
import time

def arp_scan(ip_range='192.168.1.1'):
    """Simple ARP scanner"""
    sock = L2Socket()
    responses = []
    
    # Build base Ethernet/ARP request
    eth = Ethernet()
    
    for ip in ip_range:
        arp = Arp(
            opcode=1,  # request
            ipdst=ip
        )
        packet = eth / arp
        
        # Send and wait for response
        response = sock.srp1(packet, timeout=1.0, filter_str='arp')
        
        if response:
            # Parse response
            from LightPacket import DetectLayer
            parsed = DetectLayer().start(response)
            if 'ARP' in parsed:
                mac = parsed['ARP']['src_mac']
                responses.append((ip, mac))
                print(f"{ip} is at {mac}")
        
        time.sleep(0.1)
    
    sock.close()
    return responses

# Run scan
arp_scan(['192.168.1.1', '192.168.1.10', '192.168.1.254'])
```

### Packet Sniffer

```python
from LightPacket import L2Socket, DetectLayer

def sniff_packets(interface=None, count=10, filter_str=None):
    """Simple packet sniffer"""
    sock = L2Socket(iface=interface)
    
    if filter_str:
        sock.set_filter(filter_str)
    
    packets = sock.recvl2(count=count, timeout=5.0)
    
    for raw_packet in packets:
        parsed = DetectLayer().start(raw_packet, verbose=True)
        print("-" * 60)
    
    sock.close()
    return packets

# Sniff ARP packets
sniff_packets(filter_str='arp', count=5)

# Sniff on specific interface
sniff_packets(interface='eth0', count=10)
```

### Custom Packet Sender

```python
from LightPacket import L2Socket, Ethernet, Raw

def send_custom_data(mac_dst, mac_src, data):
    """Send custom data packet"""
    eth = Ethernet(
        dst=mac_dst,
        src=mac_src,
        ethertype=0x1234  # Custom EtherType
    )
    raw = Raw(data)
    packet = eth / raw
    
    sock = L2Socket()
    result = sock.sendl2(packet)
    sock.close()
    
    return result

# Send custom data
send_custom_data(
    mac_dst='ff:ff:ff:ff:ff:ff',
    mac_src='00:11:22:33:44:55',
    data=b'Hello Network!'
)
```

---

## Platform-Specific Notes

### Linux

- Requires `libpcap-dev` package
- Default interface is automatically detected
- Uses `/sys/class/net/` for interface information
- Supports both IPv4 and IPv6

### Windows

- Requires Npcap installation
- Uses GUID-based interface names
- Npcap device names format: `\Device\NPF_{GUID}`
- Loopback interface: `\Device\NPF_Loopback`

---

## Version Information

```python
from LightPacket import version, __version__

print(f"LightPacket version: {version}")
print(f"Package version: {__version__}")
```

---

## License

LightPacket is released under the Mozilla Public License 2.0.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## Support

- **Bug Reports**: [GitHub Issues](https://github.com/adamboulaaz92-jpg/LightPacket/issues)
- **Source Code**: [GitHub Repository](https://github.com/adamboulaaz92-jpg/LightPacket)

---

## Author

- **Adam Boulaaz** - *Initial work* - [GitHub](https://github.com/adamboulaaz92-jpg)

---
