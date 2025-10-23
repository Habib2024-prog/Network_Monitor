# Network Monitor System - README

## Overview
A Linux-based network packet analyzer that captures, parses, filters, and replays network packets using custom Stack and Queue data structures.

## Requirements
- **OS**: Linux (Ubuntu 18.04+)
- **Compiler**: g++ with C++11 support
- **Privileges**: ROOT (for raw socket access)
- **Network Interface**: Single interface (default: eth0 or wlan0)

## Installation & Setup

### Step 1: Compile
```bash
  g++ -std=c++11 -o networkmonitor networkmonitor.cpp
```

### Step 2: Run with Root Privileges
```bash
  sudo ./network_monitor
```

## How It Works

### 1. Packet Capture
- Opens a raw socket on the network interface
- Continuously captures all packets for 10 seconds
- Stores packets in a Queue with ID, timestamp, IP addresses, and raw data

### 2. Packet Dissection
- Uses a Stack to parse packet layers in order:
  1. **Ethernet**: MAC addresses, EtherType
  2. **IPv4/IPv6**: IP addresses, protocol number
  3. **TCP/UDP**: Port numbers and flags

### 3. Filtering
- Filters packets by source and destination IP
- Moves matching packets to a filtered queue
- Calculates delay: `Delay (ms) = Packet Size / 1000`

### 4. Replay
- Attempts to resend filtered packets
- On failure: moves to backup list
- Retries up to 2 times per packet

## Program Flow

```
START
  ↓
Initialize Raw Socket
  ↓
Capture Packets (10 seconds)
  ↓
Display Captured Packets
  ↓
Dissect Sample Packet (show all 5 layers)
  ↓
Filter Packets by IP
  ↓
Replay Filtered Packets
  ↓
Display Backup List (failed packets)
  ↓
END
```

## Data Structures Used

### Custom Queue
- Used for: Packet storage, filtered packets, backup list
- Operations: enqueue, dequeue, isEmpty, getSize

### Custom Stack
- Used for: Protocol layer parsing
- Operations: push, pop, peek, isEmpty

## Testing & Assumptions

### Assumptions
- Program runs on Linux with root privileges
- Network interface is accessible
- Captures standard Ethernet, IPv4/IPv6, TCP/UDP packets
- Replay success rate simulated at 80%

### Sample Test Cases
1. Run program with active network traffic
2. Observe packets being captured with timestamps
3. Verify layer dissection for captured packets
4. Filter packets between two IPs (modify in code)
5. Observe replay and backup list functionality



### Change Network Interface
Modify raw socket binding (advanced modification required)

## Key Features Implemented

✅ Custom Queue implementation  
✅ Custom Stack implementation  
✅ Raw socket packet capture  
✅ 5-layer protocol dissection (Ethernet, IPv4, IPv6, TCP, UDP)  
✅ IP-based filtering  
✅ Packet replay with retry logic  
✅ Error handling and backup list  
✅ Real-time packet display  
✅ Layer dissection display  

## Known Limitations

- Packet capture limited to single interface
- Requires root/sudo privileges
- Replay success simulated (not actual network replay)
- UDP/TCP parsing basic (flags/options not fully parsed)
- IPv6 partial support

## Troubleshooting

### "Need root privileges"
```bash
  sudo ./networkmonitor
```

### No packets captured
- Check network interface is active
- Ensure there's network traffic (ping, browse, etc.)
- Verify interface name (eth0, wlan0, etc.)

### Compilation errors
- Ensure g++ supports C++11: `g++ --version`
- Install build tools: `sudo apt-get install build-essential`


