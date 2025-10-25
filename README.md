# Network Monitor System - README

## GitHub Repository
```
https://github.com/Habib2024-prog/Network_Monitor.git
```

## Overview
A comprehensive Linux-based network packet analyzer implementing custom Stack and Queue data structures for real-time packet capture, dissection, filtering, and replay using raw sockets. This system demonstrates practical application of data structures in network traffic analysis.

---

##  Features

### Core Functionality
✅ **Real-time packet capture** using raw sockets (AF_PACKET)  
✅ **Custom Stack implementation** for layer-by-layer protocol parsing  
✅ **Custom Queue implementation** for packet management and filtering  
✅ **Multi-protocol support**: Ethernet, IPv4, IPv6, TCP, UDP  
✅ **Dynamic memory management** with proper allocation/deallocation  
✅ **IP-based packet filtering** with size validation  
✅ **Packet replay mechanism** with actual network transmission  
✅ **Retry logic** with backup queue (up to 2 retries per packet)  
✅ **Delay estimation** based on packet size  
✅ **Comprehensive error handling**

---

##  Requirements

### System Requirements
- **Operating System**: Linux (Ubuntu 18.04+ / WSL 2)
- **Compiler**: g++ with C++11 support or later
- **Privileges**: ROOT access (required for raw socket operations)
- **Network Interface**: Single interface (default: eth0)

### Dependencies
```bash
  sudo apt update
  sudo apt install build-essential g++ net-tools iproute2
```

---

##  Installation & Setup

### Step 1: Clone Repository
```bash
  git clone https://github.com/Habib2024-prog/Network_Monitor.git
  cd Network_Monitor
```

### Step 2: Verify Network Interface
```bash
# Check available network interfaces
   ip link show
# or
   ifconfig -a
```
**Common interfaces:**
- `eth0` - Ethernet/primary interface
- `wlan0` - Wireless interface
- `lo` - Loopback interface

### Step 3: Compile
```bash
  g++ -std=c++11 -o networkmonitor networkmonitor.cpp
```

**With Makefile (if available):**
```bash
  make
```

### Step 4: Run with Root Privileges
```bash
   sudo ./networkmonitor
```

---

## 🔧 How It Works

### 1. Socket Initialization
- Creates raw socket with `AF_PACKET` family
- Binds socket to specified network interface using `ioctl()` and `bind()`
- Sets up packet capture for all protocols (`ETH_P_ALL`)

### 2. Packet Capture Process
- Continuously captures packets for **60 seconds** (configurable)
- Uses **blocking `recvfrom()`** to receive packets
- Stores captured data in dynamically allocated buffers
- Adds packets to main Queue with metadata:
  - Unique packet ID
  - Timestamp
  - Raw packet buffer
  - Source/Destination IP addresses
  - Protocol type (TCP/UDP/Other)

### 3. Layer Dissection (Stack-Based)
Uses a **Stack data structure** to parse protocol layers:

**Parsing Order:**
1. **Ethernet Layer** (14 bytes)
  - Destination/Source MAC addresses
  - EtherType field (0x0800 for IPv4, 0x86DD for IPv6)

2. **IP Layer** (20-40 bytes)
  - **IPv4**: Header length, source/dest IPs, protocol number
  - **IPv6**: Fixed 40-byte header, source/dest IPs, next header

3. **Transport Layer**
  - **TCP**: Source/dest ports, header length, flags
  - **UDP**: Source/dest ports, length, checksum

**Stack Operations:**
- Layers are **pushed** onto stack during parsing (bottom-up)
- Layers are **popped** for display (top-down/LIFO order)

### 4. Packet Filtering
**Filter Criteria:**
- Matches specific source AND destination IP addresses
- Validates packet size (≤ 1500 bytes maximum)
- Skips oversized packets to prevent MTU issues

**Delay Calculation:**
```
Estimated Delay (ms) = Packet Size (bytes) / 1000
```

**Process:**
- Iterates through main packet queue
- Moves matching packets to filtered queue
- Preserves original queue (non-destructive filtering)

### 5. Packet Replay with Retry Logic
**Replay Mechanism:**
- Uses `sendto()` to retransmit filtered packets
- Validates transmission by comparing bytes sent

**Error Handling:**
- **First Attempt**: Direct replay
- **On Failure**: Increments retry counter
- **Retry 1-2**: Re-attempts transmission
- **After 2 Failures**: Moves to backup queue

**Retry Flow:**
```
Packet → Replay Attempt 1
           ↓ (fail)
        Retry 1 → Replay Attempt 2
                    ↓ (fail)
                 Retry 2 → Replay Attempt 3
                             ↓ (fail)
                          Backup Queue
```

---

##  Program Flow

```
┌─────────────────────────┐
│   START PROGRAM         │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│  Check Root Privileges  │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Initialize Raw Socket   │
│ Bind to Interface       │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Capture Packets         │
│ (60 seconds continuous) │
│ Store in Queue          │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Display Captured        │
│ Packets (first 10)      │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Dissect Sample Packet   │
│ (Parse all 5 layers)    │
│ Display using Stack     │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Filter Packets by IP    │
│ Check size ≤ 1500       │
│ Calculate delay         │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Replay Filtered Packets │
│ Retry up to 2 times     │
│ Move failures to backup │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ Display Backup List     │
│ (Failed replays)        │
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│      END PROGRAM        │
└─────────────────────────┘
```

---

##  Data Structures Implementation

### Custom Queue (Linked List)
**Purpose:** Manage packets in FIFO order

**Operations:**
- `enqueue(T)` - Add packet to rear (O(1))
- `dequeue()` - Remove packet from front (O(1))
- `getFront()` - Peek at front element (O(1))
- `isEmpty()` - Check if queue is empty (O(1))
- `getSize()` - Get current size (O(1))

**Used For:**
- Main packet storage queue
- Filtered packets queue
- Backup/retry queue

**Memory Management:**
- Dynamic node allocation
- Destructor handles cleanup
- Deep copy in copy constructor

### Custom Stack (Linked List)
**Purpose:** Parse protocol layers in LIFO order

**Operations:**
- `push(T)` - Add layer to top (O(1))
- `pop()` - Remove layer from top (O(1))
- `peek()` - View top element (O(1))
- `isEmpty()` - Check if stack is empty (O(1))
- `getSize()` - Get current size (O(1))

**Used For:**
- Protocol layer dissection
- Layer-by-layer parsing (Ethernet → IP → Transport)
- Display layers in reverse order

---

##  Testing & Usage

### Generate Test Traffic

**Terminal 1: Run Monitor**
```bash
 sudo ./network_monitor
```

**Terminal 2: Generate Packets**
```bash
# ICMP packets (ping)
ping -c 20 google.com

# HTTP/HTTPS packets
curl https://example.com
wget https://github.com

# DNS queries
nslookup google.com
dig example.com

# Local traffic (IPv4)
python3 -m http.server 8080
# Then in another terminal:
curl http://localhost:8080
```

### Test Cases Demonstrated

1. **Continuous Packet Capture** (60 seconds minimum)
  - Captures all network traffic on interface
  - Displays packet count, IPs, and protocol

2. **Protocol Dissection** (All 5 layers)
  - Ethernet: MAC addresses and EtherType
  - IPv4/IPv6: IP addresses and protocol numbers
  - TCP/UDP: Port numbers and headers

3. **IP Filtering**
  - Filter by source IP: `192.168.1.100`
  - Filter by destination IP: `8.8.8.8`
  - Size validation (≤ 1500 bytes)

4. **Replay Mechanism**
  - Successful packet retransmission
  - Retry logic demonstration

5. **Error Handling**
  - Failed replay → backup queue
  - Display of failed packets

---

##  Configuration

### Change Network Interface
Edit the main function (line ~460):
```cpp
 networkMonitormonitor("eth0");  // Change to your interface
```

Options: `eth0`, `wlan0`, `ens33`, `lo`

### Adjust Capture Duration
Edit line ~435:
```cpp
monitor.capturePackets(60);  // Change to desired seconds
```

### Modify Filter IPs
Edit line ~447:
```cpp
monitor.filterPackets("SOURCE_IP", "DESTINATION_IP");
```

Example:
```cpp
monitor.filterPackets("192.168.1.100", "8.8.8.8");
```

---

## 🔍 Key Implementation Details

### Raw Socket Creation
```cpp
int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```

### Interface Binding
```cpp
struct ifreq ifr;
strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
ioctl(sockfd, SIOCGIFINDEX, &ifr);

struct sockaddr_ll sll;
sll.sll_ifindex = ifr.ifr_ifindex;
bind(sockfd, (struct sockaddr*)&sll, sizeof(sll));
```

### Packet Reception
```cpp
unsigned char buffer[65536];
int size = recvfrom(sockfd, buffer, 65536, 0, nullptr, nullptr);
```

### Packet Transmission
```cpp
int sent = sendto(sockfd, pkt.buffer, pkt.bufferSize, 0, nullptr, 0);
```

---

## Assumptions

1. **Environment**: Program runs on Linux with kernel 2.6.14+
2. **Privileges**: User has sudo/root access
3. **Network**: Single network interface is active and accessible
4. **Protocols**: Standard Ethernet/IP/TCP/UDP packet structures
5. **Interface**: Default interface is `eth0` (configurable)
6. **MTU**: Maximum packet size is 1500 bytes (Ethernet standard)
7. **Testing**: Self-generated traffic is sufficient for demonstration

---

## ⚠️ Known Limitations

1. **Single Interface**: Captures on one interface at a time
2. **Root Required**: Cannot run without elevated privileges
3. **IPv6 Options**: Extended headers not fully parsed
4. **TCP Flags**: Only basic TCP header parsed (no option parsing)
5. **Fragmentation**: IP fragments not reassembled
6. **Promiscuous Mode**: Not enabled (only sees traffic to/from host)
7. **WSL Limitation**: May only capture packets destined for WSL instance

---

## Troubleshooting

### Issue: "Failed to create raw socket"
**Cause:** Not running with root privileges  
**Solution:**
```bash
 sudo ./networkmonitor
```

### Issue: "Interface not found"
**Cause:** Incorrect interface name  
**Solution:**
```bash
  # Check available interfaces
ip link show

# Update code with correct interface name
# Edit line: NetworkMonitor monitor("YOUR_INTERFACE");
```

### Issue: No packets captured
**Cause:** No network traffic or wrong interface  
**Solutions:**
1. Generate traffic: `ping google.com`
2. Check interface is UP: `ip link show eth0`
3. Try loopback: Change to `"lo"` interface
4. Check firewall rules: `sudo iptables -L`

### Issue: Compilation errors
**Cause:** Missing C++11 support or headers  
**Solutions:**
```bash
  # Install build tools
sudo apt install build-essential

# Verify g++ version (should be 4.7+)
g++ --version

# Compile with explicit C++11 flag
g++ -std=c++11 -o network_monitor network_monitor.cpp
```

### Issue: "Permission denied" on interface
**Cause:** Insufficient privileges or interface in use  
**Solutions:**
```bash
# Run as root
sudo su
./network_monitor

# Check if interface is busy
sudo lsof | grep eth0
```

### Issue: WSL-specific packet capture issues
**Cause:** WSL networking limitations  
**Solutions:**
1. Generate traffic within WSL
2. Use localhost connections
3. Ensure WSL 2 (not WSL 1)
```bash
wsl --set-version Ubuntu 2
```

---

##   Technical References

### Socket Programming
- `socket(2)` - Create raw socket
- `bind(2)` - Bind to network interface
- `recvfrom(2)` - Receive packets
- `sendto(2)` - Send packets

### Protocol Headers
- Ethernet: 14 bytes (6 dst MAC + 6 src MAC + 2 EtherType)
- IPv4: 20-60 bytes (variable due to options)
- IPv6: 40 bytes fixed header
- TCP: 20-60 bytes (variable due to options)
- UDP: 8 bytes fixed header

### EtherType Values
- `0x0800` - IPv4
- `0x86DD` - IPv6
- `0x0806` - ARP

### IP Protocol Numbers
- `6` - TCP
- `17` - UDP
- `1` - ICMP

---

##  Author & Assignment Details
**Habibullah khaliqyar(534537)**
**Course:** CS250 - Data Structures and Algorithms  
**Assignment:** Assignment 2 - Network Monitor  
**Semester:** Fall 2025  
**Program:** BSDS-2


