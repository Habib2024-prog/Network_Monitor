#include <iostream>
#include <cstring>
#include <ctime>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <chrono>
#include <iomanip>

using namespace std;

// ========== CUSTOM QUEUE ==========
template <typename T>
class Queue {
private:
    struct Node {
        T data;
        Node* next;
        Node(T val) : data(val), next(nullptr) {}
    };
    Node* front;
    Node* rear;
    int size;

public:
    Queue() : front(nullptr), rear(nullptr), size(0) {}
    
    ~Queue() {
        while (!isEmpty()) {
            dequeue();
        }
    }

    void enqueue(T val) {
        Node* newNode = new Node(val);
        if (rear) rear->next = newNode;
        rear = newNode;
        if (!front) front = newNode;
        size++;
    }

    T dequeue() {
        if (!front) throw runtime_error("Queue empty");
        Node* temp = front;
        T val = temp->data;
        front = front->next;
        if (!front) rear = nullptr;
        delete temp;
        size--;
        return val;
    }

    T getFront() {
        if (!front) throw runtime_error("Queue empty");
        return front->data;
    }

    bool isEmpty() { return front == nullptr; }
    int getSize() { return size; }
};

// ========== CUSTOM STACK ==========
template <typename T>
class Stack {
private:
    struct Node {
        T data;
        Node* next;
        Node(T val) : data(val), next(nullptr) {}
    };
    Node* top;
    int size;

public:
    Stack() : top(nullptr), size(0) {}
    
    ~Stack() {
        while (!isEmpty()) {
            pop();
        }
    }

    void push(T val) {
        Node* newNode = new Node(val);
        newNode->next = top;
        top = newNode;
        size++;
    }

    T pop() {
        if (!top) throw runtime_error("Stack empty");
        Node* temp = top;
        T val = temp->data;
        top = top->next;
        delete temp;
        size--;
        return val;
    }

    T peek() {
        if (!top) throw runtime_error("Stack empty");
        return top->data;
    }

    bool isEmpty() { return top == nullptr; }
    int getSize() { return size; }
};

// ========== PACKET STRUCTURES ==========
struct PacketData {
    int id;
    time_t timestamp;
    unsigned char* buffer;
    int bufferSize;
    string srcIP;
    string dstIP;
    string protocol;
    int retryCount;

    PacketData() : id(0), timestamp(0), buffer(nullptr), bufferSize(0), 
                   srcIP(""), dstIP(""), protocol(""), retryCount(0) {}
    
    // Copy constructor for deep copy
    PacketData(const PacketData& other) {
        id = other.id;
        timestamp = other.timestamp;
        bufferSize = other.bufferSize;
        srcIP = other.srcIP;
        dstIP = other.dstIP;
        protocol = other.protocol;
        retryCount = other.retryCount;
        
        if (other.buffer && other.bufferSize > 0) {
            buffer = new unsigned char[bufferSize];
            memcpy(buffer, other.buffer, bufferSize);
        } else {
            buffer = nullptr;
        }
    }
    
    ~PacketData() {
        if (buffer) delete[] buffer;
    }
};

struct Layer {
    string name;
    string info;
    int offset;
    int length;
};

// ========== PROTOCOL PARSING FUNCTIONS ==========
string extractIPv4(unsigned char* data) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, data, ip, INET_ADDRSTRLEN);
    return string(ip);
}

string extractIPv6(unsigned char* data) {
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data, ip, INET6_ADDRSTRLEN);
    return string(ip);
}

// ========== PACKET PARSER ==========
class PacketParser {
public:
    static Stack<Layer> parsePacket(PacketData& pkt) {
        Stack<Layer> layerStack;
        unsigned char* data = pkt.buffer;
        int offset = 0;

        // Layer 1: Ethernet
        if (pkt.bufferSize >= 14) {
            Layer eth;
            eth.name = "Ethernet";
            eth.offset = offset;
            eth.length = 14;
            
            unsigned char* dst_mac = data;
            unsigned char* src_mac = data + 6;
            unsigned short eth_type = ntohs(*(unsigned short*)(data + 12));

            char mac_info[256];
            sprintf(mac_info, "Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x, Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, EtherType: 0x%04x",
                    dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], eth_type);
            eth.info = mac_info;
            layerStack.push(eth);
            
            offset += 14;

            // Layer 2: IP
            if (eth_type == 0x0800 && pkt.bufferSize >= offset + 20) {
                // IPv4
                Layer ipv4;
                ipv4.name = "IPv4";
                ipv4.offset = offset;
                
                unsigned char* ipv4_data = data + offset;
                int ihl = (ipv4_data[0] & 0x0F) * 4;
                ipv4.length = ihl;
                
                string src = extractIPv4(ipv4_data + 12);
                string dst = extractIPv4(ipv4_data + 16);
                unsigned char protocol = ipv4_data[9];
                
                pkt.srcIP = src;
                pkt.dstIP = dst;

                char ip_info[256];
                sprintf(ip_info, "Src: %s, Dst: %s, Protocol: %d, Header Len: %d", 
                        src.c_str(), dst.c_str(), protocol, ihl);
                ipv4.info = ip_info;
                layerStack.push(ipv4);
                
                offset += ihl;

                // Layer 3: Transport
                if (protocol == 6 && pkt.bufferSize >= offset + 20) {
                    // TCP
                    Layer tcp;
                    tcp.name = "TCP";
                    tcp.offset = offset;
                    
                    unsigned char* tcp_data = data + offset;
                    unsigned short src_port = ntohs(*(unsigned short*)tcp_data);
                    unsigned short dst_port = ntohs(*(unsigned short*)(tcp_data + 2));
                    int tcp_header_len = ((tcp_data[12] >> 4) & 0x0F) * 4;
                    tcp.length = tcp_header_len;
                    
                    pkt.protocol = "TCP";
                    
                    char tcp_info[256];
                    sprintf(tcp_info, "Src Port: %d, Dst Port: %d, Header Len: %d", 
                            src_port, dst_port, tcp_header_len);
                    tcp.info = tcp_info;
                    layerStack.push(tcp);
                    
                } else if (protocol == 17 && pkt.bufferSize >= offset + 8) {
                    // UDP
                    Layer udp;
                    udp.name = "UDP";
                    udp.offset = offset;
                    udp.length = 8;
                    
                    unsigned char* udp_data = data + offset;
                    unsigned short src_port = ntohs(*(unsigned short*)udp_data);
                    unsigned short dst_port = ntohs(*(unsigned short*)(udp_data + 2));
                    unsigned short udp_len = ntohs(*(unsigned short*)(udp_data + 4));
                    
                    pkt.protocol = "UDP";
                    
                    char udp_info[256];
                    sprintf(udp_info, "Src Port: %d, Dst Port: %d, Length: %d", 
                            src_port, dst_port, udp_len);
                    udp.info = udp_info;
                    layerStack.push(udp);
                }
                
            } else if (eth_type == 0x86DD && pkt.bufferSize >= offset + 40) {
                // IPv6
                Layer ipv6;
                ipv6.name = "IPv6";
                ipv6.offset = offset;
                ipv6.length = 40;
                
                unsigned char* ipv6_data = data + offset;
                string src = extractIPv6(ipv6_data + 8);
                string dst = extractIPv6(ipv6_data + 24);
                unsigned char next_header = ipv6_data[6];
                
                pkt.srcIP = src;
                pkt.dstIP = dst;

                char ipv6_info[512];
                sprintf(ipv6_info, "Src: %s, Dst: %s, Next Header: %d", 
                        src.c_str(), dst.c_str(), next_header);
                ipv6.info = ipv6_info;
                layerStack.push(ipv6);
                
                offset += 40;
                
                // Transport layer for IPv6
                if (next_header == 6 && pkt.bufferSize >= offset + 20) {
                    // TCP
                    Layer tcp;
                    tcp.name = "TCP";
                    tcp.offset = offset;
                    
                    unsigned char* tcp_data = data + offset;
                    unsigned short src_port = ntohs(*(unsigned short*)tcp_data);
                    unsigned short dst_port = ntohs(*(unsigned short*)(tcp_data + 2));
                    int tcp_header_len = ((tcp_data[12] >> 4) & 0x0F) * 4;
                    tcp.length = tcp_header_len;
                    
                    pkt.protocol = "TCP";
                    
                    char tcp_info[256];
                    sprintf(tcp_info, "Src Port: %d, Dst Port: %d", src_port, dst_port);
                    tcp.info = tcp_info;
                    layerStack.push(tcp);
                    
                } else if (next_header == 17 && pkt.bufferSize >= offset + 8) {
                    // UDP
                    Layer udp;
                    udp.name = "UDP";
                    udp.offset = offset;
                    udp.length = 8;
                    
                    unsigned char* udp_data = data + offset;
                    unsigned short src_port = ntohs(*(unsigned short*)udp_data);
                    unsigned short dst_port = ntohs(*(unsigned short*)(udp_data + 2));
                    
                    pkt.protocol = "UDP";
                    
                    char udp_info[256];
                    sprintf(udp_info, "Src Port: %d, Dst Port: %d", src_port, dst_port);
                    udp.info = udp_info;
                    layerStack.push(udp);
                }
            }
        }
        return layerStack;
    }
};

// ========== NETWORK MONITOR ==========
class NetworkMonitor {
private:
    Queue<PacketData> packetQueue;
    Queue<PacketData> filteredQueue;
    Queue<PacketData> backupQueue;
    int packetIdCounter;
    int rawSocket;
    string interface;

public:
    NetworkMonitor(string iface = "eth0") : packetIdCounter(0), rawSocket(-1), interface(iface) {}

    bool initSocket() {
        // Create raw socket - MUST RUN AS ROOT
        rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rawSocket < 0) {
            cerr << "Error: Failed to create raw socket. Must run with sudo!" << endl;
            return false;
        }

        // **CRITICAL FIX**: Bind to specific network interface
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
        
        // Get interface index
        if (ioctl(rawSocket, SIOCGIFINDEX, &ifr) < 0) {
            cerr << "Error: Interface '" << interface << "' not found!" << endl;
            cerr << "Try: ip link show (to see available interfaces)" << endl;
            close(rawSocket);
            return false;
        }

        // Bind socket to interface
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(rawSocket, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            cerr << "Error: Failed to bind socket to interface" << endl;
            close(rawSocket);
            return false;
        }

        cout << "✓ Raw socket created and bound to interface: " << interface << endl;
        return true;
    }

    void capturePackets(int durationSeconds) {
        cout << "\n=== CAPTURING PACKETS FOR " << durationSeconds << " SECONDS ===" << endl;
        cout << "Generate traffic: ping, curl, browse web, etc." << endl << endl;
        
        auto startTime = chrono::high_resolution_clock::now();
        int capturedCount = 0;

        while (true) {
            auto currentTime = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(currentTime - startTime).count();
            if (elapsed >= durationSeconds) break;

            unsigned char buffer[65536];
            // **FIX**: Remove MSG_DONTWAIT for blocking read
            int bufferSize = recvfrom(rawSocket, buffer, 65536, 0, nullptr, nullptr);

            if (bufferSize > 0) {
                PacketData pkt;
                pkt.id = packetIdCounter++;
                pkt.timestamp = time(nullptr);
                pkt.bufferSize = bufferSize;
                
                // Allocate memory for buffer
                pkt.buffer = new unsigned char[bufferSize];
                memcpy(pkt.buffer, buffer, bufferSize);

                // Parse packet to extract IPs
                Stack<Layer> layers = PacketParser::parsePacket(pkt);

                packetQueue.enqueue(pkt);
                capturedCount++;
                
                cout << "[" << capturedCount << "] Packet #" << pkt.id 
                     << " | Size: " << bufferSize << " bytes"
                     << " | Src: " << pkt.srcIP 
                     << " | Dst: " << pkt.dstIP
                     << " | Proto: " << pkt.protocol << endl;
            }
        }
        cout << "\n Capture complete. Total packets captured: " << packetQueue.getSize() << endl;
    }

    void displayPackets() {
        cout << "\n=== CURRENT PACKETS IN QUEUE ===" << endl;
        if (packetQueue.isEmpty()) {
            cout << "Queue is empty!" << endl;
            return;
        }

        Queue<PacketData> tempQueue;
        int count = 0;

        while (!packetQueue.isEmpty() && count < 10) {
            PacketData pkt = packetQueue.dequeue();
            char timeStr[26];
            ctime_r(&pkt.timestamp, timeStr);
            timeStr[24] = '\0'; // Remove newline
            
            cout << "ID: " << pkt.id 
                 << " | Time: " << timeStr
                 << " | Src: " << pkt.srcIP 
                 << " | Dst: " << pkt.dstIP 
                 << " | Proto: " << pkt.protocol
                 << " | Size: " << pkt.bufferSize << " bytes" << endl;
            tempQueue.enqueue(pkt);
            count++;
        }

        // Restore packets
        while (!tempQueue.isEmpty()) {
            packetQueue.enqueue(tempQueue.dequeue());
        }
    }

    void displayPacketLayers(int packetId) {
        cout << "\n=== DISSECTING PACKET #" << packetId << " ===" << endl;
        Queue<PacketData> tempQueue;
        bool found = false;

        while (!packetQueue.isEmpty()) {
            PacketData pkt = packetQueue.dequeue();
            if (pkt.id == packetId) {
                Stack<Layer> layers = PacketParser::parsePacket(pkt);
                
                cout << "Packet Details:" << endl;
                cout << "  ID: " << pkt.id << " | Size: " << pkt.bufferSize << " bytes" << endl;
                cout << "\nLayer Stack (top to bottom):" << endl;
                
                // Pop layers from stack to display
                Stack<Layer> tempStack;
                while (!layers.isEmpty()) {
                    tempStack.push(layers.pop());
                }
                
                int layerNum = 1;
                while (!tempStack.isEmpty()) {
                    Layer layer = tempStack.pop();
                    cout << "  [Layer " << layerNum++ << "] " << layer.name 
                         << " (Offset: " << layer.offset << ", Length: " << layer.length << ")" << endl;
                    cout << "    " << layer.info << endl;
                }
                found = true;
            }
            tempQueue.enqueue(pkt);
        }

        while (!tempQueue.isEmpty()) {
            packetQueue.enqueue(tempQueue.dequeue());
        }

        if (!found) cout << "Packet #" << packetId << " not found!" << endl;
    }

    void filterPackets(string srcIP, string dstIP) {
        cout << "\n=== FILTERING PACKETS ===" << endl;
        cout << "Filter: Src=" << srcIP << " | Dst=" << dstIP << endl;

        Queue<PacketData> tempQueue;
        int matched = 0;
        int oversized = 0;

        while (!packetQueue.isEmpty()) {
            PacketData pkt = packetQueue.dequeue();
            
            // Check if matches filter criteria
            if (pkt.srcIP == srcIP && pkt.dstIP == dstIP) {
                if (pkt.bufferSize <= 1500) {
                    double delay = (double)pkt.bufferSize / 1000.0;
                    cout << "✓ Matched Packet #" << pkt.id 
                         << " | Size: " << pkt.bufferSize
                         << " | Estimated Delay: " << fixed << setprecision(2) 
                         << delay << " ms" << endl;
                    filteredQueue.enqueue(pkt);
                    matched++;
                } else {
                    cout << "✗ Skipped Packet #" << pkt.id << " (oversized: " 
                         << pkt.bufferSize << " bytes)" << endl;
                    oversized++;
                }
            }
            tempQueue.enqueue(pkt);
        }

        while (!tempQueue.isEmpty()) {
            packetQueue.enqueue(tempQueue.dequeue());
        }

        cout << "\nFilter Results:" << endl;
        cout << "  Matched: " << matched << " packets" << endl;
        cout << "  Oversized (skipped): " << oversized << " packets" << endl;
    }

    void replayPackets() {
        cout << "\n=== REPLAYING FILTERED PACKETS ===" << endl;
        
        if (filteredQueue.isEmpty()) {
            cout << "No filtered packets to replay!" << endl;
            return;
        }

        Queue<PacketData> retryQueue;
        int successCount = 0;
        int failCount = 0;

        while (!filteredQueue.isEmpty()) {
            PacketData pkt = filteredQueue.dequeue();
            cout << "Replaying Packet #" << pkt.id << "... ";

            // **FIX**: Actual packet replay (sending back)
            int bytesSent = sendto(rawSocket, pkt.buffer, pkt.bufferSize, 0, nullptr, 0);
            
            bool success = (bytesSent == pkt.bufferSize);
            
            if (success) {
                cout << "✓ SUCCESS (" << bytesSent << " bytes sent)" << endl;
                successCount++;
            } else {
                cout << "✗ FAILED";
                if (pkt.retryCount < 2) {
                    cout << " - Retry " << (pkt.retryCount + 1) << "/2" << endl;
                    pkt.retryCount++;
                    retryQueue.enqueue(pkt);
                    failCount++;
                } else {
                    cout << " - Max retries reached, moving to backup" << endl;
                    backupQueue.enqueue(pkt);
                    failCount++;
                }
            }
        }

        // Move retry packets back for another attempt
        while (!retryQueue.isEmpty()) {
            filteredQueue.enqueue(retryQueue.dequeue());
        }

        cout << "\nReplay Summary:" << endl;
        cout << "  Success: " << successCount << " packets" << endl;
        cout << "  Failed: " << failCount << " packets" << endl;
    }

    void displayBackupList() {
        cout << "\n=== BACKUP LIST (FAILED REPLAYS) ===" << endl;
        
        if (backupQueue.isEmpty()) {
            cout << "Backup queue is empty" << endl;
            return;
        }

        Queue<PacketData> tempQueue;
        int count = 0;

        while (!backupQueue.isEmpty()) {
            PacketData pkt = backupQueue.dequeue();
            cout << "Packet #" << pkt.id 
                 << " | Size: " << pkt.bufferSize << " bytes"
                 << " | Retries: " << pkt.retryCount << endl;
            tempQueue.enqueue(pkt);
            count++;
        }

        while (!tempQueue.isEmpty()) {
            backupQueue.enqueue(tempQueue.dequeue());
        }
        
        cout << "Total in backup: " << count << " packets" << endl;
    }

    ~NetworkMonitor() {
        if (rawSocket >= 0) close(rawSocket);
    }
};

// ========== MAIN ==========
int main() {
  
    cout << "Network Packet Monitor System" << endl;
    cout << "\n program requires ROOT privileges" << endl;
    
    // Check root privileges
    if (geteuid() != 0) {
        cerr << "Error: Must run as root: sudo ./networkmonitor" << endl;
        return 1;
    }

    // Initialize monitor
    NetworkMonitor monitor("eth0"); // Change to your interface if needed

    if (!monitor.initSocket()) {
        return 1;
    }

    cout << "\n - TIP: Generate traffic in another terminal:" << endl;
    cout << "   - ping google.com" << endl;
    cout << "   - Browse websites" << endl;

    // Test Case 1: Capture packets for 60 seconds (as required)
    monitor.capturePackets(60);

    // Test Case 2: Display captured packets
    monitor.displayPackets();

    // Test Case 3: Dissect a sample packet
    monitor.displayPacketLayers(0);

    // Test Case 4: Filter packets (update IPs based on captured packets)
    monitor.filterPackets("172.31.127.222", "185.125.190.56");

    // Test Case 5: Replay filtered packets
    monitor.replayPackets();

    // Test Case 6: Display backup list
    monitor.displayBackupList();

    cout << "\n End complete!" << endl;
    return 0;
}
