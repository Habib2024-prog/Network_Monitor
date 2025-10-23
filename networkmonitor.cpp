#include <iostream>
#include <cstring>
#include <ctime>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <chrono>
#include <iomanip>

using namespace std;

//CUSTOM QUEUE 
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

// CUSTOM STACK 
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

//  PACKET STRUCTURES 
struct PacketData {
    int id;
    time_t timestamp;
    unsigned char buffer[2048];
    int bufferSize;
    string srcIP;
    string dstIP;
    string protocol;

    PacketData() : id(0), timestamp(0), bufferSize(0), srcIP(""), dstIP(""), protocol("") {}
};

struct Layer {
    string name;
    string info;
};

// PROTOCOL PARSING FUNCTIONS 
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

//  PACKET PARSER 
class PacketParser {
public:
    static Queue<Layer> parsePacket(const PacketData& pkt) {
        Queue<Layer> layers;
        Stack<unsigned char*> layerStack;

        // Push full packet onto stack
        unsigned char* data = (unsigned char*)pkt.buffer;
        layerStack.push(data);

        // Parse Ethernet
        if (pkt.bufferSize >= 14) {
            Layer eth;
            eth.name = "Ethernet";
            unsigned char* dst_mac = data;
            unsigned char* src_mac = data + 6;
            unsigned short eth_type = ntohs(*(unsigned short*)(data + 12));

            char mac_info[256];
            sprintf(mac_info, "Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x, Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Type: 0x%04x",
                    dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], eth_type);
            eth.info = mac_info;
            layers.enqueue(eth);

            // Parse IP layer
            if (eth_type == 0x0800 && pkt.bufferSize >= 34) {
                // IPv4
                Layer ipv4;
                ipv4.name = "IPv4";
                unsigned char* ipv4_data = data + 14;
                string src = extractIPv4(ipv4_data + 12);
                string dst = extractIPv4(ipv4_data + 16);
                unsigned char protocol = ipv4_data[9];

                ipv4.info = "Source: " + src + ", Dest: " + dst + ", Protocol: " + to_string((int)protocol);
                layers.enqueue(ipv4);

                // Parse TCP/UDP
                if (protocol == 6 && pkt.bufferSize >= 54) {
                    Layer tcp;
                    tcp.name = "TCP";
                    unsigned char* tcp_data = data + 34;
                    unsigned short src_port = ntohs(*(unsigned short*)tcp_data);
                    unsigned short dst_port = ntohs(*(unsigned short*)(tcp_data + 2));
                    tcp.info = "Src Port: " + to_string(src_port) + ", Dst Port: " + to_string(dst_port);
                    layers.enqueue(tcp);
                } else if (protocol == 17 && pkt.bufferSize >= 42) {
                    Layer udp;
                    udp.name = "UDP";
                    unsigned char* udp_data = data + 34;
                    unsigned short src_port = ntohs(*(unsigned short*)udp_data);
                    unsigned short dst_port = ntohs(*(unsigned short*)(udp_data + 2));
                    udp.info = "Src Port: " + to_string(src_port) + ", Dst Port: " + to_string(dst_port);
                    layers.enqueue(udp);
                }
            } else if (eth_type == 0x86DD && pkt.bufferSize >= 54) {
                // IPv6
                Layer ipv6;
                ipv6.name = "IPv6";
                unsigned char* ipv6_data = data + 14;
                string src = extractIPv6(ipv6_data + 8);
                string dst = extractIPv6(ipv6_data + 24);
                unsigned char next_header = ipv6_data[6];

                ipv6.info = "Source: " + src + ", Dest: " + dst + ", Next Header: " + to_string((int)next_header);
                layers.enqueue(ipv6);
            }
        }
        return layers;
    }
};

//NETWORK MONITOR 
class NetworkMonitor {
private:
    Queue<PacketData> packetQueue;
    Queue<PacketData> filteredQueue;
    Queue<PacketData> backupQueue;
    int packetIdCounter;
    int rawSocket;

public:
    NetworkMonitor() : packetIdCounter(0), rawSocket(-1) {}

    bool initSocket() {
        rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rawSocket < 0) {
            cerr << "Error: Need root privileges to create raw socket" << endl;
            return false;
        }
        return true;
    }

    void capturePackets(int durationSeconds) {
        cout << "\n<<<CAPTURING PACKETS FOR " << durationSeconds << " SECONDS >>>" << endl;
        auto startTime = chrono::high_resolution_clock::now();

        while (true) {
            auto currentTime = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(currentTime - startTime).count();
            if (elapsed >= durationSeconds) break;

            unsigned char buffer[2048];
            int bufferSize = recv(rawSocket, buffer, 2048, MSG_DONTWAIT);

            if (bufferSize > 0) {
                PacketData pkt;
                pkt.id = packetIdCounter++;
                pkt.timestamp = time(nullptr);
                memcpy(pkt.buffer, buffer, bufferSize);
                pkt.bufferSize = bufferSize;

                // Parse IPs if available
                if (bufferSize >= 34) {
                    unsigned char* ip_data = buffer + 14;
                    pkt.srcIP = extractIPv4(ip_data + 12);
                    pkt.dstIP = extractIPv4(ip_data + 16);
                    unsigned char protocol = ip_data[9];
                    pkt.protocol = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "Other";
                }

                packetQueue.enqueue(pkt);
                cout << "Captured Packet #" << pkt.id << " - Src: " << pkt.srcIP 
                     << " Dst: " << pkt.dstIP << " Size: " << bufferSize << endl;
            }
            usleep(100000); // Sleep 100ms
        }
        cout << "Capture complete. Total packets: " << packetQueue.getSize() << endl;
    }

    void displayPackets() {
        cout << "\n<<<CURRENT PACKETS IN QUEUE >>>" << endl;
        Queue<PacketData> tempQueue;
        int count = 0;

        while (!packetQueue.isEmpty() && count < 10) {
            PacketData pkt = packetQueue.dequeue();
            cout << "Packet ID: " << pkt.id << " | Time: " << ctime(&pkt.timestamp)
                 << "Src IP: " << pkt.srcIP << " | Dst IP: " << pkt.dstIP 
                 << " | Size: " << pkt.bufferSize << " bytes" << endl;
            tempQueue.enqueue(pkt);
            count++;
        }

        // Restore packets to queue
        while (!tempQueue.isEmpty()) {
            packetQueue.enqueue(tempQueue.dequeue());
        }
    }

    void displayPacketLayers(int packetId) {
        cout << "\n<<<< DISSECTING PACKET #" << packetId << ">>>> " << endl;
        Queue<PacketData> tempQueue;
        bool found = false;

        while (!packetQueue.isEmpty()) {
            PacketData pkt = packetQueue.dequeue();
            if (pkt.id == packetId) {
                Queue<Layer> layers = PacketParser::parsePacket(pkt);
                cout << "Packet Details:" << endl;
                cout << "ID: " << pkt.id << " | Size: " << pkt.bufferSize << " bytes" << endl;
                int layerNum = 1;
                while (!layers.isEmpty()) {
                    Layer layer = layers.dequeue();
                    cout << "Layer " << layerNum++ << " (" << layer.name << "): " << layer.info << endl;
                }
                found = true;
            }
            tempQueue.enqueue(pkt);
        }

        while (!tempQueue.isEmpty()) {
            packetQueue.enqueue(tempQueue.dequeue());
        }

        if (!found) cout << "Packet not found" << endl;
    }

    void filterPackets(string srcIP, string dstIP) {
        cout << "\n<<<< FILTERING PACKETS >>>>" << endl;
        cout << "Filter: Src=" << srcIP << " Dst=" << dstIP << endl;

        Queue<PacketData> tempQueue;
        int matched = 0;

        while (!packetQueue.isEmpty()) {
            PacketData pkt = packetQueue.dequeue();
            if (pkt.srcIP == srcIP && pkt.dstIP == dstIP) {
                if (pkt.bufferSize <= 1500) {
                    double delay = (double)pkt.bufferSize / 1000.0;
                    cout << "Matched Packet #" << pkt.id << " | Delay: " << fixed << setprecision(2) 
                         << delay << " ms" << endl;
                    filteredQueue.enqueue(pkt);
                    matched++;
                }
            }
            tempQueue.enqueue(pkt);
        }

        while (!tempQueue.isEmpty()) {
            packetQueue.enqueue(tempQueue.dequeue());
        }

        cout << "Filtered " << matched << " packets" << endl;
    }

    void replayPackets() {
        cout << "\n<<<< REPLAYING FILTERED PACKETS >>>>" << endl;
        Queue<PacketData> tempQueue;
        int retries = 0;

        while (!filteredQueue.isEmpty()) {
            PacketData pkt = filteredQueue.dequeue();
            cout << "Replaying Packet #" << pkt.id << "... ";

            // Simulate replay
            bool success = (rand() % 100 > 20); // 80% success rate
            if (success) {
                cout << "SUCCESS" << endl;
            } else {
                cout << "FAILED - Moving to backup" << endl;
                if (retries < 2) {
                    tempQueue.enqueue(pkt);
                    retries++;
                } else {
                    backupQueue.enqueue(pkt);
                    retries = 0;
                }
            }
        }

        while (!tempQueue.isEmpty()) {
            filteredQueue.enqueue(tempQueue.dequeue());
        }
    }

    void displayBackupList() {
        cout << "\n<<<<< BACKUP LIST (FAILED REPLAYS) >>>>>" << endl;
        Queue<PacketData> tempQueue;
        int count = 0;

        while (!backupQueue.isEmpty() && count < 5) {
            PacketData pkt = backupQueue.dequeue();
            cout << "Packet #" << pkt.id << " | Size: " << pkt.bufferSize << " bytes" << endl;
            tempQueue.enqueue(pkt);
            count++;
        }

        while (!tempQueue.isEmpty()) {
            backupQueue.enqueue(tempQueue.dequeue());
        }

        if (count == 0) cout << "Backup list is empty" << endl;
    }

    ~NetworkMonitor() {
        if (rawSocket >= 0) close(rawSocket);
    }
};

// ========== MAIN ==========
int main() {
    cout << "<<<< NETWORK MONITOR SYSTEM >>>" << endl;
    cout << "Note:requires ROOT privileges" << endl;

    NetworkMonitor monitor;

    if (!monitor.initSocket()) {
        return 1;
    }

    // Demo: Capture for 10 seconds (reduce for testing)
    cout << "\nStarting packet capture for 10 seconds..." << endl;
    monitor.capturePackets(10);

    // Display captured packets
    monitor.displayPackets();

    // Dissect a sample packet (try packet 0 if it exists)
    monitor.displayPacketLayers(0);

    // Filter packets (change IPs based on your network)
    monitor.filterPackets("127.0.0.1", "127.0.0.1");

    // Replay filtered packets
    monitor.replayPackets();

    // Display backup list
    monitor.displayBackupList();

    cout << "\n<<< End of Demo >>>" << endl;
    return 0;
}