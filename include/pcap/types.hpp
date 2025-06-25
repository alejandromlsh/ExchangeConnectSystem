#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace pcap {

// PCAP file header (24 bytes)
struct PcapFileHeader {
    uint32_t magic_number;      // 0xA1B2C3D4 or 0xD4C3B2A1
    uint16_t version_major;     // Major version number
    uint16_t version_minor;     // Minor version number
    int32_t thiszone;          // GMT to local correction
    uint32_t sigfigs;          // Accuracy of timestamps
    uint32_t snaplen;          // Max length of captured packets
    uint32_t network;          // Data link type
} __attribute__((packed));

// PCAP packet header (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;           // Timestamp seconds
    uint32_t ts_usec;          // Timestamp microseconds
    uint32_t caplen;           // Length of portion present
    uint32_t len;              // Length this packet (off wire)
} __attribute__((packed));

// Ethernet header (14 bytes)
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ethertype;
} __attribute__((packed));

// IPv4 header (20 bytes minimum)
struct IPv4Header {
    uint8_t version_ihl;       // Version (4 bits) + IHL (4 bits)
    uint8_t tos;               // Type of service
    uint16_t total_length;     // Total length
    uint16_t identification;   // Identification
    uint16_t flags_fragment;   // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t ttl;               // Time to live
    uint8_t protocol;          // Protocol
    uint16_t checksum;         // Header checksum
    uint32_t src_ip;           // Source address
    uint32_t dest_ip;          // Destination address
} __attribute__((packed));

// UDP header (8 bytes)
struct UdpHeader {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint16_t length;           // UDP length
    uint16_t checksum;         // UDP checksum
} __attribute__((packed));

// TCP header (20 bytes minimum)
struct TcpHeader {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint32_t seq_num;          // Sequence number
    uint32_t ack_num;          // Acknowledgment number
    uint8_t data_offset;       // Data offset (4 bits) + Reserved (4 bits)
    uint8_t flags;             // TCP flags
    uint16_t window;           // Window size
    uint16_t checksum;         // Checksum
    uint16_t urgent_ptr;       // Urgent pointer
} __attribute__((packed));

// Parsed packet information
struct PacketInfo {
    uint64_t timestamp_us;     // Timestamp in microseconds
    uint32_t packet_length;    // Original packet length
    uint32_t captured_length;  // Captured packet length
    
    // Ethernet info
    std::array<uint8_t, 6> src_mac;
    std::array<uint8_t, 6> dest_mac;
    uint16_t ethertype;
    
    // IP info (if present)
    bool has_ip = false;
    uint32_t src_ip = 0;
    uint32_t dest_ip = 0;
    uint8_t ip_protocol = 0;
    
    // Transport layer info (if present)
    bool has_transport = false;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    
    // TCP specific (if TCP)
    bool is_tcp = false;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_flags = 0;
    
    // Payload info
    const uint8_t* payload = nullptr;
    size_t payload_size = 0;
    
    // Helper methods
    std::string src_ip_str() const;
    std::string dest_ip_str() const;
    std::string src_mac_str() const;
    std::string dest_mac_str() const;
};

// Parser statistics
struct ParseStats {
    size_t total_packets = 0;
    size_t ethernet_packets = 0;
    size_t ip_packets = 0;
    size_t tcp_packets = 0;
    size_t udp_packets = 0;
    size_t other_packets = 0;
    size_t parse_errors = 0;
    size_t total_bytes_processed = 0;
    double parse_time_ms = 0.0;
};

} // namespace pcap
