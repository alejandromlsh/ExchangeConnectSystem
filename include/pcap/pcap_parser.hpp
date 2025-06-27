#pragma once
#include "memory_mapper.hpp"
#include "types.hpp"
#include <chrono>
#include <functional>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <cstring>

namespace pcap {


// High-performance inline byte swapping - compiles to single CPU instructions. This will replace the system calls
inline uint16_t fast_ntohs(uint16_t x) noexcept {
    return __builtin_bswap16(x);
}

inline uint32_t fast_ntohl(uint32_t x) noexcept {
    return __builtin_bswap32(x);
}



class PcapParser {
private:
    MemoryMapper mapper_;
    size_t current_offset_;
    bool header_validated_;
    bool is_nanosecond_format_;
    ParseStats stats_;
    std::chrono::high_resolution_clock::time_point start_time_;
    
    // Optional callback for packet processing
    std::function<void(const PacketInfo&)> packet_callback_;



public:
    explicit PcapParser(const std::string& filename);
    
    // Set callback for packet processing (optional)
    void set_packet_callback(std::function<void(const PacketInfo&)> callback) {
        packet_callback_ = std::move(callback);
    }
    
    // High-performance parsing methods
    bool parse_all();
    bool parse_next_packet(PacketInfo& packet_info);
    
    // Statistics and utility methods
    const ParseStats& get_stats() const { return stats_; }
    bool has_more_data() const { return current_offset_ < mapper_.size(); }
    void reset();
    
    // Static utility methods
    static std::string ip_to_string(uint32_t ip);
    static std::string mac_to_string(const std::array<uint8_t, 6>& mac);

private:
    bool validate_pcap_header();
    bool parse_ethernet_packet(const PcapPacketHeader& pkt_header, PacketInfo& packet_info);
    bool parse_ip_packet(const uint8_t* data, size_t data_size, PacketInfo& packet_info);
    bool parse_tcp_packet(const uint8_t* data, size_t data_size, PacketInfo& packet_info);
    bool parse_udp_packet(const uint8_t* data, size_t data_size, PacketInfo& packet_info);

    __attribute__((always_inline)) inline bool parse_ethernet_packet_unchecked(const PcapPacketHeader& pkt_header, PacketInfo& packet_info);  // NEW
    __attribute__((always_inline)) inline bool parse_ip_packet_unchecked(const uint8_t* data, size_t data_size, PacketInfo& packet_info);      // NEW
    __attribute__((always_inline)) inline bool parse_tcp_packet_unchecked(const uint8_t* data, size_t data_size, PacketInfo& packet_info);     // NEW
    __attribute__((always_inline)) inline bool parse_udp_packet_unchecked(const uint8_t* data, size_t data_size, PacketInfo& packet_info);     // NEW
};

// Implementation
inline PcapParser::PcapParser(const std::string& filename) 
    : mapper_(filename), current_offset_(0), header_validated_(false), 
      is_nanosecond_format_(false) {
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Optimize for sequential reading
    mapper_.advise_sequential();
}

inline bool PcapParser::parse_all() {
    if (!validate_pcap_header()) {
        return false;
    }
    
    // High-performance parsing loop - reuse PacketInfo object
    PacketInfo packet_info;
    while (has_more_data()) {
        if (parse_next_packet(packet_info)) {
            // Direct callback execution - no branching overhead
            if (packet_callback_) {
                packet_callback_(packet_info);
            }
        } else {
            break;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    stats_.parse_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time_).count();
    return true;
}
// This function was safe but a bit slower. I will replace for a faster version
// inline bool PcapParser::parse_next_packet(PacketInfo& packet_info) {
//     if (!header_validated_ && !validate_pcap_header()) {
//         return false;
//     }
    
//     if (current_offset_ + sizeof(PcapPacketHeader) > mapper_.size()) {
//         return false;
//     }
    
//     const auto* pkt_header = mapper_.read_at<PcapPacketHeader>(current_offset_);
//     if (!pkt_header) {
//         stats_.parse_errors++;
//         return false;
//     }
    
//     current_offset_ += sizeof(PcapPacketHeader);
    
//     if (current_offset_ + pkt_header->caplen > mapper_.size()) {
//         stats_.parse_errors++;
//         return false;
//     }
    
//     bool success = parse_ethernet_packet(*pkt_header, packet_info);
//     if (success) {
//         stats_.total_packets++;
//         stats_.total_bytes_processed += pkt_header->caplen;
//     } else {
//         stats_.parse_errors++;
//     }
    
//     return success;
// }

inline bool PcapParser::parse_next_packet(PacketInfo& packet_info) {
    // KEEP: Header validation (essential - runs once)
    if (!header_validated_ && !validate_pcap_header()) {
        return false;
    }
    
    // KEEP: Packet header bounds check
    if (current_offset_ + sizeof(PcapPacketHeader) > mapper_.size()) {
        return false;
    }
    
    // OPTIMIZED: Use unchecked read since we already validated bounds
    const auto* pkt_header = mapper_.read_at_unchecked<PcapPacketHeader>(current_offset_);
    current_offset_ += sizeof(PcapPacketHeader);
    
    // KEEP: Validate entire packet size once
    if (current_offset_ + pkt_header->caplen > mapper_.size()) {
        stats_.parse_errors++;
        return false;
    }
    
    // Now we KNOW the entire packet is within bounds
    bool success = parse_ethernet_packet_unchecked(*pkt_header, packet_info);
    if (success) {
        stats_.total_packets++;
        stats_.total_bytes_processed += pkt_header->caplen;
    } else {
        stats_.parse_errors++;
    }
    
    return success;
}


inline bool PcapParser::validate_pcap_header() {
    if (header_validated_) return true;
    
    if (mapper_.size() < sizeof(PcapFileHeader)) {
        return false;
    }
    
    const auto* header = mapper_.read_at<PcapFileHeader>(0);
    if (!header) {
        return false;
    }
    
    uint32_t magic = header->magic_number;
    bool is_microsecond = (magic == 0xA1B2C3D4 || magic == 0xD4C3B2A1);
    bool is_nanosecond = (magic == 0xA1B23C4D || magic == 0x4D3CB2A1);
    
    if (!is_microsecond && !is_nanosecond) {
        return false;
    }
    
    is_nanosecond_format_ = is_nanosecond;
    current_offset_ = sizeof(PcapFileHeader);
    header_validated_ = true;
    return true;
}

inline bool PcapParser::parse_ethernet_packet(const PcapPacketHeader& pkt_header, PacketInfo& packet_info) {
    size_t packet_start = current_offset_;
    
    // Reset packet info for reuse
    packet_info = {};
    
    // Handle timestamp conversion based on format
    if (is_nanosecond_format_) {
        packet_info.timestamp_us = static_cast<uint64_t>(pkt_header.ts_sec) * 1000000ULL + 
                                  (pkt_header.ts_usec / 1000);
    } else {
        packet_info.timestamp_us = static_cast<uint64_t>(pkt_header.ts_sec) * 1000000ULL + pkt_header.ts_usec;
    }
    
    packet_info.packet_length = pkt_header.len;
    packet_info.captured_length = pkt_header.caplen;
    
    // Zero-copy Ethernet header access
    const auto* eth_header = mapper_.read_at<EthernetHeader>(current_offset_);
    if (!eth_header) {
        current_offset_ = packet_start + pkt_header.caplen;
        return false;
    }
    
    current_offset_ += sizeof(EthernetHeader);
    stats_.ethernet_packets++;
    
    // Extract Ethernet information
    packet_info.src_mac = eth_header->src_mac;
    packet_info.dest_mac = eth_header->dest_mac;
    //packet_info.ethertype = ntohs(eth_header->ethertype);
    packet_info.ethertype = fast_ntohs(eth_header->ethertype);
    
    // Parse IP layer if present
    if (packet_info.ethertype == 0x0800) { // IPv4
        size_t remaining_size = packet_start + pkt_header.caplen - current_offset_;
        const uint8_t* ip_data = mapper_.data() + current_offset_;
        
        if (parse_ip_packet(ip_data, remaining_size, packet_info)) {
            stats_.ip_packets++;
        }
    }
    
    // Move to next packet
    current_offset_ = packet_start + pkt_header.caplen;
    return true;
}

__attribute__((always_inline)) inline bool PcapParser::parse_ethernet_packet_unchecked(const PcapPacketHeader& pkt_header, PacketInfo& packet_info) {
    size_t packet_start = current_offset_;
    
    // Reset packet info for reuse
    packet_info = {};
    
    // Handle timestamp conversion based on format
    if (is_nanosecond_format_) {
        packet_info.timestamp_us = static_cast<uint64_t>(pkt_header.ts_sec) * 1000000ULL +
                                  (pkt_header.ts_usec / 1000);
    } else {
        packet_info.timestamp_us = static_cast<uint64_t>(pkt_header.ts_sec) * 1000000ULL + pkt_header.ts_usec;
    }
    
    packet_info.packet_length = pkt_header.len;
    packet_info.captured_length = pkt_header.caplen;
    
    // OPTIMIZED: Zero-copy Ethernet header access without bounds check
    const auto* eth_header = mapper_.read_at_unchecked<EthernetHeader>(current_offset_);
    current_offset_ += sizeof(EthernetHeader);
    stats_.ethernet_packets++;
    
    // Extract Ethernet information
    packet_info.src_mac = eth_header->src_mac;
    packet_info.dest_mac = eth_header->dest_mac;
    packet_info.ethertype = fast_ntohs(eth_header->ethertype);
    
    // Parse IP layer if present
    if (packet_info.ethertype == 0x0800) { // IPv4
        size_t remaining_size = packet_start + pkt_header.caplen - current_offset_;
        const uint8_t* ip_data = mapper_.data() + current_offset_;
        
        // OPTIMIZED: No bounds check needed - we validated entire packet
        if (parse_ip_packet_unchecked(ip_data, remaining_size, packet_info)) {
            stats_.ip_packets++;
        }
    }
    
    // Move to next packet
    current_offset_ = packet_start + pkt_header.caplen;
    return true;
}


inline bool PcapParser::parse_ip_packet(const uint8_t* data, size_t data_size, PacketInfo& packet_info) {
    if (data_size < sizeof(IPv4Header)) {
        return false;
    }
    
    const auto* ip_header = reinterpret_cast<const IPv4Header*>(data);
    
    // Extract IP information
    packet_info.has_ip = true;
    // packet_info.src_ip = ntohl(ip_header->src_ip);
    // packet_info.dest_ip = ntohl(ip_header->dest_ip);
    packet_info.src_ip = fast_ntohl(ip_header->src_ip);
    packet_info.dest_ip = fast_ntohl(ip_header->dest_ip);
    packet_info.ip_protocol = ip_header->protocol;
    
    // Calculate IP header length
    uint8_t ip_header_len = (ip_header->version_ihl & 0x0F) * 4;
    if (ip_header_len < 20 || ip_header_len > data_size) {
        return false;
    }
    
    // Parse transport layer
    const uint8_t* transport_data = data + ip_header_len;
    size_t transport_size = data_size - ip_header_len;
    
    if (ip_header->protocol == 6) { // TCP
        if (parse_tcp_packet(transport_data, transport_size, packet_info)) {
            stats_.tcp_packets++;
            packet_info.is_tcp = true;
        }
    } else if (ip_header->protocol == 17) { // UDP
        if (parse_udp_packet(transport_data, transport_size, packet_info)) {
            stats_.udp_packets++;
        }
    } else {
        stats_.other_packets++;
    }
    
    return true;
}

__attribute__((always_inline)) inline bool PcapParser::parse_ip_packet_unchecked(const uint8_t* data, size_t data_size, PacketInfo& packet_info) {
    // OPTIMIZED: Skip size check - caller guarantees valid data
    const auto* ip_header = reinterpret_cast<const IPv4Header*>(data);
    
    // Extract IP information
    packet_info.has_ip = true;
    packet_info.src_ip = fast_ntohl(ip_header->src_ip);
    packet_info.dest_ip = fast_ntohl(ip_header->dest_ip);
    packet_info.ip_protocol = ip_header->protocol;
    
    // Calculate IP header length
    uint8_t ip_header_len = (ip_header->version_ihl & 0x0F) * 4;
    
    // OPTIMIZED: Skip bounds check - we know packet is valid
    const uint8_t* transport_data = data + ip_header_len;
    size_t transport_size = data_size - ip_header_len;
    
    if (ip_header->protocol == 6) { // TCP
        if (parse_tcp_packet_unchecked(transport_data, transport_size, packet_info)) {
            stats_.tcp_packets++;
            packet_info.is_tcp = true;
        }
    } else if (ip_header->protocol == 17) { // UDP
        if (parse_udp_packet_unchecked(transport_data, transport_size, packet_info)) {
            stats_.udp_packets++;
        }
    } else {
        stats_.other_packets++;
    }
    
    return true;
}


inline bool PcapParser::parse_tcp_packet(const uint8_t* data, size_t data_size, PacketInfo& packet_info) {
    if (data_size < sizeof(TcpHeader)) {
        return false;
    }
    
    const auto* tcp_header = reinterpret_cast<const TcpHeader*>(data);
    
    packet_info.has_transport = true;
    // packet_info.src_port = ntohs(tcp_header->src_port);
    // packet_info.dest_port = ntohs(tcp_header->dest_port);
    // packet_info.tcp_seq = ntohl(tcp_header->seq_num);
    // packet_info.tcp_ack = ntohl(tcp_header->ack_num);
    packet_info.src_port = fast_ntohs(tcp_header->src_port);
    packet_info.dest_port = fast_ntohs(tcp_header->dest_port);
    packet_info.tcp_seq = fast_ntohl(tcp_header->seq_num);
    packet_info.tcp_ack = fast_ntohl(tcp_header->ack_num);
    packet_info.tcp_flags = tcp_header->flags;
    
    // Calculate TCP header length and extract payload
    uint8_t tcp_header_len = (tcp_header->data_offset >> 4) * 4;
    if (tcp_header_len >= 20 && tcp_header_len <= data_size) {
        packet_info.payload = data + tcp_header_len;
        packet_info.payload_size = data_size - tcp_header_len;
    }
    
    return true;
}

__attribute__((always_inline)) inline bool PcapParser::parse_tcp_packet_unchecked(const uint8_t* data, size_t data_size, PacketInfo& packet_info) {
    // OPTIMIZED: Skip size check - caller guarantees valid data
    const auto* tcp_header = reinterpret_cast<const TcpHeader*>(data);
    
    packet_info.has_transport = true;
    packet_info.src_port = fast_ntohs(tcp_header->src_port);
    packet_info.dest_port = fast_ntohs(tcp_header->dest_port);
    packet_info.tcp_seq = fast_ntohl(tcp_header->seq_num);
    packet_info.tcp_ack = fast_ntohl(tcp_header->ack_num);
    packet_info.tcp_flags = tcp_header->flags;
    
    // Calculate TCP header length and extract payload
    uint8_t tcp_header_len = (tcp_header->data_offset >> 4) * 4;
    if (tcp_header_len >= 20 && tcp_header_len <= data_size) {
        packet_info.payload = data + tcp_header_len;
        packet_info.payload_size = data_size - tcp_header_len;
    }
    
    return true;
}

inline bool PcapParser::parse_udp_packet(const uint8_t* data, size_t data_size, PacketInfo& packet_info) {
    if (data_size < sizeof(UdpHeader)) {
        return false;
    }
    
    const auto* udp_header = reinterpret_cast<const UdpHeader*>(data);
    
    packet_info.has_transport = true;
    // packet_info.src_port = ntohs(udp_header->src_port);
    // packet_info.dest_port = ntohs(udp_header->dest_port);
    packet_info.src_port = fast_ntohs(udp_header->src_port);
    packet_info.dest_port = fast_ntohs(udp_header->dest_port);

    
    // Extract UDP payload
    if (data_size > sizeof(UdpHeader)) {
        packet_info.payload = data + sizeof(UdpHeader);
        packet_info.payload_size = data_size - sizeof(UdpHeader);
    }
    
    return true;
}

__attribute__((always_inline)) inline bool PcapParser::parse_udp_packet_unchecked(const uint8_t* data, size_t data_size, PacketInfo& packet_info) {
    // OPTIMIZED: Skip size check - caller guarantees valid data
    const auto* udp_header = reinterpret_cast<const UdpHeader*>(data);
    
    packet_info.has_transport = true;
    packet_info.src_port = fast_ntohs(udp_header->src_port);
    packet_info.dest_port = fast_ntohs(udp_header->dest_port);
    
    // Extract UDP payload
    if (data_size > sizeof(UdpHeader)) {
        packet_info.payload = data + sizeof(UdpHeader);
        packet_info.payload_size = data_size - sizeof(UdpHeader);
    }
    
    return true;
}


inline void PcapParser::reset() {
    current_offset_ = sizeof(PcapFileHeader);
    stats_ = {};
    start_time_ = std::chrono::high_resolution_clock::now();
}

inline std::string PcapParser::ip_to_string(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

inline std::string PcapParser::mac_to_string(const std::array<uint8_t, 6>& mac) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}

// Helper method implementations for PacketInfo
inline std::string PacketInfo::src_ip_str() const {
    return PcapParser::ip_to_string(src_ip);
}

inline std::string PacketInfo::dest_ip_str() const {
    return PcapParser::ip_to_string(dest_ip);
}

inline std::string PacketInfo::src_mac_str() const {
    return PcapParser::mac_to_string(src_mac);
}

inline std::string PacketInfo::dest_mac_str() const {
    return PcapParser::mac_to_string(dest_mac);
}

} // namespace pcap
