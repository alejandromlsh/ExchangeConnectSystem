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

enum class ParseState {
    EXPECT_PCAP_HEADER,
    EXPECT_PACKET_HEADER,
    PARSE_ETHERNET,
    PARSE_IP,
    PARSE_TRANSPORT,
    EXTRACT_PAYLOAD,
    PACKET_COMPLETE,
    ERROR_STATE,
    END_OF_FILE
};

class FSMPcapParser {
private:
    MemoryMapper mapper_;
    ParseState current_state_;
    size_t current_offset_;
    bool header_validated_;
    bool is_nanosecond_format_;
    ParseStats stats_;
    std::chrono::high_resolution_clock::time_point start_time_;
    
    // Current packet being processed
    PacketInfo current_packet_;
    const PcapPacketHeader* current_pkt_header_;
    size_t packet_start_offset_;
    
    // Callback for packet processing
    std::function<void(const PacketInfo&)> packet_callback_;

public:
    explicit FSMPcapParser(const std::string& filename);
    
    // Set callback for packet processing
    void set_packet_callback(std::function<void(const PacketInfo&)> callback) {
        packet_callback_ = std::move(callback);
    }
    
    // Parse all packets with FSM
    bool parse_all_with_fsm();
    
    // Parse next packet
    bool parse_next_packet(PacketInfo& packet_info);
    
    // Get parsing statistics
    const ParseStats& get_stats() const { return stats_; }
    
    // Check if more data available
    bool has_more_data() const { return current_offset_ < mapper_.size(); }
    
    // Reset parser to beginning
    void reset();

private:
    // FSM processing
    bool process_next_state();
    
    // FSM state handlers
    bool handle_pcap_header_state();
    bool handle_packet_header_state();
    bool handle_ethernet_state();
    bool handle_ip_state();
    bool handle_transport_state();
    bool handle_payload_state();
    bool handle_packet_complete_state();
    
    // Helper methods
    void transition_to(ParseState new_state);
    void reset_packet_state();
};

// Implementation
inline FSMPcapParser::FSMPcapParser(const std::string& filename) 
    : mapper_(filename), current_state_(ParseState::EXPECT_PCAP_HEADER),
      current_offset_(0), header_validated_(false), is_nanosecond_format_(false) {
    start_time_ = std::chrono::high_resolution_clock::now();
}

inline bool FSMPcapParser::parse_all_with_fsm() {
    // Main FSM loop
    while (current_state_ != ParseState::END_OF_FILE && 
           current_state_ != ParseState::ERROR_STATE) {
        
        if (!process_next_state()) {
            current_state_ = ParseState::ERROR_STATE;
            break;
        }
    }
    
    // Calculate parsing time
    auto end_time = std::chrono::high_resolution_clock::now();
    stats_.parse_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time_).count();
    
    return current_state_ != ParseState::ERROR_STATE;
}

inline bool FSMPcapParser::process_next_state() {
    switch (current_state_) {
        case ParseState::EXPECT_PCAP_HEADER:
            return handle_pcap_header_state();
            
        case ParseState::EXPECT_PACKET_HEADER:
            return handle_packet_header_state();
            
        case ParseState::PARSE_ETHERNET:
            return handle_ethernet_state();
            
        case ParseState::PARSE_IP:
            return handle_ip_state();
            
        case ParseState::PARSE_TRANSPORT:
            return handle_transport_state();
            
        case ParseState::EXTRACT_PAYLOAD:
            return handle_payload_state();
            
        case ParseState::PACKET_COMPLETE:
            return handle_packet_complete_state();
            
        case ParseState::ERROR_STATE:
        case ParseState::END_OF_FILE:
            return false;
            
        default:
            return false;
    }
}

inline bool FSMPcapParser::handle_pcap_header_state() {
    if (mapper_.size() < sizeof(PcapFileHeader)) {
        return false;
    }
    
    const auto* header = mapper_.read_at<PcapFileHeader>(0);
    if (!header) {
        return false;
    }
    
    // Check magic number for both microsecond and nanosecond formats
    uint32_t magic = header->magic_number;
    bool is_microsecond = (magic == 0xA1B2C3D4 || magic == 0xD4C3B2A1);
    bool is_nanosecond = (magic == 0xA1B23C4D || magic == 0x4D3CB2A1);
    
    if (!is_microsecond && !is_nanosecond) {
        return false;
    }
    
    is_nanosecond_format_ = is_nanosecond;
    current_offset_ = sizeof(PcapFileHeader);
    header_validated_ = true;
    transition_to(ParseState::EXPECT_PACKET_HEADER);
    return true;
}

inline bool FSMPcapParser::handle_packet_header_state() {
    if (current_offset_ + sizeof(PcapPacketHeader) > mapper_.size()) {
        transition_to(ParseState::END_OF_FILE);
        return true;
    }
    
    current_pkt_header_ = mapper_.read_at<PcapPacketHeader>(current_offset_);
    if (!current_pkt_header_) {
        stats_.parse_errors++;
        return false;
    }
    
    current_offset_ += sizeof(PcapPacketHeader);
    packet_start_offset_ = current_offset_;
    
    if (current_offset_ + current_pkt_header_->caplen > mapper_.size()) {
        stats_.parse_errors++;
        return false;
    }
    
    reset_packet_state();
    
    // Handle timestamp conversion based on format
    if (is_nanosecond_format_) {
        current_packet_.timestamp_us = static_cast<uint64_t>(current_pkt_header_->ts_sec) * 1000000ULL + 
                                      (current_pkt_header_->ts_usec / 1000);
    } else {
        current_packet_.timestamp_us = static_cast<uint64_t>(current_pkt_header_->ts_sec) * 1000000ULL + 
                                      current_pkt_header_->ts_usec;
    }
    
    current_packet_.packet_length = current_pkt_header_->len;
    current_packet_.captured_length = current_pkt_header_->caplen;
    
    transition_to(ParseState::PARSE_ETHERNET);
    return true;
}

inline bool FSMPcapParser::handle_ethernet_state() {
    const auto* eth_header = mapper_.read_at<EthernetHeader>(current_offset_);
    if (!eth_header) {
        current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
        transition_to(ParseState::PACKET_COMPLETE);
        return true;
    }
    
    current_offset_ += sizeof(EthernetHeader);
    stats_.ethernet_packets++;
    
    // Extract Ethernet information
    current_packet_.src_mac = eth_header->src_mac;
    current_packet_.dest_mac = eth_header->dest_mac;
    current_packet_.ethertype = ntohs(eth_header->ethertype);
    
    // Check if it's an IP packet
    if (current_packet_.ethertype == 0x0800) { // IPv4
        transition_to(ParseState::PARSE_IP);
    } else {
        current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
        transition_to(ParseState::PACKET_COMPLETE);
    }
    
    return true;
}

inline bool FSMPcapParser::handle_ip_state() {
    size_t remaining_size = packet_start_offset_ + current_pkt_header_->caplen - current_offset_;
    
    if (remaining_size < sizeof(IPv4Header)) {
        current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
        transition_to(ParseState::PACKET_COMPLETE);
        return true;
    }
    
    const auto* ip_header = mapper_.read_at<IPv4Header>(current_offset_);
    if (!ip_header) {
        current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
        transition_to(ParseState::PACKET_COMPLETE);
        return true;
    }
    
    // Extract IP information
    current_packet_.has_ip = true;
    current_packet_.src_ip = ntohl(ip_header->src_ip);
    current_packet_.dest_ip = ntohl(ip_header->dest_ip);
    current_packet_.ip_protocol = ip_header->protocol;
    
    // Calculate IP header length
    uint8_t ip_header_len = (ip_header->version_ihl & 0x0F) * 4;
    if (ip_header_len < 20 || ip_header_len > remaining_size) {
        current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
        transition_to(ParseState::PACKET_COMPLETE);
        return true;
    }
    
    current_offset_ += ip_header_len;
    stats_.ip_packets++;
    
    // Check transport protocol
    if (ip_header->protocol == 6 || ip_header->protocol == 17) { // TCP or UDP
        transition_to(ParseState::PARSE_TRANSPORT);
    } else {
        stats_.other_packets++;
        current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
        transition_to(ParseState::PACKET_COMPLETE);
    }
    
    return true;
}

inline bool FSMPcapParser::handle_transport_state() {
    size_t remaining_size = packet_start_offset_ + current_pkt_header_->caplen - current_offset_;
    
    if (current_packet_.ip_protocol == 6) { // TCP
        if (remaining_size < sizeof(TcpHeader)) {
            current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
            transition_to(ParseState::PACKET_COMPLETE);
            return true;
        }
        
        const auto* tcp_header = mapper_.read_at<TcpHeader>(current_offset_);
        if (!tcp_header) {
            current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
            transition_to(ParseState::PACKET_COMPLETE);
            return true;
        }
        
        current_packet_.has_transport = true;
        current_packet_.is_tcp = true;
        current_packet_.src_port = ntohs(tcp_header->src_port);
        current_packet_.dest_port = ntohs(tcp_header->dest_port);
        current_packet_.tcp_seq = ntohl(tcp_header->seq_num);
        current_packet_.tcp_ack = ntohl(tcp_header->ack_num);
        current_packet_.tcp_flags = tcp_header->flags;
        
        uint8_t tcp_header_len = (tcp_header->data_offset >> 4) * 4;
        current_offset_ += tcp_header_len;
        stats_.tcp_packets++;
        
    } else if (current_packet_.ip_protocol == 17) { // UDP
        if (remaining_size < sizeof(UdpHeader)) {
            current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
            transition_to(ParseState::PACKET_COMPLETE);
            return true;
        }
        
        const auto* udp_header = mapper_.read_at<UdpHeader>(current_offset_);
        if (!udp_header) {
            current_offset_ = packet_start_offset_ + current_pkt_header_->caplen;
            transition_to(ParseState::PACKET_COMPLETE);
            return true;
        }
        
        current_packet_.has_transport = true;
        current_packet_.src_port = ntohs(udp_header->src_port);
        current_packet_.dest_port = ntohs(udp_header->dest_port);
        
        current_offset_ += sizeof(UdpHeader);
        stats_.udp_packets++;
    }
    
    transition_to(ParseState::EXTRACT_PAYLOAD);
    return true;
}

inline bool FSMPcapParser::handle_payload_state() {
    // Calculate payload size and location
    size_t payload_start = current_offset_;
    size_t payload_end = packet_start_offset_ + current_pkt_header_->caplen;
    
    if (payload_start < payload_end) {
        current_packet_.payload = mapper_.data() + payload_start;
        current_packet_.payload_size = payload_end - payload_start;
    }
    
    current_offset_ = payload_end;
    transition_to(ParseState::PACKET_COMPLETE);
    return true;
}

inline bool FSMPcapParser::handle_packet_complete_state() {
    stats_.total_packets++;
    stats_.total_bytes_processed += current_pkt_header_->caplen;
    
    // Call packet callback
    if (packet_callback_) {
        packet_callback_(current_packet_);
    }
    
    transition_to(ParseState::EXPECT_PACKET_HEADER);
    return true;
}

inline void FSMPcapParser::transition_to(ParseState new_state) {
    current_state_ = new_state;
}

inline void FSMPcapParser::reset_packet_state() {
    current_packet_ = {};
}

// Legacy compatibility methods
inline bool FSMPcapParser::parse_next_packet(PacketInfo& packet_info) {
    // For compatibility, process one complete packet through FSM
    while (current_state_ != ParseState::PACKET_COMPLETE && 
           current_state_ != ParseState::END_OF_FILE &&
           current_state_ != ParseState::ERROR_STATE) {
        
        if (!process_next_state()) {
            return false;
        }
    }
    
    if (current_state_ == ParseState::PACKET_COMPLETE) {
        packet_info = current_packet_;
        return true;
    }
    
    return false;
}

inline void FSMPcapParser::reset() {
    current_state_ = ParseState::EXPECT_PCAP_HEADER;
    current_offset_ = 0;
    header_validated_ = false;
    stats_ = {};
    start_time_ = std::chrono::high_resolution_clock::now();
}

} // namespace pcap
