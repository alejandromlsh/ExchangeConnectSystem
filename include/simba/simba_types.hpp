#pragma once

#include <cstdint>
#include <cstring>
#include <set>

namespace simba {

// SIMBA SBE Message Header - network protocol structure
struct SimbaMessageHeader {
    uint16_t block_length;
    uint16_t template_id;
    uint16_t schema_id;
    uint16_t version;
} __attribute__((packed));

// Market Data Packet Header - MOEX specific structure
struct MarketDataPacketHeader {
    uint32_t msg_seq_num;        // Packet sequence number
    uint64_t sending_time;       // Sending time in nanoseconds
    uint16_t msg_size;           // Message size
    uint16_t msg_flags;          // Message flags
} __attribute__((packed));

// Message type enumeration with explicit values for wire protocol compatibility
enum class MessageType : uint16_t {
    ORDER_UPDATE = 15,
    ORDER_EXECUTION = 16,
    ORDER_BOOK_SNAPSHOT = 17,
    UNKNOWN = 0
};

// Cache-aligned decoded message structure for optimal memory access patterns
struct alignas(64) DecodedMessage {
    MessageType type;
    uint64_t timestamp_us;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    
    // Union for memory efficiency - only one message type active at a time
    union MessageData {
        struct OrderUpdate {
            uint64_t msg_seq_num;
            uint64_t sending_time;
            uint32_t security_id;
            uint64_t order_id;
            uint64_t price;
            uint64_t order_qty;
            uint8_t side;
            uint8_t ord_type;
            uint8_t padding[6]; // Explicit padding for alignment
        } order_update;
        
        struct OrderExecution {
            uint64_t msg_seq_num;
            uint64_t sending_time;
            uint32_t security_id;
            uint64_t order_id;
            uint64_t exec_id;
            uint64_t last_px;
            uint64_t last_qty;
            uint8_t side;
            uint8_t exec_type;
            uint8_t padding[6]; // Explicit padding for alignment
        } order_execution;
        
        struct OrderBookSnapshot {
            uint64_t msg_seq_num;
            uint64_t sending_time;
            uint32_t security_id;
            uint32_t last_msg_seq_num_processed;
            uint32_t rpt_seq;
            uint8_t no_md_entries;
            uint8_t padding[7]; // Explicit padding for alignment
        } order_book_snapshot;
        
        // Constructor for proper initialization
        MessageData() { std::memset(this, 0, sizeof(MessageData)); }
    } data;
    
    // Default constructor with proper initialization
    DecodedMessage() : type(MessageType::UNKNOWN), timestamp_us(0), 
                       src_ip(0), dest_ip(0), src_port(0), dest_port(0), data() {}
};

} // namespace simba
