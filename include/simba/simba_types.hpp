#pragma once

#include <cstdint>
#include <cstring>

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
    uint32_t msg_seq_num;    // Packet sequence number
    uint64_t sending_time;   // Sending time in nanoseconds
    uint16_t msg_size;       // Message size
    uint16_t msg_flags;      // Message flags
} __attribute__((packed));

// Separate optimized message types - no more union waste
struct alignas(64) OrderUpdate {
    // Common network fields
    uint64_t timestamp_us;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t padding1;
    
    // SIMBA-specific data
    uint64_t msg_seq_num;
    uint64_t sending_time;
    uint32_t security_id;
    uint64_t order_id;
    uint64_t price;
    uint64_t order_qty;
    uint8_t side;
    uint8_t ord_type;
    uint8_t padding2[6];
    
    OrderUpdate() : timestamp_us(0), src_ip(0), dest_ip(0), src_port(0), dest_port(0), padding1(0),
                   msg_seq_num(0), sending_time(0), security_id(0), order_id(0), 
                   price(0), order_qty(0), side(0), ord_type(0), padding2{} {}
};

struct alignas(64) OrderExecution {
    // Common network fields
    uint64_t timestamp_us;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t padding1;
    
    // SIMBA-specific data
    uint64_t msg_seq_num;
    uint64_t sending_time;
    uint32_t security_id;
    uint64_t order_id;
    uint64_t exec_id;
    uint64_t last_px;
    uint64_t last_qty;
    uint8_t side;
    uint8_t exec_type;
    uint8_t padding2[6];
    
    OrderExecution() : timestamp_us(0), src_ip(0), dest_ip(0), src_port(0), dest_port(0), padding1(0),
                      msg_seq_num(0), sending_time(0), security_id(0), order_id(0), 
                      exec_id(0), last_px(0), last_qty(0), side(0), exec_type(0), padding2{} {}
};

struct alignas(64) OrderBookSnapshot {
    // Common network fields
    uint64_t timestamp_us;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t padding1;
    
    // SIMBA-specific data
    uint64_t msg_seq_num;
    uint64_t sending_time;
    uint32_t security_id;
    uint32_t last_msg_seq_num_processed;
    uint32_t rpt_seq;
    uint8_t no_md_entries;
    uint8_t padding2[7];
    
    OrderBookSnapshot() : timestamp_us(0), src_ip(0), dest_ip(0), src_port(0), dest_port(0), padding1(0),
                         msg_seq_num(0), sending_time(0), security_id(0), 
                         last_msg_seq_num_processed(0), rpt_seq(0), no_md_entries(0), padding2{} {}
};

} // namespace simba
