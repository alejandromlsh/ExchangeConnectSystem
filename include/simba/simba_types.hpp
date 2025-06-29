#pragma once

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace simba {









////////// Sets
// MsgFlagsSet - exactly 16 bits (2 bytes)
struct MsgFlagsSet {
    uint16_t LastFragment : 1;        // Bit 0
    uint16_t StartOfSnapshot : 1;     // Bit 1  
    uint16_t EndOfSnapshot : 1;       // Bit 2
    uint16_t IncrementalPacket : 1;   // Bit 3
    uint16_t PossDupFlag : 1;         // Bit 4
    uint16_t reserved : 11;           // Bits 5-15 (unused)
} __attribute__((packed));

// MDFlagsSet - exactly 64 bits (8 bytes)  
struct MDFlagsSet {
    uint64_t Day : 1;                    // Bit 0
    uint64_t IOC : 1;                    // Bit 1
    uint64_t NonQuote : 1;               // Bit 2
    uint64_t reserved1 : 9;              // Bits 3-11 (unused)
    uint64_t EndOfTransaction : 1;       // Bit 12
    uint64_t DueToCrossCancel : 1;       // Bit 13
    uint64_t SecondLeg : 1;              // Bit 14
    uint64_t reserved2 : 4;              // Bits 15-18 (unused)
    uint64_t FOK : 1;                    // Bit 19
    uint64_t Replace : 1;                // Bit 20
    uint64_t Cancel : 1;                 // Bit 21
    uint64_t MassCancel : 1;             // Bit 22
    uint64_t reserved3 : 3;              // Bits 23-25 (unused)
    uint64_t Negotiated : 1;             // Bit 26
    uint64_t MultiLeg : 1;               // Bit 27
    uint64_t reserved4 : 1;              // Bit 28 (unused)
    uint64_t CrossTrade : 1;             // Bit 29
    uint64_t reserved5 : 1;              // Bit 30 (unused)
    uint64_t NegotiatedMatchByRef : 1;   // Bit 31
    uint64_t COD : 1;                    // Bit 32
    uint64_t reserved6 : 8;              // Bits 33-40 (unused)
    uint64_t ActiveSide : 1;             // Bit 41
    uint64_t PassiveSide : 1;            // Bit 42
    uint64_t reserved7 : 2;              // Bits 43-44 (unused)
    uint64_t Synthetic : 1;              // Bit 45
    uint64_t RFS : 1;                    // Bit 46
    uint64_t reserved8 : 10;             // Bits 47-56 (unused)
    uint64_t SyntheticPassive : 1;       // Bit 57
    uint64_t reserved9 : 2;              // Bits 58-59 (unused)
    uint64_t BOC : 1;                    // Bit 60
    uint64_t reserved10 : 1;             // Bit 61 (unused)
    uint64_t DuringDiscreteAuction : 1;  // Bit 62
    uint64_t reserved11 : 1;             // Bit 63 (unused)
} __attribute__((packed));

struct MDFlags2Set {
    uint64_t Zero : 1;                // Bit 0 (value 0) - only defined flag
    uint64_t reserved : 63;           // 63 bits unused
} __attribute__((packed));

// FlagsSet - exactly 64 bits (8 bytes) for SIMBA messages
struct FlagsSet {
    uint64_t reserved1 : 4;              // Bits 0-3 (unused)
    uint64_t AnonymousTrading : 1;       // Bit 4 (value 4)
    uint64_t PrivateTrading : 1;         // Bit 5 (value 5)
    uint64_t reserved2 : 2;              // Bits 6-7 (unused)
    uint64_t MultiLeg : 1;               // Bit 8 (value 8)
    uint64_t reserved3 : 9;              // Bits 9-17 (unused)
    uint64_t Collateral : 1;             // Bit 18 (value 18)
    uint64_t IntradayExercise : 1;       // Bit 19 (value 19)
    uint64_t reserved4 : 44;             // Bits 20-63 (unused)
} __attribute__((packed));


struct TradePeriodAccessSet {
    uint64_t DaySession : 1;             // Bit 0 (value 0)
    uint64_t EveningSession : 1;         // Bit 1 (value 1)
    uint64_t WeekendSession : 1;         // Bit 2 (value 2)
    uint64_t MorningSession : 1;         // Bit 3 (value 3)
    uint64_t reserved : 60;              // Bits 4-63 (unused)
} __attribute__((packed));

///////// ENUMS

enum class MDUpdateAction : uint8_t {
    New = 0,      // New entry
    Change = 1,   // Change existing entry  
    Delete = 2    // Delete existing entry
};

enum class MDEntryType : char {
    Bid = '0',      //bid
    Offer = '1',   // offer
    EmptyBook = 'J'    // empty book
};




















  // structs composites

// Market Data Packet Header - MOEX specific structure
struct MarketDataPacketHeader {
    uint32_t msg_seq_num;   
    uint16_t msg_size;  
    MsgFlagsSet msg_flags;       
    uint64_t sending_time;     
} __attribute__((packed));

struct IncrementalPacketHeader {
    uint64_t timestamp;      // 8 bytes
    uint32_t packet_flags;   // 4 bytes  
} __attribute__((packed));   // Total: 12 bytes

// SIMBA SBE Message Header - network protocol structure
struct SimbaMessageHeader {
    uint16_t block_length;
    uint16_t template_id;
    uint16_t schema_id;
    uint16_t version;
} __attribute__((packed));


struct GroupSize {
  uint16_t block_length;
  uint8_t num_in_group;
}__attribute__((packed));;

struct GroupSize2 {
  uint16_t block_length;
  uint16_t num_in_group;
}__attribute__((packed));;


struct Decimal5 {
  int64_t mantissa;
  int8_t exponent;
}__attribute__((packed));

struct Decimal5Null {
  int64_t mantissa;
  int8_t exponent;
}__attribute__((packed));

struct Decimal2Null {
  int64_t mantissa;
  int8_t exponent;
}__attribute__((packed));


// TradePeriodAccessSet - exactly 64 bits (8 bytes) for SIMBA messages







/////////// MESAGES
// Separate
struct alignas(64) OrderUpdate {       // this will use 1 cache lines. For the future maybe place together same size fields
    // Not simba protocol but comming from the packets
    // uint64_t timestamp_us; //8 byte
    // uint32_t src_ip;  // 4 byte
    // uint32_t dest_ip;// 4 byte
    // uint16_t src_port;// 2 byte
    // uint16_t dest_port; // 2 byte 
    // uint16_t padding1;  // 2 byte
    

    // SIMBA message fields
    int64_t md_entry_id;     // 8 byte
    Decimal5 md_entry_px;    // this is 9 bytes
    int64_t md_entry_size;   // 8 byte
    MDFlagsSet md_flags;   //8 bytes bitfield
    MDFlags2Set md_flags_2; // 8 byte bitfield
    int32_t security_id;  //4 byte
    uint32_t rpt_seq; // 4 byte

    MDUpdateAction md_update_action;
    MDEntryType md_entry_type;  // 1 byte
    ///49 bytes
    uint8_t padding[64-49];

};

struct alignas(64) OrderExecution {         // this will use 2 cache lines. For the future maybe place together same size fields
    // Common network fields 22 bytes total
    // uint64_t timestamp_us;
    // uint32_t src_ip;
    // uint32_t dest_ip;
    // uint16_t src_port;
    // uint16_t dest_port;
    // uint16_t padding1;
    
    // SIMBA-specific data
    int64_t md_entry_id;     // 8 byte
    Decimal5 md_entry_px;    // this is 9 bytes
    int64_t md_entry_size;   // 8 byte

    Decimal5 last_price; //9 bytes
    int64_t last_quantity; //8 bytes
    int64_t trade_id;       //8bytes

    MDFlagsSet md_flags;    //8 bytes bitfield
    MDFlags2Set md_flags_2; //8 bytes bitfield
    MDUpdateAction md_update_action; // 1 byte enum
    MDEntryType md_entry_type;       // 1byte enum
    uint8_t padding2[128 - 68];
    
};

struct alignas(64) OrderBookSnapshot {
    // Common network fields
    // uint64_t timestamp_us;
    // uint32_t src_ip;
    // uint32_t dest_ip;
    // uint16_t src_port;
    // uint16_t dest_port;
    // uint16_t padding1;
    
    // SIMBA-specific data
    int32_t security_id;                  // 4
    uint32_t last_msg_seq_num_processed;  // 4
    uint32_t rpt_seq;                     // 4
    uint32_t exchange_trade_session_id;   // 4

    GroupSize no_md_entries;              // 3

    static constexpr size_t MAX_ENTRIES = 16;

    struct MDEntry {               // 58 + 6
      int64_t md_entry_id;         // 8 bytes
      uint64_t transact_time;      // 8 bytes

      Decimal5Null md_entry_px;   // 9 bytes
      int64_t md_entry_size;      // 8
      int64_t trade_id;           // 8 bytes

      MDFlagsSet md_flags;         // 8 bytes
      MDFlags2Set md_flags_2;      // 8 bytes
      MDEntryType md_entry_type;   // 1 byte
      uint8_t padding[64-58];
    } __attribute__((packed));

    MDEntry entries[MAX_ENTRIES];        //64*16 = 1024

    // 19 + 1024 = 1043
    // next 64 byte boundary = 1088 bytes
    uint8_t padding[45];




};

} // namespace simba
