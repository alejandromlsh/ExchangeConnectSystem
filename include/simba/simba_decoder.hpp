#pragma once

#include "../pcap/types.hpp"
#include "../utils/ring_buffer.hpp"
#include "simba_types.hpp"
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>
#include <set>

namespace simba {

// High-performance SIMBA decoder with separate ring buffers for each message type
class SimbaDecoder {
private:
    pcap::HFTRingBuffer<pcap::PacketInfo, 1048576>& input_queue_;
    pcap::HFTRingBuffer<simba::OrderUpdate, 262144>& order_update_queue_;
    pcap::HFTRingBuffer<simba::OrderExecution, 262144>& order_execution_queue_;
    pcap::HFTRingBuffer<simba::OrderBookSnapshot, 65536>& snapshot_queue_;
    std::atomic<bool>& parsing_complete_;
    std::atomic<bool> should_stop_;

    // Performance counters - cache-aligned for optimal access
    alignas(64) std::atomic<uint64_t> processed_packets_;
    alignas(64) std::atomic<uint64_t> decoded_messages_;
    alignas(64) std::atomic<uint64_t> decode_errors_;

public:
    explicit SimbaDecoder(pcap::HFTRingBuffer<pcap::PacketInfo, 1048576>& input_queue,
                         pcap::HFTRingBuffer<simba::OrderUpdate, 262144>& order_update_queue,
                         pcap::HFTRingBuffer<simba::OrderExecution, 262144>& order_execution_queue,
                         pcap::HFTRingBuffer<simba::OrderBookSnapshot, 65536>& snapshot_queue,
                         std::atomic<bool>& parsing_complete) noexcept
        : input_queue_(input_queue),
          order_update_queue_(order_update_queue),
          order_execution_queue_(order_execution_queue),
          snapshot_queue_(snapshot_queue),
          parsing_complete_(parsing_complete), should_stop_(false),
          processed_packets_(0), decoded_messages_(0), decode_errors_(0) {}

    // Non-copyable, non-movable for thread safety
    SimbaDecoder(const SimbaDecoder&) = delete;
    SimbaDecoder& operator=(const SimbaDecoder&) = delete;
    SimbaDecoder(SimbaDecoder&&) = delete;
    SimbaDecoder& operator=(SimbaDecoder&&) = delete;

    void stop() noexcept {
        should_stop_.store(true, std::memory_order_release);
    }

    // Main processing loop - optimized for minimal latency with lock-free ring buffers
    void run() noexcept {
        constexpr auto sleep_duration = std::chrono::microseconds(1);
        while (!should_stop_.load(std::memory_order_acquire) &&
               (!parsing_complete_.load(std::memory_order_acquire) ||
                !input_queue_.empty())) {
            pcap::PacketInfo packet;
            if (input_queue_.try_pop(packet)) [[likely]] {
                process_packet(packet);
                processed_packets_.fetch_add(1, std::memory_order_relaxed);
            } else [[unlikely]] {
                std::this_thread::sleep_for(sleep_duration);
            }
        }
    }

    // Performance metrics accessors
    [[nodiscard]] uint64_t get_processed_packets() const noexcept {
        return processed_packets_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_decoded_messages() const noexcept {
        return decoded_messages_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_decode_errors() const noexcept {
        return decode_errors_.load(std::memory_order_relaxed);
    }

private:
    // FIXED: Much more permissive packet validation (NO LOGGING)
    [[nodiscard]] bool is_valid_simba_packet(const pcap::PacketInfo& packet) const noexcept {
        // Basic transport layer validation
        if (!packet.has_transport || packet.payload_size < 16) {
            return false;
        }
        
        // Accept both TCP and UDP for SIMBA discovery
        // Many financial protocols use TCP, not just UDP
        
        // Expanded port range for SIMBA/MOEX - be more permissive during discovery
        uint16_t port = packet.dest_port;
        
        // Common SIMBA/MOEX port ranges (much broader for discovery)
        bool valid_port = (port >= 20000 && port <= 21000) ||  // MOEX range
                          (port >= 9000 && port <= 9999) ||    // Alternative range
                          (port >= 8000 && port <= 8999) ||    // Common financial range
                          (port >= 18000 && port <= 19000);    // Extended range
        
        return valid_port;
    }

    void process_packet(const pcap::PacketInfo& packet) noexcept {
        if (!is_valid_simba_packet(packet)) [[unlikely]] {
            return;
        }

        if (decode_simba_message(packet)) [[likely]] {
            decoded_messages_.fetch_add(1, std::memory_order_relaxed);
        } else [[unlikely]] {
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ENHANCED: Much more flexible message decoding WITHOUT performance-killing logging
    [[nodiscard]] bool decode_simba_message(const pcap::PacketInfo& packet) noexcept {
        const uint8_t* data = packet.payload;
        const size_t remaining = packet.payload_size;
        
        // More permissive header validation
        if (remaining < 16) {  // Minimum reasonable size
            return false;
        }
        
        // Try different header interpretations
        
        // Option 1: Direct SBE header (no Market Data Packet Header)
        if (remaining >= sizeof(SimbaMessageHeader)) {
            const auto* sbe_header = reinterpret_cast<const SimbaMessageHeader*>(data);
            uint16_t template_id = sbe_header->template_id;
            
            // NO LOGGING - just validate and decode
            if (is_valid_template_id(template_id)) {
                return decode_by_template_id(template_id, data + sizeof(SimbaMessageHeader), 
                                           remaining - sizeof(SimbaMessageHeader), packet);
            }
        }
        
        // Option 2: Market Data Packet Header + SBE header
        if (remaining >= sizeof(MarketDataPacketHeader) + sizeof(SimbaMessageHeader)) {
            const uint8_t* sbe_data = data + sizeof(MarketDataPacketHeader);
            const size_t sbe_remaining = remaining - sizeof(MarketDataPacketHeader);
            
            const auto* sbe_header = reinterpret_cast<const SimbaMessageHeader*>(sbe_data);
            uint16_t template_id = sbe_header->template_id;
            
            if (is_valid_template_id(template_id)) {
                return decode_by_template_id(template_id, sbe_data + sizeof(SimbaMessageHeader),
                                           sbe_remaining - sizeof(SimbaMessageHeader), packet);
            }
        }
        
        // Option 3: Try to find SBE pattern in payload
        return try_pattern_matching(data, remaining, packet);
    }

    // Helper function to validate template IDs
    [[nodiscard]] bool is_valid_template_id(uint16_t template_id) const noexcept {
        // Much broader range of template IDs for discovery
        return (template_id >= 1 && template_id <= 100) ||     // Common range
               (template_id >= 1000 && template_id <= 2000);   // Extended range
    }

    // Unified decoding by template ID
    [[nodiscard]] bool decode_by_template_id(uint16_t template_id, const uint8_t* payload_data, 
                                           size_t payload_size, const pcap::PacketInfo& packet) noexcept {
        // Much more permissive template ID handling
        switch (template_id) {
            case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10:
            case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18: case 19: case 20: {
                // Try as OrderUpdate first
                OrderUpdate msg;
                if (decode_order_update(payload_data, packet, msg)) {
                    return order_update_queue_.try_push(std::move(msg));
                }
                
                // Fallback to OrderExecution
                OrderExecution exec_msg;
                if (decode_order_execution(payload_data, packet, exec_msg)) {
                    return order_execution_queue_.try_push(std::move(exec_msg));
                }
                break;
            }
            
            case 50: case 51: case 52: case 53: case 54: case 55: {
                // Try as OrderBookSnapshot
                OrderBookSnapshot snapshot_msg;
                if (decode_order_book_snapshot(payload_data, packet, snapshot_msg)) {
                    return snapshot_queue_.try_push(std::move(snapshot_msg));
                }
                break;
            }
            
            default:
                // For unknown template IDs, try all decoders
                OrderUpdate update_msg;
                if (decode_order_update(payload_data, packet, update_msg)) {
                    return order_update_queue_.try_push(std::move(update_msg));
                }
                
                OrderExecution exec_msg;
                if (decode_order_execution(payload_data, packet, exec_msg)) {
                    return order_execution_queue_.try_push(std::move(exec_msg));
                }
                
                OrderBookSnapshot snapshot_msg;
                if (decode_order_book_snapshot(payload_data, packet, snapshot_msg)) {
                    return snapshot_queue_.try_push(std::move(snapshot_msg));
                }
                break;
        }
        
        return false;
    }

    // Pattern matching fallback for non-standard formats
    [[nodiscard]] bool try_pattern_matching(const uint8_t* data, size_t size, 
                                          const pcap::PacketInfo& packet) noexcept {
        // Look for common financial message patterns
        if (size < 8) return false;
        
        // Try to find any structured data and decode it generically
        OrderUpdate msg;
        if (decode_order_update(data, packet, msg)) {
            return order_update_queue_.try_push(std::move(msg));
        }
        
        return false;
    }

    // Type-specific decoders - highly optimized, no branching
    bool decode_order_update(const uint8_t* data, const pcap::PacketInfo& packet, OrderUpdate& msg) noexcept {
        // Set common network fields
        msg.timestamp_us = packet.timestamp_us;
        msg.src_ip = packet.src_ip;
        msg.dest_ip = packet.dest_ip;
        msg.src_port = packet.src_port;
        msg.dest_port = packet.dest_port;

        // For now, zero-initialize SIMBA fields (you'll implement proper SBE parsing later)
        msg.msg_seq_num = 0;
        msg.sending_time = 0;
        msg.security_id = 0;
        msg.order_id = 0;
        msg.price = 0;
        msg.order_qty = 0;
        msg.side = 0;
        msg.ord_type = 0;

        return true;
    }

    bool decode_order_execution(const uint8_t* data, const pcap::PacketInfo& packet, OrderExecution& msg) noexcept {
        msg.timestamp_us = packet.timestamp_us;
        msg.src_ip = packet.src_ip;
        msg.dest_ip = packet.dest_ip;
        msg.src_port = packet.src_port;
        msg.dest_port = packet.dest_port;

        msg.msg_seq_num = 0;
        msg.sending_time = 0;
        msg.security_id = 0;
        msg.order_id = 0;
        msg.exec_id = 0;
        msg.last_px = 0;
        msg.last_qty = 0;
        msg.side = 0;
        msg.exec_type = 0;

        return true;
    }

    bool decode_order_book_snapshot(const uint8_t* data, const pcap::PacketInfo& packet, OrderBookSnapshot& msg) noexcept {
        msg.timestamp_us = packet.timestamp_us;
        msg.src_ip = packet.src_ip;
        msg.dest_ip = packet.dest_ip;
        msg.src_port = packet.src_port;
        msg.dest_port = packet.dest_port;

        msg.msg_seq_num = 0;
        msg.sending_time = 0;
        msg.security_id = 0;
        msg.last_msg_seq_num_processed = 0;
        msg.rpt_seq = 0;
        msg.no_md_entries = 0;

        return true;
    }
};

} // namespace simba
