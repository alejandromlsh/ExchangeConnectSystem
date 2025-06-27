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
    // FIXED: Updated template parameters to match main_pipeline.cpp
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
    // FIXED: Updated constructor signature to match main_pipeline.cpp
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
    // Fast packet validation and filtering
    [[nodiscard]] bool is_valid_simba_packet(const pcap::PacketInfo& packet) const noexcept {
        return packet.has_transport &&
               !packet.is_tcp &&
               packet.payload_size >= sizeof(SimbaMessageHeader) &&
               packet.dest_port >= 20081 &&
               packet.dest_port <= 20086;
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

    // Zero-copy message decoding with direct type-specific ring buffers
    [[nodiscard]] bool decode_simba_message(const pcap::PacketInfo& packet) noexcept {
        const uint8_t* data = packet.payload;
        const size_t remaining = packet.payload_size;
        
        // Check for Market Data Packet Header first
        if (remaining < sizeof(MarketDataPacketHeader)) [[unlikely]] {
            return false;
        }

        // Skip Market Data Packet Header (16 bytes) - MOEX uses little-endian
        data += sizeof(MarketDataPacketHeader);
        const size_t sbe_remaining = remaining - sizeof(MarketDataPacketHeader);
        
        // Now check for SBE Header
        if (sbe_remaining < sizeof(SimbaMessageHeader)) [[unlikely]] {
            return false;
        }

        // Read SBE header - MOEX uses LITTLE-ENDIAN
        const auto* header = reinterpret_cast<const SimbaMessageHeader*>(data);
        const uint16_t template_id = header->template_id;
        const uint16_t block_length = header->block_length;

        // Skip SBE header
        const uint8_t* payload_data = data + sizeof(SimbaMessageHeader);
        const size_t payload_remaining = sbe_remaining - sizeof(SimbaMessageHeader);
        
        if (payload_remaining < block_length) [[unlikely]] {
            return false;
        }

        // Direct decode to specific types - no union overhead, lock-free push
        switch (template_id) {
            case 3: case 4: case 5: { // OrderUpdate variants
                OrderUpdate msg;
                if (decode_order_update(payload_data, packet, msg)) {
                    if (!order_update_queue_.try_push(std::move(msg))) {
                        // Handle backpressure - message dropped
                        return false;
                    }
                    return true;
                }
                break;
            }

            case 6: { // OrderExecution
                OrderExecution msg;
                if (decode_order_execution(payload_data, packet, msg)) {
                    if (!order_execution_queue_.try_push(std::move(msg))) {
                        return false;
                    }
                    return true;
                }
                break;
            }

            case 7: { // OrderBookSnapshot
                OrderBookSnapshot msg;
                if (decode_order_book_snapshot(payload_data, packet, msg)) {
                    if (!snapshot_queue_.try_push(std::move(msg))) {
                        return false;
                    }
                    return true;
                }
                break;
            }

            case 8: case 9: case 11: case 16: { // Other execution types
                OrderExecution msg;
                if (decode_order_execution(payload_data, packet, msg)) {
                    if (!order_execution_queue_.try_push(std::move(msg))) {
                        return false;
                    }
                    return true;
                }
                break;
            }

            default:
                return false;
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
