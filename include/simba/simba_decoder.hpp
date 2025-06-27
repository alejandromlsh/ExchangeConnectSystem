#pragma once

#include "../pcap/types.hpp"
#include "../utils/thread_safe_queue.hpp"
#include "simba_types.hpp"
#include <atomic>
#include <thread>
#include <chrono>
#include <set>
#include <iostream>

namespace simba {

// High-performance SIMBA decoder with separation of concerns
class SimbaDecoder {
private:
    pcap::ThreadSafeQueue<pcap::PacketInfo>& input_queue_;
    pcap::ThreadSafeQueue<DecodedMessage>& output_queue_;
    std::atomic<bool>& parsing_complete_;
    std::atomic<bool> should_stop_;
    
    // Performance counters - cache-aligned for optimal access
    alignas(64) std::atomic<uint64_t> processed_packets_;
    alignas(64) std::atomic<uint64_t> decoded_messages_;
    alignas(64) std::atomic<uint64_t> decode_errors_;
    
    // Pre-allocated message buffer to avoid allocations in hot path
    DecodedMessage msg_buffer_;

public:
    explicit SimbaDecoder(pcap::ThreadSafeQueue<pcap::PacketInfo>& input_queue,
                         pcap::ThreadSafeQueue<DecodedMessage>& output_queue,
                         std::atomic<bool>& parsing_complete) noexcept
        : input_queue_(input_queue), output_queue_(output_queue),
          parsing_complete_(parsing_complete), should_stop_(false),
          processed_packets_(0), decoded_messages_(0), decode_errors_(0) {}

    void stop() noexcept { 
        should_stop_.store(true, std::memory_order_release); 
    }

    void run() noexcept {
        constexpr auto sleep_duration = std::chrono::microseconds(1);
        
        while (!should_stop_.load(std::memory_order_acquire) &&
               (!parsing_complete_.load(std::memory_order_acquire) || 
                !input_queue_.empty())) {
            
            auto packet_opt = input_queue_.try_pop();
            if (packet_opt) [[likely]] {
                process_packet(*packet_opt);
                processed_packets_.fetch_add(1, std::memory_order_relaxed);
            } else [[unlikely]] {
                std::this_thread::sleep_for(sleep_duration);
            }
        }
    }

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

    [[nodiscard]] bool decode_simba_message(const pcap::PacketInfo& packet) noexcept {
        const uint8_t* data = packet.payload;
        const size_t remaining = packet.payload_size;
        
        if (remaining < sizeof(MarketDataPacketHeader)) [[unlikely]] {
            return false;
        }

        data += sizeof(MarketDataPacketHeader);
        const size_t sbe_remaining = remaining - sizeof(MarketDataPacketHeader);
        
        if (sbe_remaining < sizeof(SimbaMessageHeader)) [[unlikely]] {
            return false;
        }

        const auto* header = reinterpret_cast<const SimbaMessageHeader*>(data);
        const uint16_t template_id = header->template_id;
        const uint16_t block_length = header->block_length;

        static std::set<uint16_t> seen_templates;
        if (seen_templates.insert(template_id).second && seen_templates.size() <= 10) {
            std::cout << "Found SIMBA template ID: " << template_id
                     << " (block_length: " << block_length << ")" << std::endl;
        }

        const uint8_t* payload_data = data + sizeof(SimbaMessageHeader);
        const size_t payload_remaining = sbe_remaining - sizeof(SimbaMessageHeader);
        
        if (payload_remaining < block_length) [[unlikely]] {
            return false;
        }

        msg_buffer_ = DecodedMessage{};
        msg_buffer_.timestamp_us = packet.timestamp_us;
        msg_buffer_.src_ip = packet.src_ip;
        msg_buffer_.dest_ip = packet.dest_ip;
        msg_buffer_.src_port = packet.src_port;
        msg_buffer_.dest_port = packet.dest_port;

        switch (template_id) {
            case 3: case 4: case 5:
                msg_buffer_.type = MessageType::ORDER_UPDATE;
                break;
            case 6:
                msg_buffer_.type = MessageType::ORDER_EXECUTION;
                break;
            case 7:
                msg_buffer_.type = MessageType::ORDER_BOOK_SNAPSHOT;
                break;
            case 8: case 9: case 11: case 16:
                msg_buffer_.type = MessageType::ORDER_EXECUTION;
                break;
            default:
                return false;
        }

        output_queue_.push(std::move(msg_buffer_));
        return true;
    }
};

} // namespace simba
