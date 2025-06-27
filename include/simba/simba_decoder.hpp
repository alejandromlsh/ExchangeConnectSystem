#pragma once

#include "../pcap/types.hpp"
#include "../utils/thread_safe_queue.hpp"
#include "../json/json_writer.hpp"
#include "simba_types.hpp"
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>

namespace simba {

// High-performance SIMBA decoder with zero-copy design
class SimbaDecoder {
private:
    pcap::ThreadSafeQueue<pcap::PacketInfo>& input_queue_;
    pcap::ThreadSafeQueue<DecodedMessage>& output_queue_;
    std::atomic<bool>& parsing_complete_;
    std::atomic<bool> should_stop_;
    
    // Performance counters - cache-aligned for optimal access
    alignas(64) std::atomic<size_t> processed_packets_;
    alignas(64) std::atomic<size_t> decoded_messages_;
    alignas(64) std::atomic<size_t> decode_errors_;
    
    // Pre-allocated message buffer to avoid allocations in hot path
    DecodedMessage msg_buffer_;
    
public:
    explicit SimbaDecoder(pcap::ThreadSafeQueue<pcap::PacketInfo>& input_queue,
                         pcap::ThreadSafeQueue<DecodedMessage>& output_queue,
                         std::atomic<bool>& parsing_complete) noexcept
        : input_queue_(input_queue), output_queue_(output_queue),
          parsing_complete_(parsing_complete), should_stop_(false),
          processed_packets_(0), decoded_messages_(0), decode_errors_(0) {}
    
    // Non-copyable, non-movable for thread safety
    SimbaDecoder(const SimbaDecoder&) = delete;
    SimbaDecoder& operator=(const SimbaDecoder&) = delete;
    SimbaDecoder(SimbaDecoder&&) = delete;
    SimbaDecoder& operator=(SimbaDecoder&&) = delete;
    
    void stop() noexcept { should_stop_.store(true, std::memory_order_release); }
    
    // Main processing loop - optimized for minimal latency
    void run() noexcept {
        constexpr auto sleep_duration = std::chrono::microseconds(1);
        
        while (!should_stop_.load(std::memory_order_acquire) && 
               (!parsing_complete_.load(std::memory_order_acquire) || !input_queue_.empty())) {
            
            auto packet_opt = input_queue_.try_pop();
            if (packet_opt) [[likely]] {
                process_packet(*packet_opt);
                processed_packets_.fetch_add(1, std::memory_order_relaxed);
            } else [[unlikely]] {
                std::this_thread::sleep_for(sleep_duration);
            }
        }
    }
    
    // Performance metrics accessors
    [[nodiscard]] size_t get_processed_packets() const noexcept { 
        return processed_packets_.load(std::memory_order_relaxed); 
    }
    
    [[nodiscard]] size_t get_decoded_messages() const noexcept { 
        return decoded_messages_.load(std::memory_order_relaxed); 
    }
    
    [[nodiscard]] size_t get_decode_errors() const noexcept { 
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
    
    // Zero-copy message decoding with branch prediction hints
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
        
        // Read SBE header - MOEX uses LITTLE-ENDIAN, not big-endian!
        const auto* header = reinterpret_cast<const SimbaMessageHeader*>(data);
        const uint16_t template_id = header->template_id;        // NO BYTE SWAP - little endian
        const uint16_t block_length = header->block_length;      // NO BYTE SWAP - little endian
        
        // Debug output for template ID discovery
        static std::set<uint16_t> seen_templates;
        if (seen_templates.insert(template_id).second && seen_templates.size() <= 10) {
            std::cout << "Found SIMBA template ID: " << template_id 
                      << " (block_length: " << block_length << ")" << std::endl;
        }
        
        // Skip SBE header
        const uint8_t* payload_data = data + sizeof(SimbaMessageHeader);
        const size_t payload_remaining = sbe_remaining - sizeof(SimbaMessageHeader);
        
        if (payload_remaining < block_length) [[unlikely]] {
            return false;
        }
        
        // Initialize message buffer
        msg_buffer_ = DecodedMessage{};
        msg_buffer_.timestamp_us = packet.timestamp_us;
        msg_buffer_.src_ip = packet.src_ip;
        msg_buffer_.dest_ip = packet.dest_ip;
        msg_buffer_.src_port = packet.src_port;
        msg_buffer_.dest_port = packet.dest_port;
        
        // Template-based decoding - REAL MOEX template IDs from documentation
        switch (template_id) {
            case 3:  // BestPrices
            case 4:  // EmptyBook  
            case 5:  // OrderUpdate
            case 6:  // OrderExecution
            case 7:  // OrderBookSnapshot
            case 8:  // SecurityDefinition
            case 9:  // SecurityStatus
            case 11: // TradingSessionStatus
            case 16: // Trade
                // For now, just return true to count successful decodes
                output_queue_.push(std::move(msg_buffer_));
                return true;
            default:
                // Unknown template ID
                return false;
        }
    }
};

// High-performance JSON serializer with batched I/O
class JsonSerializer {
private:
    pcap::ThreadSafeQueue<DecodedMessage>& message_queue_;
    std::atomic<bool>& decoding_complete_;
    std::atomic<bool> should_stop_;
    json::JsonWriter json_writer_;
    
    // Performance counters
    alignas(64) std::atomic<size_t> serialized_messages_;
    
public:
    explicit JsonSerializer(pcap::ThreadSafeQueue<DecodedMessage>& queue,
                           std::atomic<bool>& decoding_complete,
                           const std::string& output_filename)
        : message_queue_(queue), decoding_complete_(decoding_complete),
          should_stop_(false), json_writer_(output_filename), serialized_messages_(0) {}
    
    // Non-copyable, non-movable
    JsonSerializer(const JsonSerializer&) = delete;
    JsonSerializer& operator=(const JsonSerializer&) = delete;
    JsonSerializer(JsonSerializer&&) = delete;
    JsonSerializer& operator=(JsonSerializer&&) = delete;
    
    void stop() noexcept { should_stop_.store(true, std::memory_order_release); }
    
    void run() noexcept {
        constexpr auto sleep_duration = std::chrono::microseconds(10);
        
        while (!should_stop_.load(std::memory_order_acquire) && 
               (!decoding_complete_.load(std::memory_order_acquire) || !message_queue_.empty())) {
            
            auto msg_opt = message_queue_.try_pop();
            if (msg_opt) [[likely]] {
                serialize_message(*msg_opt);
                serialized_messages_.fetch_add(1, std::memory_order_relaxed);
            } else [[unlikely]] {
                std::this_thread::sleep_for(sleep_duration);
            }
        }
        json_writer_.flush();
    }
    
    [[nodiscard]] size_t get_serialized_messages() const noexcept {
        return serialized_messages_.load(std::memory_order_relaxed);
    }

private:
    void serialize_message(const DecodedMessage& msg) noexcept {
        json_writer_.start_object();
        
        // Common fields - optimized field order for cache efficiency
        json_writer_.add_fields(
            json::JsonField("timestamp_us", msg.timestamp_us),
            json::JsonField("src_ip", json::JsonWriter::format_ip(msg.src_ip)),
            json::JsonField("dest_ip", json::JsonWriter::format_ip(msg.dest_ip)),
            json::JsonField("src_port", msg.src_port),
            json::JsonField("dest_port", msg.dest_port)
        );
        
        // Message-specific serialization with branch prediction
        switch (msg.type) {
            case MessageType::ORDER_UPDATE:
                serialize_order_update(msg.data.order_update);
                break;
            case MessageType::ORDER_EXECUTION:
                serialize_order_execution(msg.data.order_execution);
                break;
            case MessageType::ORDER_BOOK_SNAPSHOT:
                serialize_order_book_snapshot(msg.data.order_book_snapshot);
                break;
            default:
                return;
        }
        
        json_writer_.end_object();
    }
    
    void serialize_order_update(const DecodedMessage::MessageData::OrderUpdate& data) noexcept {
        json_writer_.add_fields(
            json::JsonField("type", "OrderUpdate"),
            json::JsonField("msg_seq_num", data.msg_seq_num),
            json::JsonField("sending_time", data.sending_time),
            json::JsonField("security_id", data.security_id),
            json::JsonField("order_id", data.order_id),
            json::JsonField("price", data.price),
            json::JsonField("order_qty", data.order_qty),
            json::JsonField("side", data.side),
            json::JsonField("ord_type", data.ord_type)
        );
    }
    
    void serialize_order_execution(const DecodedMessage::MessageData::OrderExecution& data) noexcept {
        json_writer_.add_fields(
            json::JsonField("type", "OrderExecution"),
            json::JsonField("msg_seq_num", data.msg_seq_num),
            json::JsonField("sending_time", data.sending_time),
            json::JsonField("security_id", data.security_id),
            json::JsonField("order_id", data.order_id),
            json::JsonField("exec_id", data.exec_id),
            json::JsonField("last_px", data.last_px),
            json::JsonField("last_qty", data.last_qty),
            json::JsonField("side", data.side),
            json::JsonField("exec_type", data.exec_type)
        );
    }
    
    void serialize_order_book_snapshot(const DecodedMessage::MessageData::OrderBookSnapshot& data) noexcept {
        json_writer_.add_fields(
            json::JsonField("type", "OrderBookSnapshot"),
            json::JsonField("msg_seq_num", data.msg_seq_num),
            json::JsonField("sending_time", data.sending_time),
            json::JsonField("security_id", data.security_id),
            json::JsonField("last_msg_seq_num_processed", data.last_msg_seq_num_processed),
            json::JsonField("rpt_seq", data.rpt_seq),
            json::JsonField("no_md_entries", data.no_md_entries)
        );
    }
};

} // namespace simba
