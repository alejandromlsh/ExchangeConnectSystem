#pragma once

#include "../simba/simba_types.hpp"
#include "../utils/thread_safe_queue.hpp"
#include <fstream>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <sstream>

namespace output {

// Simple JSON writer that works with existing ThreadSafeQueue
class JsonOutputWriter {
private:
    pcap::ThreadSafeQueue<simba::DecodedMessage>& message_queue_;
    std::atomic<bool>& decoding_complete_;
    std::atomic<bool> should_stop_;
    
    std::ofstream output_file_;
    
    // Performance counters
    alignas(64) std::atomic<uint64_t> messages_written_;
    alignas(64) std::atomic<uint64_t> write_errors_;
    
    bool first_message_;

public:
    explicit JsonOutputWriter(pcap::ThreadSafeQueue<simba::DecodedMessage>& queue,
                             std::atomic<bool>& decoding_complete,
                             const std::string& output_filename)
        : message_queue_(queue), decoding_complete_(decoding_complete),
          should_stop_(false), messages_written_(0), write_errors_(0),
          first_message_(true) {
        
        output_file_.open(output_filename, std::ios::out | std::ios::trunc);
        if (!output_file_.is_open()) {
            throw std::runtime_error("Failed to open output file: " + output_filename);
        }
        
        // Start JSON array
        output_file_ << "[\n";
    }

    ~JsonOutputWriter() {
        if (output_file_.is_open()) {
            // Close JSON array
            output_file_ << "\n]";
            output_file_.close();
        }
    }

    void stop() noexcept { 
        should_stop_.store(true, std::memory_order_release); 
    }

    void run() noexcept {
        constexpr auto sleep_duration = std::chrono::microseconds(10);
        
        while (!should_stop_.load(std::memory_order_acquire) &&
               (!decoding_complete_.load(std::memory_order_acquire) || 
                !message_queue_.empty())) {
            
            auto msg_opt = message_queue_.try_pop();
            if (msg_opt) [[likely]] {
                serialize_message(*msg_opt);
                messages_written_.fetch_add(1, std::memory_order_relaxed);
            } else [[unlikely]] {
                std::this_thread::sleep_for(sleep_duration);
            }
        }
        
        output_file_.flush();
    }

    [[nodiscard]] uint64_t get_messages_written() const noexcept {
        return messages_written_.load(std::memory_order_relaxed);
    }
    
    [[nodiscard]] uint64_t get_write_errors() const noexcept {
        return write_errors_.load(std::memory_order_relaxed);
    }

private:
    void serialize_message(const simba::DecodedMessage& msg) noexcept {
        try {
            if (!first_message_) {
                output_file_ << ",\n";
            } else {
                first_message_ = false;
            }
            
            output_file_ << "  {\n";
            output_file_ << "    \"timestamp_us\": " << msg.timestamp_us << ",\n";
            output_file_ << "    \"src_ip\": \"" << format_ip(msg.src_ip) << "\",\n";
            output_file_ << "    \"dest_ip\": \"" << format_ip(msg.dest_ip) << "\",\n";
            output_file_ << "    \"src_port\": " << msg.src_port << ",\n";
            output_file_ << "    \"dest_port\": " << msg.dest_port << ",\n";
            output_file_ << "    \"type\": \"" << get_message_type_string(msg.type) << "\"\n";
            output_file_ << "  }";
            
        } catch (...) {
            write_errors_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    
    static std::string format_ip(uint32_t ip) noexcept {
        return std::to_string((ip >> 24) & 0xFF) + "." +
               std::to_string((ip >> 16) & 0xFF) + "." +
               std::to_string((ip >> 8) & 0xFF) + "." +
               std::to_string(ip & 0xFF);
    }
    
    static const char* get_message_type_string(simba::MessageType type) noexcept {
        switch (type) {
            case simba::MessageType::ORDER_UPDATE: return "OrderUpdate";
            case simba::MessageType::ORDER_EXECUTION: return "OrderExecution";
            case simba::MessageType::ORDER_BOOK_SNAPSHOT: return "OrderBookSnapshot";
            default: return "Unknown";
        }
    }
};

} // namespace output
