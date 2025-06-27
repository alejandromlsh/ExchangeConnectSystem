#pragma once

#include "../simba/simba_types.hpp"
#include "../utils/ring_buffer.hpp"
#include <fstream>
#include <iostream>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>

namespace output {

// JSON writer that handles all three message types with lock-free ring buffers
class JsonOutputWriter {
private:
    // FIXED: Updated template parameters to match main_pipeline.cpp
    pcap::HFTRingBuffer<simba::OrderUpdate, 262144>& order_update_queue_;
    pcap::HFTRingBuffer<simba::OrderExecution, 262144>& order_execution_queue_;
    pcap::HFTRingBuffer<simba::OrderBookSnapshot, 65536>& snapshot_queue_;
    std::atomic<bool>& decoding_complete_;
    std::atomic<bool> should_stop_;
    std::ofstream output_file_;

    // Performance counters
    alignas(64) std::atomic<uint64_t> messages_written_;
    alignas(64) std::atomic<uint64_t> write_errors_;
    bool first_message_;

public:
    // FIXED: Updated constructor signature to match main_pipeline.cpp
    explicit JsonOutputWriter(pcap::HFTRingBuffer<simba::OrderUpdate, 262144>& order_update_queue,
                             pcap::HFTRingBuffer<simba::OrderExecution, 262144>& order_execution_queue,
                             pcap::HFTRingBuffer<simba::OrderBookSnapshot, 65536>& snapshot_queue,
                             std::atomic<bool>& decoding_complete,
                             const std::string& output_filename)
        : order_update_queue_(order_update_queue),
          order_execution_queue_(order_execution_queue),
          snapshot_queue_(snapshot_queue),
          decoding_complete_(decoding_complete),
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
                !all_queues_empty())) {
            bool processed_any = false;

            // Process OrderUpdate messages with lock-free ring buffer
            simba::OrderUpdate order_update;
            if (order_update_queue_.try_pop(order_update)) {
                serialize_order_update(order_update);
                messages_written_.fetch_add(1, std::memory_order_relaxed);
                processed_any = true;
            }

            // Process OrderExecution messages
            simba::OrderExecution order_execution;
            if (order_execution_queue_.try_pop(order_execution)) {
                serialize_order_execution(order_execution);
                messages_written_.fetch_add(1, std::memory_order_relaxed);
                processed_any = true;
            }

            // Process OrderBookSnapshot messages
            simba::OrderBookSnapshot snapshot;
            if (snapshot_queue_.try_pop(snapshot)) {
                serialize_order_book_snapshot(snapshot);
                messages_written_.fetch_add(1, std::memory_order_relaxed);
                processed_any = true;
            }

            if (!processed_any) {
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
    bool all_queues_empty() const noexcept {
        return order_update_queue_.empty() &&
               order_execution_queue_.empty() &&
               snapshot_queue_.empty();
    }

    void write_message_header() {
        if (!first_message_) {
            output_file_ << ",\n";
        } else {
            first_message_ = false;
        }
    }

    void serialize_order_update(const simba::OrderUpdate& msg) noexcept {
        try {
            write_message_header();
            output_file_ << "  {\n";
            output_file_ << "    \"type\": \"OrderUpdate\",\n";
            output_file_ << "    \"timestamp_us\": " << msg.timestamp_us << ",\n";
            output_file_ << "    \"src_ip\": \"" << format_ip(msg.src_ip) << "\",\n";
            output_file_ << "    \"dest_ip\": \"" << format_ip(msg.dest_ip) << "\",\n";
            output_file_ << "    \"src_port\": " << msg.src_port << ",\n";
            output_file_ << "    \"dest_port\": " << msg.dest_port << ",\n";
            output_file_ << "    \"msg_seq_num\": " << msg.msg_seq_num << ",\n";
            output_file_ << "    \"sending_time\": " << msg.sending_time << ",\n";
            output_file_ << "    \"security_id\": " << msg.security_id << ",\n";
            output_file_ << "    \"order_id\": " << msg.order_id << ",\n";
            output_file_ << "    \"price\": " << msg.price << ",\n";
            output_file_ << "    \"order_qty\": " << msg.order_qty << ",\n";
            output_file_ << "    \"side\": " << static_cast<int>(msg.side) << ",\n";
            output_file_ << "    \"ord_type\": " << static_cast<int>(msg.ord_type) << "\n";
            output_file_ << "  }";
        } catch (...) {
            write_errors_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void serialize_order_execution(const simba::OrderExecution& msg) noexcept {
        try {
            write_message_header();
            output_file_ << "  {\n";
            output_file_ << "    \"type\": \"OrderExecution\",\n";
            output_file_ << "    \"timestamp_us\": " << msg.timestamp_us << ",\n";
            output_file_ << "    \"src_ip\": \"" << format_ip(msg.src_ip) << "\",\n";
            output_file_ << "    \"dest_ip\": \"" << format_ip(msg.dest_ip) << "\",\n";
            output_file_ << "    \"src_port\": " << msg.src_port << ",\n";
            output_file_ << "    \"dest_port\": " << msg.dest_port << ",\n";
            output_file_ << "    \"msg_seq_num\": " << msg.msg_seq_num << ",\n";
            output_file_ << "    \"sending_time\": " << msg.sending_time << ",\n";
            output_file_ << "    \"security_id\": " << msg.security_id << ",\n";
            output_file_ << "    \"order_id\": " << msg.order_id << ",\n";
            output_file_ << "    \"exec_id\": " << msg.exec_id << ",\n";
            output_file_ << "    \"last_px\": " << msg.last_px << ",\n";
            output_file_ << "    \"last_qty\": " << msg.last_qty << ",\n";
            output_file_ << "    \"side\": " << static_cast<int>(msg.side) << ",\n";
            output_file_ << "    \"exec_type\": " << static_cast<int>(msg.exec_type) << "\n";
            output_file_ << "  }";
        } catch (...) {
            write_errors_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void serialize_order_book_snapshot(const simba::OrderBookSnapshot& msg) noexcept {
        try {
            write_message_header();
            output_file_ << "  {\n";
            output_file_ << "    \"type\": \"OrderBookSnapshot\",\n";
            output_file_ << "    \"timestamp_us\": " << msg.timestamp_us << ",\n";
            output_file_ << "    \"src_ip\": \"" << format_ip(msg.src_ip) << "\",\n";
            output_file_ << "    \"dest_ip\": \"" << format_ip(msg.dest_ip) << "\",\n";
            output_file_ << "    \"src_port\": " << msg.src_port << ",\n";
            output_file_ << "    \"dest_port\": " << msg.dest_port << ",\n";
            output_file_ << "    \"msg_seq_num\": " << msg.msg_seq_num << ",\n";
            output_file_ << "    \"sending_time\": " << msg.sending_time << ",\n";
            output_file_ << "    \"security_id\": " << msg.security_id << ",\n";
            output_file_ << "    \"last_msg_seq_num_processed\": " << msg.last_msg_seq_num_processed << ",\n";
            output_file_ << "    \"rpt_seq\": " << msg.rpt_seq << ",\n";
            output_file_ << "    \"no_md_entries\": " << static_cast<int>(msg.no_md_entries) << "\n";
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
};

} // namespace output
