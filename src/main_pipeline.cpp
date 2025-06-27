#include "pcap/pcap_parser.hpp"
#include "utils/ring_buffer.hpp"
#include "simba/simba_decoder.hpp"
#include "json/json_output_writer.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <array>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <output_json>\n";
        std::cerr << "Example: " << argv[0] << " ../pcap_files/2023-10-10.0845-0905.pcap output.json\n";
        return 1;
    }

    try {
        // FIXED: Use correct namespace and type names
        auto packet_queue = std::make_unique<pcap::HFTRingBuffer<pcap::PacketInfo, 1048576>>();
        auto order_update_queue = std::make_unique<pcap::HFTRingBuffer<simba::OrderUpdate, 262144>>();
        auto order_execution_queue = std::make_unique<pcap::HFTRingBuffer<simba::OrderExecution, 262144>>();
        auto snapshot_queue = std::make_unique<pcap::HFTRingBuffer<simba::OrderBookSnapshot, 65536>>();

        pcap::PcapParser parser(argv[1]);
        std::atomic<bool> parsing_complete{false};
        std::atomic<bool> decoding_complete{false};
        std::atomic<size_t> dropped_packets{0};

        // NEW: Batching variables for packet processing
        std::array<pcap::PacketInfo, 32> packet_batch;
        size_t batch_count = 0;
        std::atomic<size_t> total_batches_processed{0};

        // Create components with heap-allocated ring buffers
        simba::SimbaDecoder decoder(*packet_queue, *order_update_queue,
                                   *order_execution_queue, *snapshot_queue, parsing_complete);
        output::JsonOutputWriter json_writer(*order_update_queue, *order_execution_queue,
                                           *snapshot_queue, decoding_complete, argv[2]);

        // UPDATED: Batched packet callback with optimized ring buffer operations
        parser.set_packet_callback([&](const pcap::PacketInfo& packet) {
            packet_batch[batch_count++] = packet;
            
            // Process batch when full
            if (batch_count == 32) {
                size_t pushed = packet_queue->try_push_batch(packet_batch.data(), batch_count);
                dropped_packets.fetch_add(batch_count - pushed, std::memory_order_relaxed);
                total_batches_processed.fetch_add(1, std::memory_order_relaxed);
                batch_count = 0;
            }
        });

        // THREAD 2: SIMBA Decoder (Queue 1 → Queue 2a/2b/2c)
        std::thread decoder_thread([&decoder, &decoding_complete]() {
            std::cout << "SIMBA decoder thread started..." << std::endl;
            decoder.run();
            decoding_complete.store(true, std::memory_order_release);
            std::cout << "SIMBA decoder thread finished." << std::endl;
        });

        // THREAD 3: JSON Writer (Queue 2a/2b/2c → File)
        std::thread json_writer_thread([&json_writer]() {
            std::cout << "JSON writer thread started..." << std::endl;
            json_writer.run();
            std::cout << "JSON writer thread finished." << std::endl;
        });

        // Start complete pipeline timing
        std::cout << "Starting optimized lock-free 3-thread PCAP→SIMBA→JSON pipeline..." << std::endl;
        auto pipeline_start_time = std::chrono::high_resolution_clock::now();

        // Start parsing (Thread 1 - main thread)
        auto parsing_start_time = std::chrono::high_resolution_clock::now();
        bool success = parser.parse_all();
        
        // NEW: Handle remaining packets in batch after parsing completes
        if (batch_count > 0) {
            size_t pushed = packet_queue->try_push_batch(packet_batch.data(), batch_count);
            dropped_packets.fetch_add(batch_count - pushed, std::memory_order_relaxed);
            total_batches_processed.fetch_add(1, std::memory_order_relaxed);
        }
        
        parsing_complete.store(true, std::memory_order_release);
        auto parsing_end_time = std::chrono::high_resolution_clock::now();

        // Wait for complete pipeline to finish
        decoder_thread.join();
        json_writer_thread.join();

        // Complete pipeline timing
        auto pipeline_end_time = std::chrono::high_resolution_clock::now();

        if (success) {
            // Calculate all timing metrics
            auto parsing_duration = std::chrono::duration<double, std::milli>(parsing_end_time - parsing_start_time);
            auto pipeline_duration = std::chrono::duration<double, std::milli>(pipeline_end_time - pipeline_start_time);
            auto decoding_duration = std::chrono::duration<double, std::milli>(pipeline_end_time - parsing_end_time);

            const auto& stats = parser.get_stats();

            std::cout << "\n=== OPTIMIZED LOCK-FREE PIPELINE PERFORMANCE STATISTICS ===" << std::endl;
            std::cout << "Total packets: " << stats.total_packets << std::endl;
            std::cout << "Processed packets: " << decoder.get_processed_packets() << std::endl;
            std::cout << "Decoded messages: " << decoder.get_decoded_messages() << std::endl;
            std::cout << "JSON messages written: " << json_writer.get_messages_written() << std::endl;
            std::cout << "Decode errors: " << decoder.get_decode_errors() << std::endl;
            std::cout << "JSON write errors: " << json_writer.get_write_errors() << std::endl;
            std::cout << "Dropped packets (backpressure): " << dropped_packets.load() << std::endl;

            // NEW: Batch processing statistics
            std::cout << "Total batches processed: " << total_batches_processed.load() << std::endl;
            if (total_batches_processed.load() > 0) {
                std::cout << "Average batch utilization: " << 
                    (static_cast<double>(stats.total_packets) / (total_batches_processed.load() * 32.0) * 100.0) << "%" << std::endl;
            }

            std::cout << "\n=== TIMING BREAKDOWN ===" << std::endl;
            std::cout << "Parsing time: " << parsing_duration.count() << " ms" << std::endl;
            std::cout << "Decoding + JSON writing time: " << decoding_duration.count() << " ms" << std::endl;
            std::cout << "Total pipeline time: " << pipeline_duration.count() << " ms" << std::endl;

            std::cout << "\n=== THROUGHPUT METRICS ===" << std::endl;
            std::cout << "Parsing throughput: " << (stats.total_packets / parsing_duration.count() * 1000.0)
                      << " packets/sec" << std::endl;
            std::cout << "Complete pipeline throughput: " << (stats.total_packets / pipeline_duration.count() * 1000.0)
                      << " packets/sec" << std::endl;
            std::cout << "End-to-end decoding rate: " << (decoder.get_decoded_messages() / pipeline_duration.count() * 1000.0)
                      << " messages/sec" << std::endl;
            std::cout << "JSON writing rate: " << (json_writer.get_messages_written() / pipeline_duration.count() * 1000.0)
                      << " messages/sec" << std::endl;

            // NEW: Batch processing performance metrics
            if (total_batches_processed.load() > 0) {
                std::cout << "Batch processing rate: " << (total_batches_processed.load() / parsing_duration.count() * 1000.0)
                          << " batches/sec" << std::endl;
                std::cout << "Average packets per batch: " << (static_cast<double>(stats.total_packets) / total_batches_processed.load())
                          << std::endl;
            }

            std::cout << "\n=== EFFICIENCY METRICS ===" << std::endl;
            double decode_success_rate = (double)decoder.get_decoded_messages() / (double)decoder.get_processed_packets() * 100.0;
            double pipeline_efficiency = parsing_duration.count() / pipeline_duration.count() * 100.0;
            double drop_rate = (double)dropped_packets.load() / (double)stats.total_packets * 100.0;
            
            std::cout << "Decode success rate: " << decode_success_rate << "%" << std::endl;
            std::cout << "Pipeline efficiency: " << pipeline_efficiency << "% (parsing vs total time)" << std::endl;
            std::cout << "Packet drop rate: " << drop_rate << "%" << std::endl;

            // NEW: Performance improvement indicators
            std::cout << "\n=== OPTIMIZATION IMPACT ===" << std::endl;
            std::cout << "Atomic operations reduced by batching: ~" << (31.0 / 32.0 * 100.0) << "%" << std::endl;
            if (drop_rate < 0.1) {
                std::cout << "Queue backpressure: EXCELLENT (< 0.1% drops)" << std::endl;
            } else if (drop_rate < 1.0) {
                std::cout << "Queue backpressure: GOOD (< 1% drops)" << std::endl;
            } else {
                std::cout << "Queue backpressure: NEEDS TUNING (" << drop_rate << "% drops)" << std::endl;
            }

        } else {
            std::cerr << "Parsing failed!" << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
