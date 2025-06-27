#include "pcap/pcap_parser.hpp"
#include "utils/thread_safe_queue.hpp"
#include "simba/simba_decoder.hpp"
#include "json/json_output_writer.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input.pcap> <output.json>\n";
        return 1;
    }

    try {
        // Clean 3-thread pipeline with proper queues matching your decoder
        pcap::ThreadSafeQueue<pcap::PacketInfo> packet_queue;           // Queue 1: Raw packets
        pcap::ThreadSafeQueue<simba::OrderUpdate> order_update_queue;   // Queue 2a: OrderUpdate messages
        pcap::ThreadSafeQueue<simba::OrderExecution> order_execution_queue; // Queue 2b: OrderExecution messages  
        pcap::ThreadSafeQueue<simba::OrderBookSnapshot> snapshot_queue; // Queue 2c: OrderBookSnapshot messages
        
        pcap::PcapParser parser(argv[1]);
        std::atomic<bool> parsing_complete{false};
        std::atomic<bool> decoding_complete{false};

        // Create components matching your actual class constructors
        simba::SimbaDecoder decoder(packet_queue, order_update_queue, 
                                   order_execution_queue, snapshot_queue, parsing_complete);
        output::JsonOutputWriter json_writer(order_update_queue, order_execution_queue, 
                                            snapshot_queue, decoding_complete, argv[2]);

        // THREAD 1: PCAP Parser (runs in main thread)
        // This callback pushes packets to Queue 1
        parser.set_packet_callback([&packet_queue](const pcap::PacketInfo& packet) {
            packet_queue.push(packet);
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

        // Start parsing (Thread 1 - main thread)
        std::cout << "Starting clean 3-thread PCAP→SIMBA→JSON pipeline..." << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        bool success = parser.parse_all();
        parsing_complete.store(true, std::memory_order_release);
        
        auto end_time = std::chrono::high_resolution_clock::now();

        // Wait for pipeline to complete
        decoder_thread.join();
        json_writer_thread.join();

        if (success) {
            auto duration = std::chrono::duration<double, std::milli>(end_time - start_time);
            const auto& stats = parser.get_stats();

            std::cout << "\n=== CLEAN 3-THREAD PIPELINE STATISTICS ===" << std::endl;
            std::cout << "Total packets: " << stats.total_packets << std::endl;
            std::cout << "Processed packets: " << decoder.get_processed_packets() << std::endl;
            std::cout << "Decoded messages: " << decoder.get_decoded_messages() << std::endl;
            std::cout << "JSON messages written: " << json_writer.get_messages_written() << std::endl;
            std::cout << "Decode errors: " << decoder.get_decode_errors() << std::endl;
            std::cout << "JSON write errors: " << json_writer.get_write_errors() << std::endl;
            std::cout << "Parse time: " << duration.count() << " ms" << std::endl;
            std::cout << "Throughput: " << (stats.total_packets / duration.count() * 1000.0) 
                     << " packets/sec" << std::endl;
            std::cout << "Decoding rate: " << (decoder.get_decoded_messages() / duration.count() * 1000.0)
                     << " messages/sec" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
