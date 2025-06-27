#include "pcap/pcap_parser.hpp"
#include "utils/thread_safe_queue.hpp"
#include "simba/simba_decoder.hpp"
#include "json/json_writer.hpp"

#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <set>
bool is_simba_port(uint16_t port) {
    //return port >= 9000 && port <= 9999;
    return port >= 20080 && port <= 20090;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <output_json_file>\n";
        return 1;
    }

    try {
        // Create thread-safe queues for the pipeline
        pcap::ThreadSafeQueue<pcap::PacketInfo> packet_queue;
        pcap::ThreadSafeQueue<simba::DecodedMessage> message_queue;
        
        pcap::PcapParser parser(argv[1]);
        std::atomic<bool> parsing_complete{false};
        std::atomic<bool> decoding_complete{false};
        
        size_t processed_count = 0;
        size_t simba_candidates = 0;

        // Create SIMBA decoder and JSON serializer
        simba::SimbaDecoder decoder(packet_queue, message_queue, parsing_complete);
        simba::JsonSerializer json_serializer(message_queue, decoding_complete, argv[2]);

        // SIMBA decoder thread
        std::thread decoder_thread([&decoder, &decoding_complete]() {
            std::cout << "SIMBA decoder thread started..." << std::endl;
            decoder.run();
            decoding_complete = true;
            std::cout << "SIMBA decoder thread finished." << std::endl;
        });

        // JSON serializer thread
        std::thread serializer_thread([&json_serializer]() {
            std::cout << "JSON serializer thread started..." << std::endl;
            json_serializer.run();
            std::cout << "JSON serializer thread finished." << std::endl;
        });

        // Consumer thread for packet analysis
        std::thread consumer_thread([&]() {
            std::cout << "Consumer thread started..." << std::endl;
                std::set<uint16_t> seen_ports;
            while (!parsing_complete || !packet_queue.empty()) {
                auto packet_opt = packet_queue.try_pop();
                if (packet_opt) {
                    const auto& packet = *packet_opt;
                    processed_count++;

            // ADD THE DIAGNOSTIC CODE RIGHT HERE - AFTER processed_count++
            if (packet.has_transport && !packet.is_tcp && packet.payload_size > 0) {
                if (seen_ports.insert(packet.dest_port).second && seen_ports.size() <= 20) {
                    std::cout << "Found UDP port: " << packet.dest_port 
                              << " (payload size: " << packet.payload_size << ")" << std::endl;
                }
              }
               
                    
                    if (packet.has_transport && !packet.is_tcp &&
                        packet.payload_size > 0 && is_simba_port(packet.dest_port)) {
                        simba_candidates++;
                    }
                } else {
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
            }
            std::cout << "Consumer thread finished." << std::endl;
        });

        // Set callback to push packets to queue
        parser.set_packet_callback([&packet_queue](const pcap::PacketInfo& packet) {
            packet_queue.push(packet);
        });

        // Parse all packets
        std::cout << "Starting PCAP parsing with SIMBA decoding pipeline..." << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        bool success = parser.parse_all();
        parsing_complete = true;
        
        auto end_time = std::chrono::high_resolution_clock::now();
        
        // Wait for all threads to complete
        consumer_thread.join();
        decoder_thread.join();
        serializer_thread.join();

        if (success) {
            auto duration = std::chrono::duration<double, std::milli>(end_time - start_time);
            const auto& stats = parser.get_stats();

            std::cout << "\n=== PCAP + SIMBA PIPELINE STATISTICS ===" << std::endl;
            std::cout << "Total packets: " << stats.total_packets << std::endl;
            std::cout << "Processed: " << processed_count << std::endl;
            std::cout << "SIMBA candidates: " << simba_candidates << std::endl;
            std::cout << "Decoded messages: " << decoder.get_decoded_messages() << std::endl;
            std::cout << "Parse time: " << duration.count() << " ms" << std::endl;
            std::cout << "Throughput: " << (stats.total_packets / duration.count() * 1000.0) << " packets/sec" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
