#include "pcap/pcap_parser.hpp"
#include "utils/thread_safe_queue.hpp"
#include "simba/simba_decoder.hpp"
#include "json/json_output_writer.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <set>

bool is_simba_port(uint16_t port) {
    return port >= 20080 && port <= 20090;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input.pcap> <output.json>\n";
        return 1;
    }

    try {
        // Create thread-safe queues for the pipeline
        pcap::ThreadSafeQueue<pcap::PacketInfo> packet_queue;
        pcap::ThreadSafeQueue<simba::DecodedMessage> decoded_queue;
        
        pcap::PcapParser parser(argv[1]);
        std::atomic<bool> parsing_complete{false};
        std::atomic<bool> decoding_complete{false};
        
        size_t processed_count = 0;
        size_t simba_candidates = 0;

        // Create components with clear separation of concerns
        simba::SimbaDecoder decoder(packet_queue, decoded_queue, parsing_complete);
        output::JsonOutputWriter json_writer(decoded_queue, decoding_complete, argv[2]);

        // SIMBA decoder thread
        std::thread decoder_thread([&decoder, &decoding_complete]() {
            std::cout << "SIMBA decoder thread started..." << std::endl;
            decoder.run();
            decoding_complete.store(true, std::memory_order_release);
            std::cout << "SIMBA decoder thread finished." << std::endl;
        });

        // JSON writer thread
        std::thread json_writer_thread([&json_writer]() {
            std::cout << "JSON writer thread started..." << std::endl;
            json_writer.run();
            std::cout << "JSON writer thread finished." << std::endl;
        });

        // Packet analysis thread
        std::thread analysis_thread([&]() {
            std::cout << "Analysis thread started..." << std::endl;
            std::set<uint16_t> seen_ports;
            
            while (!parsing_complete.load(std::memory_order_acquire) || 
                   !packet_queue.empty()) {
                auto packet_opt = packet_queue.try_pop();
                if (packet_opt) {
                    const auto& packet = *packet_opt;
                    processed_count++;

                    if (packet.has_transport && !packet.is_tcp && packet.payload_size > 0) {
                        if (seen_ports.insert(packet.dest_port).second && seen_ports.size() <= 20) {
                            std::cout << "Found UDP port: " << packet.dest_port
                                     << " (payload size: " << packet.payload_size << ")" << std::endl;
                        }

                        if (is_simba_port(packet.dest_port)) {
                            simba_candidates++;
                        }
                    }
                } else {
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                }
            }
            std::cout << "Analysis thread finished." << std::endl;
        });

        // Set callback to push packets to queue
        parser.set_packet_callback([&packet_queue](const pcap::PacketInfo& packet) {
            packet_queue.push(packet);
        });

        // Parse all packets
        std::cout << "Starting PCAP parsing with SIMBA decoding pipeline..." << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        bool success = parser.parse_all();
        parsing_complete.store(true, std::memory_order_release);
        
        auto end_time = std::chrono::high_resolution_clock::now();

        // Wait for all threads to complete
        analysis_thread.join();
        decoder_thread.join();
        json_writer_thread.join();

        if (success) {
            auto duration = std::chrono::duration<double, std::milli>(end_time - start_time);
            const auto& stats = parser.get_stats();

            std::cout << "\n=== FIXED PCAP + SIMBA PIPELINE STATISTICS ===" << std::endl;
            std::cout << "Total packets: " << stats.total_packets << std::endl;
            std::cout << "Processed: " << processed_count << std::endl;
            std::cout << "SIMBA candidates: " << simba_candidates << std::endl;
            std::cout << "Decoded messages: " << decoder.get_decoded_messages() << std::endl;
            std::cout << "JSON messages written: " << json_writer.get_messages_written() << std::endl;
            std::cout << "Decode errors: " << decoder.get_decode_errors() << std::endl;
            std::cout << "JSON write errors: " << json_writer.get_write_errors() << std::endl;
            std::cout << "Parse time: " << duration.count() << " ms" << std::endl;
            std::cout << "Throughput: " << (stats.total_packets / duration.count() * 1000.0) 
                     << " packets/sec" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
