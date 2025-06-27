#include "pcap/pcap_parser.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>


#ifdef DEBUG
void print_packet_info(const pcap::PacketInfo& packet) {
    std::cout << "Packet: " << std::fixed << std::setprecision(6)
              << (packet.timestamp_us / 1000000.0) << "s"
              << " | Length: " << packet.captured_length
              << " | " << packet.src_mac_str() << " -> " << packet.dest_mac_str();
    
    if (packet.has_ip) {
        std::cout << " | " << packet.src_ip_str() << " -> " << packet.dest_ip_str();
        if (packet.has_transport) {
            std::cout << " | " << packet.src_port << " -> " << packet.dest_port;
            if (packet.is_tcp) {
                std::cout << " | TCP seq:" << packet.tcp_seq
                          << " ack:" << packet.tcp_ack
                          << " flags:0x" << std::hex << (int)packet.tcp_flags << std::dec;
            } else {
                std::cout << " | UDP";
            }
        }
        if (packet.payload_size > 0) {
            std::cout << " | Payload: " << packet.payload_size << " bytes";
        }
    }
    std::cout << std::endl;
}
#endif

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        std::cerr << "Example: " << argv[0] << " ../pcap_files/2023-10-10.0845-0905.pcap\n";
        return 1;
    }
    
    try {
#ifdef DEBUG
        std::cout << "Parsing PCAP file: " << argv[1] << std::endl;
#endif
        
        // Create parser with zero-copy memory mapping
        pcap::PcapParser parser(argv[1]);
        
        // Set up packet callback for processing
        size_t packet_count = 0;
        parser.set_packet_callback([&packet_count](const pcap::PacketInfo& packet) {
            packet_count++;
            
#ifdef DEBUG
            // Print first 10 packets in detail
            if (packet_count <= 10) {
                print_packet_info(packet);
            }
            
            // Print progress every 1000 packets
            if (packet_count % 1000 == 0) {
                std::cout << "Processed " << packet_count << " packets..." << std::endl;
            }
#endif
        });
        
        // Parse all packets
        auto start_time = std::chrono::high_resolution_clock::now();
        bool success = parser.parse_all();
        auto end_time = std::chrono::high_resolution_clock::now();
        
        if (!success) {
            std::cerr << "Failed to parse PCAP file" << std::endl;
            return 1;
        }
        
        // Print statistics (ALWAYS printed)
        const auto& stats = parser.get_stats();
        auto duration = std::chrono::duration<double, std::milli>(end_time - start_time);
        
        std::cout << "\n=== PARSING STATISTICS ===" << std::endl;
        std::cout << "Total packets: " << stats.total_packets << std::endl;
        std::cout << "Ethernet packets: " << stats.ethernet_packets << std::endl;
        std::cout << "IP packets: " << stats.ip_packets << std::endl;
        std::cout << "TCP packets: " << stats.tcp_packets << std::endl;
        std::cout << "UDP packets: " << stats.udp_packets << std::endl;
        std::cout << "Other packets: " << stats.other_packets << std::endl;
        std::cout << "Parse errors: " << stats.parse_errors << std::endl;
        std::cout << "Total bytes processed: " << stats.total_bytes_processed << std::endl;
        std::cout << "Parse time: " << duration.count() << " ms" << std::endl;
        std::cout << "Processing rate: " << (stats.total_packets / duration.count() * 1000.0)
                  << " packets/sec" << std::endl;
        std::cout << "Throughput: " << (stats.total_bytes_processed / duration.count() / 1000.0)
                  << " MB/sec" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
