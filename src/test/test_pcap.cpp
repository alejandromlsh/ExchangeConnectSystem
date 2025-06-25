#include "pcap/pcap_parser.hpp"
#include <iostream>
#include <cassert>

void test_basic_parsing() {
    try {
        pcap::PcapParser parser("2023-10-09.1849-1906.pcap");
        
        size_t packet_count = 0;
        parser.set_packet_callback([&packet_count](const pcap::PacketInfo& packet) {
            packet_count++;
            
            // Basic validation
            assert(packet.timestamp_us > 0);
            assert(packet.captured_length > 0);
            assert(packet.packet_length > 0);
            
            std::cout << "Packet " << packet_count << ": " 
                      << packet.captured_length << " bytes" << std::endl;
        });
        
        bool success = parser.parse_all();
        assert(success);
        
        const auto& stats = parser.get_stats();
        std::cout << "Test passed! Parsed " << stats.total_packets << " packets" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        exit(1);
    }
}

int main() {
    test_basic_parsing();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
