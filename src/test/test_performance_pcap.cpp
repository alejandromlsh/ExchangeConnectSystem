#include "pcap/pcap_parser.hpp"
#include "pcap/pcap_parser_fsm.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

void print_statistics(const std::string& method_name, const pcap::ParseStats& stats, double duration_ms) {
    std::cout << "\n=== " << method_name << " PARSING STATISTICS ===" << std::endl;
    std::cout << "Total packets: " << stats.total_packets << std::endl;
    std::cout << "Ethernet packets: " << stats.ethernet_packets << std::endl;
    std::cout << "IP packets: " << stats.ip_packets << std::endl;
    std::cout << "TCP packets: " << stats.tcp_packets << std::endl;
    std::cout << "UDP packets: " << stats.udp_packets << std::endl;
    std::cout << "Other packets: " << stats.other_packets << std::endl;
    std::cout << "Parse errors: " << stats.parse_errors << std::endl;
    std::cout << "Total bytes processed: " << stats.total_bytes_processed << std::endl;
    std::cout << "Parse time: " << duration_ms << " ms" << std::endl;
    std::cout << "Processing rate: " << std::scientific << std::setprecision(5) 
              << (stats.total_packets / duration_ms * 1000.0) << " packets/sec" << std::endl;
    std::cout << "Throughput: " << std::fixed << std::setprecision(2)
              << (stats.total_bytes_processed / duration_ms / 1000.0) << " MB/sec" << std::endl;
}

void test_original_parser(const std::string& pcap_file) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "TESTING ORIGINAL PROCEDURAL PARSER" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    try {
        pcap::PcapParser parser(pcap_file);
        size_t packet_count = 0;
        
        // Set up callback to count packets
        parser.set_packet_callback([&packet_count](const pcap::PacketInfo& packet) {
            packet_count++;
            
            // Progress indicator for large files
            if (packet_count % 500000 == 0) {
                std::cout << "Original parser processed " << packet_count << " packets..." << std::endl;
            }
        });
        
        // Measure parsing time
        auto start_time = std::chrono::high_resolution_clock::now();
        bool success = parser.parse_all();
        auto end_time = std::chrono::high_resolution_clock::now();
        
        if (!success) {
            std::cerr << "Original parser failed to parse PCAP file" << std::endl;
            return;
        }
        
        auto duration = std::chrono::duration<double, std::milli>(end_time - start_time);
        const auto& stats = parser.get_stats();
        
        print_statistics("ORIGINAL PROCEDURAL", stats, duration.count());
        
    } catch (const std::exception& e) {
        std::cerr << "Original parser error: " << e.what() << std::endl;
    }
}

void test_fsm_parser(const std::string& pcap_file) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "TESTING FSM-BASED PARSER" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    try {
        pcap::FSMPcapParser fsm_parser(pcap_file);
        size_t packet_count = 0;
        
        // Set up callback to count packets
        fsm_parser.set_packet_callback([&packet_count](const pcap::PacketInfo& packet) {
            packet_count++;
            
            // Progress indicator for large files
            if (packet_count % 500000 == 0) {
                std::cout << "FSM parser processed " << packet_count << " packets..." << std::endl;
            }
        });
        
        // Measure parsing time
        auto start_time = std::chrono::high_resolution_clock::now();
        bool success = fsm_parser.parse_all_with_fsm();
        auto end_time = std::chrono::high_resolution_clock::now();
        
        if (!success) {
            std::cerr << "FSM parser failed to parse PCAP file" << std::endl;
            return;
        }
        
        auto duration = std::chrono::duration<double, std::milli>(end_time - start_time);
        const auto& stats = fsm_parser.get_stats();
        
        print_statistics("FSM-BASED", stats, duration.count());
        
    } catch (const std::exception& e) {
        std::cerr << "FSM parser error: " << e.what() << std::endl;
    }
}

void compare_results(const std::string& pcap_file) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "PERFORMANCE COMPARISON SUMMARY" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    // Quick comparison run for summary
    try {
        // Test original parser
        pcap::PcapParser original_parser(pcap_file);
        size_t original_packets = 0;
        original_parser.set_packet_callback([&original_packets](const pcap::PacketInfo&) {
            original_packets++;
        });
        
        auto start1 = std::chrono::high_resolution_clock::now();
        bool success1 = original_parser.parse_all();
        auto end1 = std::chrono::high_resolution_clock::now();
        auto duration1 = std::chrono::duration<double, std::milli>(end1 - start1);
        
        // Test FSM parser
        pcap::FSMPcapParser fsm_parser(pcap_file);
        size_t fsm_packets = 0;
        fsm_parser.set_packet_callback([&fsm_packets](const pcap::PacketInfo&) {
            fsm_packets++;
        });
        
        auto start2 = std::chrono::high_resolution_clock::now();
        bool success2 = fsm_parser.parse_all_with_fsm();
        auto end2 = std::chrono::high_resolution_clock::now();
        auto duration2 = std::chrono::duration<double, std::milli>(end2 - start2);
        
        if (success1 && success2) {
            double original_rate = original_packets / duration1.count() * 1000.0;
            double fsm_rate = fsm_packets / duration2.count() * 1000.0;
            double improvement = ((fsm_rate - original_rate) / original_rate) * 100.0;
            
            std::cout << "Original Parser Rate: " << std::scientific << std::setprecision(5) 
                      << original_rate << " packets/sec" << std::endl;
            std::cout << "FSM Parser Rate:      " << std::scientific << std::setprecision(5) 
                      << fsm_rate << " packets/sec" << std::endl;
            std::cout << "Performance Change:   " << std::fixed << std::setprecision(2) 
                      << improvement << "%" << std::endl;
            
            if (improvement > 1.0) {
                std::cout << "✓ FSM parser is FASTER" << std::endl;
            } else if (improvement < -1.0) {
                std::cout << "✗ FSM parser is SLOWER" << std::endl;
            } else {
                std::cout << "≈ Performance is EQUIVALENT" << std::endl;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Comparison error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        std::cerr << "Example: " << argv[0] << " 2023-10-09.1849-1906.pcap\n";
        return 1;
    }
    
    std::string pcap_file = argv[1];
    
    std::cout << "PCAP PARSER PERFORMANCE COMPARISON" << std::endl;
    std::cout << "File: " << pcap_file << std::endl;
    std::cout << "Comparing: Original Procedural vs FSM-Based Parsing" << std::endl;
    
    // Test both parsers
    test_original_parser(pcap_file);
    test_fsm_parser(pcap_file);
    
    // Show comparison summary
    compare_results(pcap_file);
    
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "PERFORMANCE TESTING COMPLETE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    return 0;
}
