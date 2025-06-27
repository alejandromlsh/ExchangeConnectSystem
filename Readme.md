# First version.

Simply I will create a functional program, later I will increase performance.

One thing to do from the beginning is to use header only library files

I need the **pcap parser**, followed by **simba decoder** to read the payload data of the pcap file.
In particular **OrderUpdate**, **OrderExecution** and **OrderBookSnapshot**.

For the parsing I will start with zero copy memory mapped parsing from the beginning and procedural parsing. 
## Single threded Procedural Zero-Copy PCAP Parser

```
parse_next_packet() → parse_ethernet_packet() → parse_ip_packet() → parse_udp_packet()
```

**./pcap_parser ../pcap_files/2023-10-10.0845-0905.pcap**

This were the stats for processing a full file with it
```
= PARSING STATISTICS ===
Total packets: 1133958
Ethernet packets: 1133958
IP packets: 1133958
TCP packets: 0
UDP packets: 1133958
Other packets: 0
Parse errors: 0
Total bytes processed: 564489517
Parse time: 79.1056 ms
Processing rate: 1.43347e+07 packets/sec
Throughput: 7135.9 MB/sec

```

## Single threaded FSM Zero copy PCAP parser

PCAP PARSER PERFORMANCE COMPARISON
File: ../pcap_files/2023-10-10.0845-0905.pcap
Comparing: Original Procedural vs FSM-Based Parsing

### TESTING ORIGINAL PROCEDURAL PARSER

=== ORIGINAL PROCEDURAL PARSING STATISTICS ===

Total packets: 4294773
Ethernet packets: 4294773
IP packets: 4294773
TCP packets: 0
UDP packets: 4294773
Other packets: 0
Parse errors: 0
Total bytes processed: 1927692452
Parse time: 265.791 ms
Processing rate: 1.61584e+07 packets/sec
Throughput: 7252.65 MB/sec

### TESTING FSM-BASED PARSER


=== FSM-BASED PARSING STATISTICS ===

Total packets: 4294773
Ethernet packets: 4294773
IP packets: 4294773
TCP packets: 0
UDP packets: 4294773
Other packets: 0
Parse errors: 0
Total bytes processed: 1927692452
Parse time: 306.56 ms
Processing rate: 1.40098e+07 packets/sec
Throughput: 6288.24 MB/sec

### PERFORMANCE COMPARISON SUMMARY
Original Parser Rate: 1.75219e+07 packets/sec
FSM Parser Rate:      1.57633e+07 packets/sec
Performance Change:   -10.04%
✗ FSM parser is SLOWER

```
1. Original Parser is Already Highly Optimized

Your procedural parser achieves 16M packets/sec and 7.2GB/sec throughput, which is excellent performance. The bottleneck isn't in the parsing logic but in:

    Memory bandwidth: Reading 1.9GB of data from storage

    Cache efficiency: Your zero-copy memory mapping is already optimal

    Branch prediction: Modern CPUs handle your procedural branches very well

2. FSM Overhead in This Context

The FSM approach adds overhead that doesn't provide benefits for your use case:

    State transition overhead: Each switch statement and state change

    Additional memory accesses: Storing and checking current state

    Function call patterns: FSM state handlers vs. direct function calls

3. PCAP Parsing is Too Simple for FSM Benefits

PCAP parsing is linear and predictable:

    No backtracking or complex decision trees

    Fixed header sizes and straightforward protocol stack

    Your procedural approach already follows the natural packet structure

```
Your current parser achieves 16M packets/sec and 7.2GB/sec throughput, which means you're likely hitting:

    Memory bandwidth limits: Reading 1.9GB of PCAP data from storage

    Sequential I/O constraints: Single-threaded file reading is already near-optimal



## Pipelined FSM Zero copy PCAP parser





Looking at the test task requirements and the search results about multithreading in packet analysis, here's how the architecture should be designed:
Task Relationship Analysis
Sequential vs Parallel Design

The three tasks are logically sequential but can be architecturally parallel:

    Task 1 (PCAP Parser) → Task 2 (SIMBA Decoder) → Task 3 (JSON Output)

However, for production-grade performance, you can implement a pipeline architecture where these tasks run concurrently.
Multithreading Opportunities
1. Producer-Consumer Pipeline

cpp
// Thread 1: PCAP Reading & Parsing
PcapParser → PacketQueue

// Thread 2: SIMBA Protocol Decoding  
PacketQueue → SimbaDecoder → DecodedQueue

// Thread 3: JSON Output Writing
DecodedQueue → JsonWriter

2. Packet-Level Parallelism

Based on the search results showing 10x performance improvement with multithreading:

    Multiple decoder threads processing different packets simultaneously

    Lock-free queues for inter-thread communication

    Thread pool for SIMBA message decoding

3. File-Level Parallelism

For your 7 PCAP files (7.21GB total):

    Parallel file processing using multiple parser instances

    Concurrent JSON output to different files

Recommended Architecture
High-Performance Pipeline Design

cpp
class PipelineProcessor {
private:
    // Thread-safe queues
    LockFreeQueue<RawPacket> raw_packets_;
    LockFreeQueue<DecodedMessage> decoded_messages_;
    
    // Thread pools
    ThreadPool packet_parsers_;
    ThreadPool simba_decoders_;
    ThreadPool json_writers_;
    
public:
    void process_pcap_file(const std::string& filename);
};

Benefits for Your Test Task

    Task 1 Enhancement: Zero-copy parsing with concurrent packet extraction

    Task 2 Optimization: Parallel SIMBA decoding of OrderUpdate, OrderExecution, OrderBookSnapshot

    Task 3 Acceleration: Concurrent JSON serialization and file I/O

Implementation Strategy
Phase 1: Sequential (Current)

Complete each task sequentially to ensure correctness:

cpp
for (auto& packet : packets) {
    auto decoded = simba_decoder.decode(packet);
    json_writer.write(decoded);
}

Phase 2: Pipelined (Performance)

Implement multithreaded pipeline for production performance:

cpp
// Producer thread
while (parser.has_packets()) {
    auto packet = parser.parse_next();
    packet_queue.enqueue(packet);
}

// Consumer threads
while (!packet_queue.empty()) {
    auto packet = packet_queue.dequeue();
    auto decoded = simba_decoder.decode(packet);
    output_queue.enqueue(decoded);
}

Performance Expectations

Based on the search results showing 10x improvement with multithreading:

    Current: ~8M packets/sec (single-threaded)

    Potential: ~80M packets/sec (multi-threaded)

    File processing: All 7 files processed in parallel

Answer to Your Question

Yes, there's significant opportunity for multithreading, especially given:

    Large dataset: 7.21GB across 7 files

    CPU-intensive tasks: Protocol decoding and JSON serialization

    I/O operations: File reading and writing

    Independent processing: Each packet can be decoded independently

The tasks are logically sequential (you need parsed packets before decoding SIMBA), but architecturally parallel (multiple packets can be processed simultaneously through a pipeline).

For the test task demonstration, implement sequentially first for correctness, then add multithreading as a performance optimization to showcase your concurrent programming expertise.












# First fully working pipeline from parsing, to decoding to writing the in the file

Without lock free queue, without unified queue messafe, without memory pool allocation and without disruptor

== COMPLETE PIPELINE PERFORMANCE STATISTICS ===
Total packets: 4294773
Processed packets: 4294773
Decoded messages: 288
JSON messages written: 288
Decode errors: 4294485
JSON write errors: 0

=== TIMING BREAKDOWN ===
Parsing time: 1263.62 ms
Decoding + JSON writing time: 184.03 ms
Total pipeline time: 1447.65 ms

=== THROUGHPUT METRICS ===
Parsing throughput: 3.39879e+06 packets/sec
Complete pipeline throughput: 2.96672e+06 packets/sec
End-to-end decoding rate: 198.943 messages/sec
JSON writing rate: 198.943 messages/sec

=== EFFICIENCY METRICS ===
Decode success rate: 0.00670583%
Pipeline efficiency: 87.2875% (parsing vs total time)

Performance is pretty bad

# Replacing queue with locks with a lock free ring buffer.

=== LOCK-FREE PIPELINE PERFORMANCE STATISTICS ===
Total packets: 4294773
Processed packets: 4283059
Decoded messages: 288
JSON messages written: 288
Decode errors: 4282771
JSON write errors: 0
Dropped packets (backpressure): 11714

=== TIMING BREAKDOWN ===
Parsing time: 595.948 ms
Decoding + JSON writing time: 6.13251 ms
Total pipeline time: 602.081 ms

=== THROUGHPUT METRICS ===
Parsing throughput: 7.20663e+06 packets/sec
Complete pipeline throughput: 7.13321e+06 packets/sec
End-to-end decoding rate: 478.341 messages/sec
JSON writing rate: 478.341 messages/sec

=== EFFICIENCY METRICS ===
Decode success rate: 0.00672417%
Pipeline efficiency: 98.9813% (parsing vs total time)

# After deleting one debug message from the decoder

=== LOCK-FREE PIPELINE PERFORMANCE STATISTICS ===
Total packets: 4294773
Processed packets: 4294773
Decoded messages: 288
JSON messages written: 288
Decode errors: 4294485
JSON write errors: 0
Dropped packets (backpressure): 0

=== TIMING BREAKDOWN ===
Parsing time: 394.292 ms
Decoding + JSON writing time: 0.178934 ms
Total pipeline time: 394.472 ms

=== THROUGHPUT METRICS ===
Parsing throughput: 1.08924e+07 packets/sec
Complete pipeline throughput: 1.08874e+07 packets/sec
End-to-end decoding rate: 730.089 messages/sec
JSON writing rate: 730.089 messages/sec

=== EFFICIENCY METRICS ===
Decode success rate: 0.00670583%
Pipeline efficiency: 99.9543% (parsing vs total time)

# Improving cache efficiency moving from alignas(32) to alignas(64)

(base) alejandro@alejandro-Aura-15-Gen1:~/workspace/eqlivent_task/build$ ./pcap_pipeline ../pcap_files/2023-10-10.0845-0905.pcap example.json
Starting lock-free 3-thread PCAP→SIMBA→JSON pipeline...
SIMBA decoder thread started...JSON writer thread started...

SIMBA decoder thread finished.
JSON writer thread finished.

=== LOCK-FREE PIPELINE PERFORMANCE STATISTICS ===
Total packets: 4294773
Processed packets: 4294773
Decoded messages: 288
JSON messages written: 288
Decode errors: 4294485
JSON write errors: 0
Dropped packets (backpressure): 0

=== TIMING BREAKDOWN ===
Parsing time: 386.522 ms
Decoding + JSON writing time: 0.136261 ms
Total pipeline time: 386.659 ms

=== THROUGHPUT METRICS ===
Parsing throughput: 1.11113e+07 packets/sec
Complete pipeline throughput: 1.11074e+07 packets/sec
End-to-end decoding rate: 744.843 messages/sec
JSON writing rate: 744.843 messages/sec

=== EFFICIENCY METRICS ===
Decode success rate: 0.00670583%
Pipeline efficiency: 99.9645% (parsing vs total time)
(base) alejandro@alejandro-Aura-15-Gen1:~/workspace/eqlivent_task/build$ 

# Changing ntohs calls from system calls to inlining the builtin

I check that each system call is around 50=100CPU cycles (from the function call to the library lookpu). 
Since in each packet Icall 7 calls, and I have around 4 M packet that is around 2 billion cycles.

With the inline optimisation we should move to 1-2CPU cucles per call. So we only have around 45 million cycles.

=== LOCK-FREE PIPELINE PERFORMANCE STATISTICS ===
Total packets: 4294773
Processed packets: 4294773
Decoded messages: 288
JSON messages written: 288
Decode errors: 4294485
JSON write errors: 0
Dropped packets (backpressure): 0

=== TIMING BREAKDOWN ===
Parsing time: 367.313 ms
Decoding + JSON writing time: 0.1364 ms
Total pipeline time: 367.45 ms

=== THROUGHPUT METRICS ===
Parsing throughput: 1.16924e+07 packets/sec
Complete pipeline throughput: 1.1688e+07 packets/sec
End-to-end decoding rate: 783.78 messages/sec
JSON writing rate: 783.78 messages/sec

=== EFFICIENCY METRICS ===
Decode success rate: 0.00670583%
Pipeline efficiency: 99.9626% (parsing vs total time)
