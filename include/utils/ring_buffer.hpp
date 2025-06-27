#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <algorithm>
#include <thread>

namespace pcap {

template<typename T, size_t Size>
class HFTRingBuffer {
private:
    static_assert((Size & (Size - 1)) == 0, "Size must be power of 2");
    static_assert(Size >= 64, "Size too small for HFT");
    
    // Cache-aligned to prevent false sharing between producer and consumer
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    alignas(64) std::array<T, Size> buffer_;
    
    static constexpr size_t mask_ = Size - 1;

public:
    // FIXED: Non-blocking push with compare_exchange to avoid race condition
    [[nodiscard]] bool try_push(T&& item) noexcept {
        size_t head = head_.load(std::memory_order_relaxed);
        
        while (true) {
            const size_t next_head = (head + 1) & mask_;
            
            if (next_head == tail_.load(std::memory_order_acquire)) [[unlikely]] {
                return false; // Queue full
            }
            
            // FIXED: Use compare_exchange to avoid ABA race condition
            if (head_.compare_exchange_weak(head, next_head, 
                                           std::memory_order_release, 
                                           std::memory_order_relaxed)) {
                buffer_[head] = std::move(item);
                return true;
            }
            // head was updated by compare_exchange_weak, retry with new value
        }
    }
    
    // Overload for copy semantics
    [[nodiscard]] bool try_push(const T& item) noexcept {
        size_t head = head_.load(std::memory_order_relaxed);
        
        while (true) {
            const size_t next_head = (head + 1) & mask_;
            
            if (next_head == tail_.load(std::memory_order_acquire)) [[unlikely]] {
                return false;
            }
            
            if (head_.compare_exchange_weak(head, next_head, 
                                           std::memory_order_release, 
                                           std::memory_order_relaxed)) {
                buffer_[head] = item;
                return true;
            }
        }
    }
    
    // FIXED: Non-blocking pop with compare_exchange to avoid race condition
    [[nodiscard]] bool try_pop(T& item) noexcept {
        size_t tail = tail_.load(std::memory_order_relaxed);
        
        while (true) {
            if (tail == head_.load(std::memory_order_acquire)) [[unlikely]] {
                return false; // Queue empty
            }
            
            const size_t next_tail = (tail + 1) & mask_;
            
            if (tail_.compare_exchange_weak(tail, next_tail, 
                                           std::memory_order_release, 
                                           std::memory_order_relaxed)) {
                item = std::move(buffer_[tail]);
                return true;
            }
        }
    }
    
    [[nodiscard]] bool empty() const noexcept {
        return tail_.load(std::memory_order_relaxed) == 
               head_.load(std::memory_order_acquire);
    }
    
    [[nodiscard]] size_t size() const noexcept {
        const size_t head = head_.load(std::memory_order_acquire);
        const size_t tail = tail_.load(std::memory_order_acquire);
        return (head - tail) & mask_;
    }
};

} // namespace pcap
