#pragma once

#include <atomic>
#include <array>
#include <memory>
#include <algorithm>
#include <cstddef>

namespace pcap {

template<typename T, size_t Size>
class HFTRingBuffer {
private:
    static_assert((Size & (Size - 1)) == 0, "Size must be power of 2");
    static_assert(Size >= 1024, "Size too small for batching");
    
    static constexpr size_t BATCH_SIZE = 32;  // Optimal for cache lines
    static constexpr size_t mask_ = Size - 1;
    
    // Separate cache lines to prevent false sharing
    alignas(128) std::atomic<size_t> head_{0};
    alignas(128) std::atomic<size_t> tail_{0};
    alignas(64) std::array<T, Size> buffer_;
    
    // Thread-local cached positions to reduce atomic reads
    thread_local static size_t cached_tail_;
    thread_local static size_t cached_head_;
    thread_local static size_t cache_refresh_counter_;
    
public:
    // High-performance single push with reduced atomic operations
    [[nodiscard]] bool try_push(T&& item) noexcept {
        // Refresh cache every 16 operations to balance performance vs accuracy
        if (__builtin_expect((++cache_refresh_counter_ & 15) == 0, 0)) {
            cached_tail_ = tail_.load(std::memory_order_acquire);
        }
        
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t next_head = (current_head + 1) & mask_;
        
        // Fast path: check against cached tail first
        if (__builtin_expect(next_head == cached_tail_, 0)) {
            // Slow path: refresh and double-check
            cached_tail_ = tail_.load(std::memory_order_acquire);
            if (next_head == cached_tail_) {
                return false; // Queue full
            }
        }
        
        // Single atomic operation instead of compare_exchange loop
        if (__builtin_expect(head_.compare_exchange_strong(
            const_cast<size_t&>(current_head), next_head,
            std::memory_order_acq_rel, std::memory_order_relaxed), 1)) {
            
            buffer_[current_head] = std::move(item);
            return true;
        }
        
        return false; // Contention - caller should retry
    }
    
    // Batch push for maximum throughput
    [[nodiscard]] size_t try_push_batch(T* items, size_t count) noexcept {
        if (count == 0) return 0;
        
        const size_t batch_size = std::min(count, BATCH_SIZE);
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_acquire);
        
        // Calculate available space
        const size_t available = (current_tail + Size - current_head - 1) & mask_;
        const size_t to_push = std::min(batch_size, available);
        
        if (to_push == 0) return 0;
        
        // Reserve space with single atomic operation
        const size_t new_head = (current_head + to_push) & mask_;
        if (!head_.compare_exchange_strong(
            const_cast<size_t&>(current_head), new_head,
            std::memory_order_acq_rel, std::memory_order_relaxed)) {
            return 0; // Contention
        }
        
        // Batch copy without atomic operations
        for (size_t i = 0; i < to_push; ++i) {
            buffer_[(current_head + i) & mask_] = std::move(items[i]);
        }
        
        return to_push;
    }
    
    // Optimized pop with similar improvements
    [[nodiscard]] bool try_pop(T& item) noexcept {
        if (__builtin_expect((++cache_refresh_counter_ & 15) == 0, 0)) {
            cached_head_ = head_.load(std::memory_order_acquire);
        }
        
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        
        if (__builtin_expect(current_tail == cached_head_, 0)) {
            cached_head_ = head_.load(std::memory_order_acquire);
            if (current_tail == cached_head_) {
                return false; // Queue empty
            }
        }
        
        const size_t next_tail = (current_tail + 1) & mask_;
        if (__builtin_expect(tail_.compare_exchange_strong(
            const_cast<size_t&>(current_tail), next_tail,
            std::memory_order_acq_rel, std::memory_order_relaxed), 1)) {
            
            item = std::move(buffer_[current_tail]);
            return true;
        }
        
        return false;
    }
    
    // Batch pop for consumer thread
    [[nodiscard]] size_t try_pop_batch(T* items, size_t max_count) noexcept {
        const size_t batch_size = std::min(max_count, BATCH_SIZE);
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);
        
        const size_t available = (current_head - current_tail) & mask_;
        const size_t to_pop = std::min(batch_size, available);
        
        if (to_pop == 0) return 0;
        
        const size_t new_tail = (current_tail + to_pop) & mask_;
        if (!tail_.compare_exchange_strong(
            const_cast<size_t&>(current_tail), new_tail,
            std::memory_order_acq_rel, std::memory_order_relaxed)) {
            return 0;
        }
        
        for (size_t i = 0; i < to_pop; ++i) {
            items[i] = std::move(buffer_[(current_tail + i) & mask_]);
        }
        
        return to_pop;
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

// Thread-local storage definitions
template<typename T, size_t Size>
thread_local size_t HFTRingBuffer<T, Size>::cached_tail_ = 0;

template<typename T, size_t Size>
thread_local size_t HFTRingBuffer<T, Size>::cached_head_ = 0;

template<typename T, size_t Size>
thread_local size_t HFTRingBuffer<T, Size>::cache_refresh_counter_ = 0;

} // namespace pcap
