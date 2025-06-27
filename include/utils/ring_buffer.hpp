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
    // Non-blocking push - returns false if full (HFT prefers dropping to blocking)
    [[nodiscard]] bool try_push(T&& item) noexcept {
        const size_t head = head_.load(std::memory_order_relaxed);
        const size_t next_head = (head + 1) & mask_;
        
        if (next_head == tail_.load(std::memory_order_acquire)) [[unlikely]] {
            return false; // Queue full - don't block in HFT
        }
        
        buffer_[head] = std::move(item);
        head_.store(next_head, std::memory_order_release);
        return true;
    }
    
    // Overload for copy semantics
    [[nodiscard]] bool try_push(const T& item) noexcept {
        const size_t head = head_.load(std::memory_order_relaxed);
        const size_t next_head = (head + 1) & mask_;
        
        if (next_head == tail_.load(std::memory_order_acquire)) [[unlikely]] {
            return false;
        }
        
        buffer_[head] = item;
        head_.store(next_head, std::memory_order_release);
        return true;
    }
    
    // Non-blocking pop - returns false if empty
    [[nodiscard]] bool try_pop(T& item) noexcept {
        const size_t tail = tail_.load(std::memory_order_relaxed);
        
        if (tail == head_.load(std::memory_order_acquire)) [[unlikely]] {
            return false; // Queue empty
        }
        
        item = std::move(buffer_[tail]);
        tail_.store((tail + 1) & mask_, std::memory_order_release);
        return true;
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
