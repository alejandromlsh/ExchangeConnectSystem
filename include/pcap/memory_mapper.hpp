#pragma once
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>
#include <cerrno>

namespace pcap {

class MemoryMapper {
private:
    int fd_;
    void* mapped_data_;
    size_t file_size_;
    std::string filename_;

public:
    explicit MemoryMapper(const std::string& filename);
    ~MemoryMapper();
    
    // Non-copyable, movable
    MemoryMapper(const MemoryMapper&) = delete;
    MemoryMapper& operator=(const MemoryMapper&) = delete;
    MemoryMapper(MemoryMapper&& other) noexcept;
    MemoryMapper& operator=(MemoryMapper&& other) noexcept;
    
    // Zero-copy access methods
    const uint8_t* data() const noexcept { return static_cast<const uint8_t*>(mapped_data_); }
    size_t size() const noexcept { return file_size_; }
    bool is_valid() const noexcept { return mapped_data_ != nullptr && mapped_data_ != MAP_FAILED; }
    
    // Performance optimization hints
    void advise_sequential() const noexcept;
    void advise_random() const noexcept;
    void prefetch(size_t offset, size_t length) const noexcept;
    
    // Template for zero-copy struct access
    template<typename T>
    const T* read_at(size_t offset) const noexcept {
        if (offset + sizeof(T) > file_size_) {
            return nullptr;
        }
        return reinterpret_cast<const T*>(static_cast<const uint8_t*>(mapped_data_) + offset);
    }
};

// Implementation
inline MemoryMapper::MemoryMapper(const std::string& filename) 
    : fd_(-1), mapped_data_(nullptr), file_size_(0), filename_(filename) {
    
    // Open file with read-only access
    fd_ = open(filename.c_str(), O_RDONLY);
    if (fd_ == -1) {
        throw std::runtime_error("Failed to open file: " + filename + " - " + std::string(strerror(errno)));
    }
    
    // Get file size
    struct stat sb;
    if (fstat(fd_, &sb) == -1) {
        close(fd_);
        throw std::runtime_error("Failed to get file size: " + filename);
    }
    
    file_size_ = sb.st_size;
    
    // Memory map the entire file
    mapped_data_ = mmap(nullptr, file_size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (mapped_data_ == MAP_FAILED) {
        close(fd_);
        throw std::runtime_error("Failed to memory map file: " + filename);
    }
    
    // Optimize for sequential access by default
    advise_sequential();
}

inline MemoryMapper::~MemoryMapper() {
    if (mapped_data_ != nullptr && mapped_data_ != MAP_FAILED) {
        munmap(mapped_data_, file_size_);
    }
    if (fd_ != -1) {
        close(fd_);
    }
}

inline MemoryMapper::MemoryMapper(MemoryMapper&& other) noexcept 
    : fd_(other.fd_), mapped_data_(other.mapped_data_), 
      file_size_(other.file_size_), filename_(std::move(other.filename_)) {
    other.fd_ = -1;
    other.mapped_data_ = nullptr;
    other.file_size_ = 0;
}

inline void MemoryMapper::advise_sequential() const noexcept {
    if (is_valid()) {
        madvise(mapped_data_, file_size_, MADV_SEQUENTIAL);
    }
}

inline void MemoryMapper::advise_random() const noexcept {
    if (is_valid()) {
        madvise(mapped_data_, file_size_, MADV_RANDOM);
    }
}

inline void MemoryMapper::prefetch(size_t offset, size_t length) const noexcept {
    if (is_valid() && offset < file_size_) {
        size_t actual_length = std::min(length, file_size_ - offset);
        madvise(static_cast<uint8_t*>(mapped_data_) + offset, actual_length, MADV_WILLNEED);
    }
}

} // namespace pcap
