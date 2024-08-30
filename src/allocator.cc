#include <map>
#include <thread>
#include <mutex>
#include <functional>
#include <sys/mman.h>
#include "pegasus/allocator.h"
#include "pegasus/mm.h"

using namespace pegasus;

SlabAllocator::SlabAllocator(size_t object_size_, size_t num_objects_per_block_)
    : object_size(object_size_), num_objects_per_block(num_objects_per_block_) {
    size_t max_objects_per_block = MaskSize * 64;
    num_objects_per_block = (num_objects_per_block + 63) / 64 * 64;
    if (num_objects_per_block > max_objects_per_block) {
        num_objects_per_block = max_objects_per_block;
    }
}

SlabAllocator::~SlabAllocator() {
    for (auto &&b : blocks) {
        if (page_deallocator) {
            page_deallocator(b.start, (b.end - b.start) / PAGE_SIZE);
        } else {
            munmap(b.start, b.end - b.start);
        }
    }
}

void *SlabAllocator::allocate() {
    std::unique_lock lock(mutex);
    for (auto &&b : blocks) {
        if (b.size == num_objects_per_block) {
            continue;
        }
        return allocate_from_block(b);
    }

    lock.unlock();
    size_t num_pages = (num_objects_per_block * object_size + PAGE_SIZE - 1) / PAGE_SIZE;
    void *mem;
    if (page_allocator) {
        mem = page_allocator(num_pages); 
    } else {
        mem = mmap(nullptr, num_pages * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    }
    if (mem == MAP_FAILED) {
        return nullptr;
    }
    lock.lock();

    size_t i = blocks.size();
    try {
        blocks.resize(i + 1);
    } catch (std::bad_alloc &e) {
        lock.unlock();
        if (page_deallocator) {
            page_deallocator(mem, num_pages);
        } else {
            munmap(mem, num_pages * PAGE_SIZE);
        }
        return nullptr;
    }
    blocks[i].start = (uint8_t *)mem;
    blocks[i].end = (uint8_t *)mem + num_pages * PAGE_SIZE;
    blocks[i].size = 0;
    return allocate_from_block(blocks[i]);
}

void *SlabAllocator::allocate_from_block(SlabAllocator::Block &block) {
    size_t n = num_objects_per_block / 64;
    for (size_t i = 0; i < n; ++i) {
        if (block.mask[i] == -1ull) {
            continue;
        }
        uint64_t m = block.mask[i];
        for (int j = 0; j < 64; ++j) {
            if (!((m >> j) & 1ull)) {
                block.mask[i] |= 1ull << j;
                ++block.size;
                return block.start + object_size * (i * 64 + j);
            }
        }
    }
    return nullptr;
}

void SlabAllocator::deallocate(void *ptr) {
    std::lock_guard lock(mutex);
    uint8_t *p = (uint8_t *)ptr;
    for (auto &&b : blocks) {
        if (p >= b.start && p <= b.end) {
            size_t i = p - b.start;
            size_t j = i / object_size;
            if (j * object_size != i || j >= num_objects_per_block) {
                return;
            }
            size_t k = j / 64;
            size_t l = j % 64;
            b.mask[k] &= ~(1ull << l);
            --b.size;
            return;
        }
    }
}

void SlabAllocator::reset() {
    std::lock_guard lock(mutex);
    for (auto &&b : blocks) {
        if (page_deallocator) {
            page_deallocator(b.start, (b.end - b.start) / PAGE_SIZE);
        } else {
            munmap(b.start, b.end - b.start);
        }
    }
    blocks.clear();
    page_allocator = nullptr;
    page_deallocator = nullptr;
    
}
