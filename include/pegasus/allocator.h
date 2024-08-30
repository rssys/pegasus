#pragma once
#include <vector>
#include <functional>
#include "lock.h"

namespace pegasus {
class SlabAllocator {
public:
    SlabAllocator(size_t object_size_, size_t num_objects_per_block_);
    ~SlabAllocator();
    void *allocate();
    void deallocate(void *ptr);
    void reset();
    std::function<void *(size_t)> page_allocator;
    std::function<void (void *, size_t)> page_deallocator;
private:
    static constexpr size_t MaskSize = 13;
    struct Block {
        uint8_t *start;
        uint8_t *end;
        uint16_t size;
        uint64_t mask[MaskSize];
    };
    static_assert(sizeof(Block) == 128, "");
    void *allocate_from_block(Block &block);

    size_t object_size;
    size_t num_objects_per_block;
    SpinLock mutex;
    std::vector<Block> blocks;
};
}