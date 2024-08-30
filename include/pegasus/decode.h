#pragma once
#include <cstddef>
#include <cinttypes>

extern "C" {
#include "xed/xed-interface.h"
}

#include "types.h"

namespace pegasus {
void init_decoder();
struct AddressGenerationContext {
    uintptr_t *gregs;
    uintptr_t fs;
    uintptr_t gs;
};

struct MemoryOperand {
    uint64_t addr;
    size_t size;
    bool read;
    bool write;
};

bool get_xrstor_address(AddressGenerationContext *ctx, const uint8_t *inst_buf, size_t n, uint64_t *addr);
bool get_memory_operands(AddressGenerationContext *ctx, const uint8_t *inst_buf, size_t n,
                         MemoryOperand *operands, int *num_operands);
}