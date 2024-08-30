#pragma once
#include <cstddef>
#include <cinttypes>

namespace pegasus {
bool get_fpstate_size(MM *mm, uintptr_t ptr, uint32_t *size, uint64_t *xfeatures);
bool get_fpstate_size(uintptr_t ptr, uint32_t *size, uint64_t *xfeatures, uintptr_t start, uintptr_t end);
bool get_fpstate_size(uintptr_t ptr, uint32_t *size, uint64_t *xfeatures);
bool sanitize_fpstate(uintptr_t ptr, size_t size, uint64_t xcr0, uint32_t mxcsr_mask);
void write_xstate(uintptr_t ptr, int pkru, bool clean_xstate, size_t pkru_offset, uint64_t xcr0);
void reset_mxcsr(uintptr_t ptr);
}