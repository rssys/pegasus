#include <cinttypes>
#include <cstdio>
#include <ucontext.h>
#include "pegasus/decode.h"

using namespace pegasus;

static xed_uint64_t agen_callback(xed_reg_enum_t reg, void *context, xed_bool_t *error) {
    AddressGenerationContext *ctx = (AddressGenerationContext *)context;
    switch (reg) {
        case XED_REG_RAX:   return ctx->gregs[REG_RAX];
        case XED_REG_RCX:   return ctx->gregs[REG_RCX];
        case XED_REG_RDX:   return ctx->gregs[REG_RDX];
        case XED_REG_RBX:   return ctx->gregs[REG_RBX];
        case XED_REG_RSP:   return ctx->gregs[REG_RSP];
        case XED_REG_RBP:   return ctx->gregs[REG_RBP];
        case XED_REG_RSI:   return ctx->gregs[REG_RSI];
        case XED_REG_RDI:   return ctx->gregs[REG_RDI];
        case XED_REG_R8:    return ctx->gregs[REG_R8];
        case XED_REG_R9:    return ctx->gregs[REG_R9];
        case XED_REG_R10:   return ctx->gregs[REG_R10];
        case XED_REG_R11:   return ctx->gregs[REG_R11];
        case XED_REG_R12:   return ctx->gregs[REG_R12];
        case XED_REG_R13:   return ctx->gregs[REG_R13];
        case XED_REG_R14:   return ctx->gregs[REG_R14];
        case XED_REG_R15:   return ctx->gregs[REG_R15];
        case XED_REG_RIP:   return ctx->gregs[REG_RIP];
        case XED_REG_EAX:   return ctx->gregs[REG_RAX] & 0xfffffffful;
        case XED_REG_ECX:   return ctx->gregs[REG_RCX] & 0xfffffffful;
        case XED_REG_EDX:   return ctx->gregs[REG_RDX] & 0xfffffffful;
        case XED_REG_EBX:   return ctx->gregs[REG_RBX] & 0xfffffffful;
        case XED_REG_ESP:   return ctx->gregs[REG_RSP] & 0xfffffffful;
        case XED_REG_EBP:   return ctx->gregs[REG_RBP] & 0xfffffffful;
        case XED_REG_ESI:   return ctx->gregs[REG_RSI] & 0xfffffffful;
        case XED_REG_EDI:   return ctx->gregs[REG_RDI] & 0xfffffffful;
        case XED_REG_R8D:   return ctx->gregs[REG_R8]  & 0xfffffffful;
        case XED_REG_R9D:   return ctx->gregs[REG_R9]  & 0xfffffffful;
        case XED_REG_R10D:  return ctx->gregs[REG_R10] & 0xfffffffful;
        case XED_REG_R11D:  return ctx->gregs[REG_R11] & 0xfffffffful;
        case XED_REG_R12D:  return ctx->gregs[REG_R12] & 0xfffffffful;
        case XED_REG_R13D:  return ctx->gregs[REG_R13] & 0xfffffffful;
        case XED_REG_R14D:  return ctx->gregs[REG_R14] & 0xfffffffful;
        case XED_REG_R15D:  return ctx->gregs[REG_R15] & 0xfffffffful;
        case XED_REG_EIP:   return ctx->gregs[REG_RIP] & 0xfffffffful;
        case XED_REG_CS:
        case XED_REG_DS:
        case XED_REG_SS:
        case XED_REG_ES:    return 0;
        case XED_REG_FS:    return ctx->fs;
        case XED_REG_GS:    return ctx->gs;
        default:
            *error = 1;
            return 0;
    }
}

void pegasus::init_decoder() {
    xed_tables_init();
    xed_agen_register_callback(agen_callback, agen_callback);
}

bool pegasus::get_xrstor_address(AddressGenerationContext *ctx, const uint8_t *inst_buf, size_t n, uint64_t *addr) {
    xed_decoded_inst_t inst;
    xed_decoded_inst_zero(&inst);
    xed_decoded_inst_set_mode(&inst, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    if (xed_decode(&inst, inst_buf, n) != XED_ERROR_NONE) {
        return false;
    }
    if (xed_decoded_inst_get_iclass(&inst) != XED_ICLASS_XRSTOR ||
        xed_decoded_inst_number_of_memory_operands(&inst) != 1) {
        return false;
    }
    ctx->gregs[REG_RIP] += xed_decoded_inst_get_length(&inst);
    return xed_agen(&inst, 0, ctx, addr) == XED_ERROR_NONE;
}

bool pegasus::get_memory_operands(AddressGenerationContext *ctx, const uint8_t *inst_buf, size_t n,
                                 MemoryOperand *operands, int *num_operands) {
    xed_decoded_inst_t inst;
    xed_decoded_inst_zero(&inst);
    xed_decoded_inst_set_mode(&inst, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    if (xed_decode(&inst, inst_buf, n) != XED_ERROR_NONE) {
        return false;
    }
    int num = xed_decoded_inst_number_of_memory_operands(&inst);
    int num_without_lea = num;
    for (int i = 0, j = 0; i < num; ++i) {
        bool write = xed_decoded_inst_mem_written(&inst, i);
        bool read = xed_decoded_inst_mem_read(&inst, i);
        if (!write && !read) {
            --num_without_lea;
            continue;
        }
        operands[j].read = read;
        operands[j].write = write;
        operands[j].size = xed_decoded_inst_get_memory_operand_length(&inst, i);
        if (xed_agen(&inst, i, ctx, &operands[j].addr) != XED_ERROR_NONE) {
            return false;
        }
        ++j;
    }
    *num_operands = num_without_lea;
    return true;
}