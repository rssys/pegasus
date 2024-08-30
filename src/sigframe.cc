#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cfenv>
//#include <asm/signal.h>
#include <asm/sigcontext.h>
//#include <asm/ucontext.h>
#include <asm/siginfo.h>
#include "pegasus/mm.h"
#include "pegasus/sigframe.h"

using namespace pegasus;

bool pegasus::get_fpstate_size(MM *mm, uintptr_t ptr, uint32_t *size, uint64_t *xfeatures) {
    struct _xstate *xstate = (struct _xstate *)ptr;
    struct _fpstate *fpstate = (struct _fpstate *)ptr;
    uint32_t magic = mm->get_sandbox<uint32_t>(&fpstate->sw_reserved.magic1);
    if (magic != FP_XSTATE_MAGIC1) {
        *size = sizeof(struct _fpstate);
        return false;
    }
    *size = mm->get_sandbox<uint32_t>(&fpstate->sw_reserved.extended_size);
    *xfeatures = mm->get_sandbox<uint64_t>(&xstate->xstate_hdr.xfeatures);
    return true;
}

bool pegasus::get_fpstate_size(uintptr_t ptr, uint32_t *size, uint64_t *xfeatures, uintptr_t start, uintptr_t end) {
    struct _xstate *xstate = (struct _xstate *)ptr;
    struct _fpstate *fpstate = (struct _fpstate *)ptr;
    
    if ((uintptr_t)xstate < start || (uintptr_t)xstate + sizeof(struct _xstate) > end) {
        return false;
    }
    uint32_t magic = fpstate->sw_reserved.magic1;
    if (magic != FP_XSTATE_MAGIC1) {
        *size = sizeof(struct _fpstate);
        return false;
    }
    *size = fpstate->sw_reserved.extended_size;
    *xfeatures = xstate->xstate_hdr.xfeatures;
    return true;
}

bool pegasus::get_fpstate_size(uintptr_t ptr, uint32_t *size, uint64_t *xfeatures) {
    struct _xstate *xstate = (struct _xstate *)ptr;
    struct _fpstate *fpstate = (struct _fpstate *)ptr;
    uint32_t magic = fpstate->sw_reserved.magic1;
    if (magic != FP_XSTATE_MAGIC1) {
        *size = sizeof(struct _fpstate);
        return false;
    }
    *size = fpstate->sw_reserved.extended_size;
    *xfeatures = xstate->xstate_hdr.xfeatures;
    return true;
}

bool pegasus::sanitize_fpstate(uintptr_t ptr, size_t size, uint64_t xcr0, uint32_t mxcsr_mask) {
    struct _xstate *xstate = (struct _xstate *)ptr;
    struct _fpstate *fpstate = (struct _fpstate *)ptr;
    if ((fpstate->mxcsr & mxcsr_mask) != fpstate->mxcsr) {
        return false;
    }
    if (fpstate->sw_reserved.magic1 != FP_XSTATE_MAGIC1) {
        return false;
    }
    uint32_t s = fpstate->sw_reserved.extended_size;
    if (s != size) {
        return false;
    }
    if (fpstate->sw_reserved.xstate_size != size - FP_XSTATE_MAGIC2_SIZE) {
        return false;
    }
    uintptr_t pmagic2 = ptr + s - FP_XSTATE_MAGIC2_SIZE;
    if (*(uint32_t *)pmagic2 != FP_XSTATE_MAGIC2) {
        return false;
    }
    uint64_t xfeatures = xstate->xstate_hdr.xfeatures;
    if (xfeatures & (1lu << 63)) {
        return false;
    }
#ifndef CONFIG_DISABLE_MPK
    if (!(xfeatures & (1lu << 9))) {
        // when PKRU is zero (which is possible in the switch gate),
        // xstate->xstate_hdr.xfeatures's PKRU bit can be cleared
        // so we manually set the bit
        xfeatures |= 1lu << 9;
        xstate->xstate_hdr.xfeatures = xfeatures;
    }
#endif
    if ((xfeatures & xcr0) != xfeatures) {
        return false;
    }
    xfeatures = fpstate->sw_reserved.xfeatures;
#ifndef CONFIG_DISABLE_MPK
    if (!(xfeatures & (1lu << 9))) {
        return false;
    }
#endif
    return true;
}

void pegasus::write_xstate(uintptr_t ptr, int pkru, bool clean_xstate, size_t pkru_offset, uint64_t xcr0) {
    struct _xstate *xstate = (struct _xstate *)ptr;
    if (clean_xstate) {
        memset(xstate, 0, sizeof(struct _xstate));
    }
    asm volatile (
        "stmxcsr %0\n"
        : "=m"(xstate->fpstate.mxcsr)
    );
    xstate->fpstate.sw_reserved.magic1 = FP_XSTATE_MAGIC1;
    xstate->fpstate.sw_reserved.extended_size = pkru_offset + 12;
    xstate->fpstate.sw_reserved.xstate_size = pkru_offset + 12 - FP_XSTATE_MAGIC2_SIZE;
    uintptr_t pmagic2 = ptr + pkru_offset + 12 - FP_XSTATE_MAGIC2_SIZE;
    *(uint32_t *)pmagic2 = FP_XSTATE_MAGIC2;
    if (clean_xstate) {
        uint64_t xfeatures = 0x2ff & xcr0;
        xstate->xstate_hdr.xfeatures = xfeatures;
        xstate->fpstate.sw_reserved.xfeatures = xfeatures;
    } else {
        xstate->fpstate.sw_reserved.xfeatures = xstate->xstate_hdr.xfeatures;
    }
#ifndef CONFIG_DISABLE_MPK
    uintptr_t ppkru = ptr + pkru_offset;
    *(int *)(ppkru) = pkru;
#endif
}

void pegasus::reset_mxcsr(uintptr_t ptr) {
    struct _xstate *xstate = (struct _xstate *)ptr;
    asm volatile (
        "stmxcsr %0\n"
        : "=m"(xstate->fpstate.mxcsr)
    );
}
