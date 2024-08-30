#pragma once
#include "types.h"

namespace pegasus {
extern "C" {
    bool pegasus_safe_wrpkru(uint32_t pkru);
    EnterMonitorType pegasus_gate_resume_sandbox_call(CPUState *from, const VThreadState *to);
    EnterMonitorType pegasus_gate_resume_syscall(CPUState *from, const VThreadState *to);
    EnterMonitorType pegasus_gate_resume_signal(CPUState *from, uintptr_t frame, uintptr_t fs);
    void pegasus_gate_monitor_call(void);
    void pegasus_gate_syscall_rewrite(void);
    void pegasus_gate_syscall_rewrite_restart(void);
    void pegasus_gate_syscall_rewrite_nofpu(void);
    void pegasus_gate_syscall_rewrite_nofpu_restart(void);
    void pegasus_gate_fast_call(void);
    void pegasus_sig_restorer(void);
    void pegasus_vsig_restorer(void);
    void pegasus_ld_so_safe_xrstor(void);
    uintptr_t pegasus_handle_fast_call(uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t);
    void pegasus_gate_trace_time(int tag);
};
}