#include <sys/syscall.h>
#include <asm-generic/mman-common.h>

#define PAGE_SIZE 4096
#define offset_pcpupriv_monitor_entry 0
#define offset_pcpupriv_current 8
#define offset_pcpupriv_uswitch_data 16
#define offset_pcpupriv_mode 24
#define offset_pcpupriv_fast_call_rsp 32
#define offset_pcpupriv_fast_call_handler 40
#define offset_pcpupriv_signal_fixup_mask 144
#define offset_pcpupriv_signal_fixup_rsp 152
#define offset_pcpupriv_signal_fixup_rip 160

#define offset_pcpupub_pkru 0
#define offset_pcpupub_syscall_rewrite_rsp 24
#define offset_pcpupub_trace_buffer 48
#define offset_pcpupub_trace_buffer_size 56

#define offset_vthread_saved_state 0

#define offset_uswitch_data_block_signals 40

#define PER_CPU_PUB(name) %gs:(offset_pcpupub_ ## name)
#define PER_CPU_PRIV(name) %gs:(PAGE_SIZE+offset_pcpupriv_ ## name)

#define FromMonitorCall 0
#define FromSignal 1
#define MonitorMode 0
#define SandboxMode 1
#define SyscallMode 2
#define MonitorCallRewriteSyscall 1

#ifdef CONFIG_DISABLE_MPK
#define wrpkru
#endif

.text
pegasus_mpk_violate:
    movl $__NR_exit, %eax
    xorl %edi, %edi
    syscall

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_safe_wrpkru
pegasus_safe_wrpkru:
    movl %edi, %gs:(PAGE_SIZE*2+offset_pcpupub_pkru)
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl %edi, %eax
    wrpkru
    movl PER_CPU_PUB(pkru), %edx
    cmpl %eax, %edx
    jne pegasus_mpk_violate
    movl $1, %eax
    ret

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_gate_resume_sandbox_call
.global pegasus_gate_resume_sandbox_call_race_start
.global pegasus_gate_resume_sandbox_call_race_end
pegasus_gate_resume_sandbox_call:
    leaq .Lpegasus_gate_resume_sandbox_call_resume(%rip), %rax
    vzeroall
    movq %rax, (%rdi)
    movq %rsp, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %rbx, 24(%rdi)
    movq %r12, 32(%rdi)
    movq %r13, 40(%rdi)
    movq %r14, 48(%rdi)
    movq %r15, 56(%rdi)
    rdfsbase %rax
    movq %rax, 64(%rdi)

    movq 96(%rsi), %rax     // fs_base
    wrfsbase %rax
    movq 88(%rsi), %r11     // %rip
    movq 80(%rsi), %rsp     // %rsp
    movq 72(%rsi), %r12     // %rcx
    movq 64(%rsi), %r13     // %rax
    movq 56(%rsi), %r14     // %rdx
    movq 48(%rsi), %rbx     // %rbx
    movq 40(%rsi), %rbp     // %rbp
    movq 32(%rsi), %rcx     // %rsi
    movq 24(%rsi), %rdi     // %rdi
    movq 16(%rsi), %r10     // %r10
    movq  8(%rsi), %r9      // %r9
    movq  0(%rsi), %r8      // %r8

    movq %rcx, %rsi

    xorl %ecx, %ecx
    xorl %edx, %edx
    movl PER_CPU_PUB(pkru), %eax

    // enable signals
    movq PER_CPU_PRIV(uswitch_data), %r15
    movl $0, offset_uswitch_data_block_signals(%r15)
pegasus_gate_resume_sandbox_call_race_start:
    wrpkru
pegasus_gate_resume_sandbox_call_race_end:
    movl PER_CPU_PUB(pkru), %edx
    cmpl %eax, %edx
    jne pegasus_mpk_violate
    movq %r12, %rcx
    movq %r13, %rax
    movq %r14, %rdx
    jmpq *%r11

.Lpegasus_gate_resume_sandbox_call_resume:
    ret

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_gate_monitor_call
.global pegasus_gate_monitor_call_race_start
.global pegasus_gate_monitor_call_race_end
.global pegasus_gate_monitor_call_race_restart
pegasus_gate_monitor_call:
    movq %rax, %r12
    movq %rcx, %r13
    movq %rdx, %r14
pegasus_gate_monitor_call_race_restart:
    xorl %eax, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru

pegasus_gate_monitor_call_race_start:
    testl %eax, %eax
    jnz pegasus_mpk_violate

    // disable signals
    movq PER_CPU_PRIV(uswitch_data), %rax
    movl $1, offset_uswitch_data_block_signals(%rax)
pegasus_gate_monitor_call_race_end:

    movq PER_CPU_PRIV(monitor_entry), %rdx
    movq PER_CPU_PRIV(current), %rcx
#if offset_vthread_saved_state != 0
    leaq offset_vthread_saved_state(%rcx), %rcx
#endif

    // save registers
    leaq .Lpegasus_gate_monitor_call_resume(%rip), %rax
    movq %rax, 88(%rcx)     // %rip
    rdfsbase %rax
    movq %rax, 96(%rcx)     // fs_base
    movq %rsp, 80(%rcx)     // %rsp
    movq %r13, 72(%rcx)     // %rcx
    movq %r12, 64(%rcx)     // %rax
    movq %r14, 56(%rcx)     // %rdx
    movq %rbx, 48(%rcx)     // %rbx
    movq %rbp, 40(%rcx)     // %rbp
    movq %rsi, 32(%rcx)     // %rsi
    movq %rdi, 24(%rcx)     // %rdi
    movq %r10, 16(%rcx)     // %r10
    movq %r9,   8(%rcx)     // %r9
    movq %r8,   0(%rcx)     // %r8

    movq 64(%rdx), %rax
    wrfsbase %rax
    movq 56(%rdx), %r15
    movq 48(%rdx), %r14
    movq 40(%rdx), %r13
    movq 32(%rdx), %r12
    movq 24(%rdx), %rbx
    movq 16(%rdx), %rbp
    movq 8(%rdx), %rsp
    movq (%rdx), %r10
    movl $FromMonitorCall, %eax
    jmp *%r10

.Lpegasus_gate_monitor_call_resume:
    movq (%rsp), %r11
    cmpq $0x65, %r11
    je pegasus_mpk_violate
    ret
    
.section pegasus_trusted_code,"ax",@progbits
.global pegasus_gate_resume_syscall
.global pegasus_gate_resume_syscall_race_point
pegasus_gate_resume_syscall:
    leaq .Lpegasus_gate_resume_syscall_resume(%rip), %rax
    movq %rax, (%rdi)
    movq %rsp, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %rbx, 24(%rdi)
    movq %r12, 32(%rdi)
    movq %r13, 40(%rdi)
    movq %r14, 48(%rdi)
    movq %r15, 56(%rdi)
    rdfsbase %rax
    movq %rax, 64(%rdi)

    movq 64(%rsi), %r13     // %rax
    movq 56(%rsi), %r14     // %rdx
    movq 24(%rsi), %rdi     // %rdi
    movq 16(%rsi), %r10     // %r10
    movq  8(%rsi), %r9      // %r9
    movq  0(%rsi), %r8      // %r8
    movq 32(%rsi), %rsi     // %rsi

    xorl %ecx, %ecx
    xorl %edx, %edx
    movl PER_CPU_PUB(pkru), %eax

    // enable signals
    movq PER_CPU_PRIV(uswitch_data), %r15
    movl $0, offset_uswitch_data_block_signals(%r15)
    wrpkru
    movl PER_CPU_PUB(pkru), %edx
    cmpl %eax, %edx
    jne pegasus_mpk_violate
    movq %r13, %rax
    movq %r14, %rdx
    syscall
// %rip < race_point: -ERESTART
// %rip == race_point: %rax
// %rip > race_point: %r12
pegasus_gate_resume_syscall_race_point:
    movq %rax, %r12
    xorl %eax, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru
    testl %eax, %eax
    jnz pegasus_mpk_violate

    // disable signals
    movq PER_CPU_PRIV(uswitch_data), %rax
    movl $1, offset_uswitch_data_block_signals(%rax)

    movq PER_CPU_PRIV(monitor_entry), %rdx
    movq PER_CPU_PRIV(current), %rcx
#if offset_vthread_saved_state != 0
    leaq offset_vthread_saved_state(%rcx), %rcx
#endif
    movq %r12, 64(%rcx) // %rax

    movq 56(%rdx), %r15
    movq 48(%rdx), %r14
    movq 40(%rdx), %r13
    movq 32(%rdx), %r12
    movq 24(%rdx), %rbx
    movq 16(%rdx), %rbp
    movq 8(%rdx), %rsp
    movl $FromMonitorCall, %eax
.Lpegasus_gate_resume_syscall_resume:
    ret

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_signal_trampoline
pegasus_signal_trampoline:
    rdgsbase %r8
    movq %rdx, %rbx
    testq %r8, %r8
    jz .Lpegasus_signal_trampoline_priv
    movl $0, (PAGE_SIZE*2+offset_pcpupub_pkru)(%r8)
    xorl %ecx, %ecx
    xorl %edx, %edx
    xorl %eax, %eax
    wrpkru
    movl PER_CPU_PUB(pkru), %edx
    cmpl %eax, %edx
    jne pegasus_mpk_violate
    movl PER_CPU_PRIV(mode), %eax
    testl %eax, %eax
    jz .Lpegasus_signal_trampoline_priv
    
    movq PER_CPU_PRIV(monitor_entry), %r8
    movq PER_CPU_PRIV(current), %r9
#if offset_vthread_saved_state != 0
    leaq offset_vthread_saved_state(%r9), %r9
#endif
    movl %edi, 104(%r9)
    movq %rsi, 112(%r9)
    movq %rsp, 120(%r9)
    rdfsbase %rax
    movq %rax, 96(%r9)
    movq 64(%r8), %rax
    wrfsbase %rax
    movq 56(%r8), %r15
    movq 48(%r8), %r14
    movq 40(%r8), %r13
    movq 32(%r8), %r12
    movq 24(%r8), %rbx
    movq 16(%r8), %rbp
    movq 8(%r8), %rsp
    movq (%r8), %r10
    movl $FromSignal, %eax
    jmp *%r10

.Lpegasus_signal_trampoline_priv:
    movq %rbx, %rdx
    movq %rsp, %rcx
    jmp pegasus_handle_monitor_signal

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_gate_syscall_rewrite
.global pegasus_gate_syscall_rewrite_restart
pegasus_gate_syscall_rewrite_restart:
    movq %rsp, %r11
    movq PER_CPU_PUB(syscall_rewrite_rsp), %rsp
    pushfq
    pushq $1
    jmp .Lpegasus_gate_syscall_rewrite_1;
pegasus_gate_syscall_rewrite:
    movq %rsp, %r11
    movq PER_CPU_PUB(syscall_rewrite_rsp), %rsp
    pushfq
    pushq $0
.Lpegasus_gate_syscall_rewrite_1:
    pushq %r11
    pushq %rcx
    pushq %rax
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8

    // saved context
    movq %rsp, %rbp

    addq $-3072, %rsp
    andq $-64, %rsp
    xorl %edx, %edx
    movl $0x2ff, %eax
    movq %rdx, 0x200(%rsp)
    movq %rdx, 0x208(%rsp)
    movq %rdx, 0x210(%rsp)
    movq %rdx, 0x218(%rsp)
    movq %rdx, 0x220(%rsp)
    movq %rdx, 0x228(%rsp)
    movq %rdx, 0x230(%rsp)
    movq %rdx, 0x238(%rsp)
    xsave (%rsp)

    // saved fpstate
    movq %rsp, %rbx

    movl $MonitorCallRewriteSyscall, %eax
    call pegasus_gate_monitor_call
    xorl %edx, %edx
    movl $0xff, %eax
    xrstor (%rsp)
    cmpl $0xff, %eax
    jne pegasus_mpk_violate
    movq %rbp, %rsp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rax
    addq $16, %rsp
    popq %rcx
    popfq
    movq -24(%rsp), %rsp
    jmpq *%rcx

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_gate_syscall_rewrite_nofpu
.global pegasus_gate_syscall_rewrite_nofpu_restart
pegasus_gate_syscall_rewrite_nofpu_restart:
    movq %rsp, %r11
    movq PER_CPU_PUB(syscall_rewrite_rsp), %rsp
    pushfq
    pushq $1
    jmp .Lpegasus_gate_syscall_rewrite_nofpu_1;
pegasus_gate_syscall_rewrite_nofpu:
    movq %rsp, %r11
    movq PER_CPU_PUB(syscall_rewrite_rsp), %rsp
    pushfq
    pushq $0
.Lpegasus_gate_syscall_rewrite_nofpu_1:
    pushq %r11
    pushq %rcx
    pushq %rax
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8

    // saved context
    movq %rsp, %rbp
    addq $-128, %rsp
    andq $-64, %rsp
    movdqa %xmm0, (%rsp)
    movdqa %xmm1, 16(%rsp)
    movdqa %xmm2, 32(%rsp)
    movdqa %xmm3, 48(%rsp)
    movdqa %xmm4, 64(%rsp)
    movdqa %xmm5, 80(%rsp)
    movdqa %xmm6, 96(%rsp)
    movdqa %xmm7, 112(%rsp)
    xorl %ebx, %ebx

    movl $MonitorCallRewriteSyscall, %eax
    call pegasus_gate_monitor_call
    movdqa (%rsp), %xmm0
    movdqa 16(%rsp), %xmm1
    movdqa 32(%rsp), %xmm2
    movdqa 48(%rsp), %xmm3
    movdqa 64(%rsp), %xmm4
    movdqa 80(%rsp), %xmm5
    movdqa 96(%rsp), %xmm6
    movdqa 112(%rsp), %xmm7
    movq %rbp, %rsp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rax
    addq $16, %rsp
    popq %rcx
    popfq
    movq -24(%rsp), %rsp
    jmpq *%rcx


.section pegasus_trusted_code,"ax",@progbits
.global pegasus_gate_fast_call
.global pegasus_gate_fast_call_race1_start
.global pegasus_gate_fast_call_race1_end
.global pegasus_gate_fast_call_race2_start
.global pegasus_gate_fast_call_race2_end
pegasus_gate_fast_call:
    xorl %eax, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru
pegasus_gate_fast_call_race1_start:
    movq PER_CPU_PRIV(uswitch_data), %rbx
    movl $1, offset_uswitch_data_block_signals(%rbx)
pegasus_gate_fast_call_race1_end:
    movq %rsp, %rbp
    movq PER_CPU_PRIV(fast_call_rsp), %rsp
    callq *PER_CPU_PRIV(fast_call_handler)
    movq %rbp, %rsp
    movq %rax, %r8

    xorl %ecx, %ecx
    xorl %edx, %edx
    movl PER_CPU_PUB(pkru), %eax

    movl $0, offset_uswitch_data_block_signals(%rbx)
pegasus_gate_fast_call_race2_start:
    wrpkru
pegasus_gate_fast_call_race2_end:
    movl PER_CPU_PUB(pkru), %edx
    cmpl %eax, %edx
    jne pegasus_mpk_violate
    movq %r8, %rax
    ret

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_ld_so_safe_xrstor
pegasus_ld_so_safe_xrstor:
    movl $0xee, %eax
    xorl %edx, %edx
    xrstor 0x48(%rsp)
    cmpl $0xee, %eax
    jne pegasus_mpk_violate
    ret

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_sig_restorer
pegasus_sig_restorer:
    movl $__NR_rt_sigreturn, %eax
    syscall

.section pegasus_trusted_code,"ax",@progbits
.global pegasus_vsig_restorer
pegasus_vsig_restorer:
    xorl %eax, %eax
    movl $__NR_rt_sigreturn, %ecx
    jmp pegasus_gate_monitor_call

.text
.global pegasus_gate_resume_signal
pegasus_gate_resume_signal:
    leaq .Lpegasus_gate_resume_signal_resume(%rip), %rax
    vzeroall
    movq %rax, (%rdi)
    movq %rsp, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %rbx, 24(%rdi)
    movq %r12, 32(%rdi)
    movq %r13, 40(%rdi)
    movq %r14, 48(%rdi)
    movq %r15, 56(%rdi)
    rdfsbase %rax
    movq %rax, 64(%rdi)
    wrfsbase %rdx
    movq %rsi, %rsp
    movl $__NR_rt_sigreturn, %eax
    syscall
.Lpegasus_gate_resume_signal_resume:
    ret

.text
.global pegasus_memcpy_catch_fault
pegasus_memcpy_catch_fault:
    leaq .Lpegasus_memcpy_catch_fault_fault(%rip), %rax
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rbx
    pushq %rbp
    movl $0x800, PER_CPU_PRIV(signal_fixup_mask)
    movq %rax, PER_CPU_PRIV(signal_fixup_rip)
    movq %rsp, PER_CPU_PRIV(signal_fixup_rsp)
    call memcpy
    movl $0, PER_CPU_PRIV(signal_fixup_mask)
    popq %rbp
    popq %rbx
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    xorl %eax, %eax
    ret
.Lpegasus_memcpy_catch_fault_fault:
    movl $0, PER_CPU_PRIV(signal_fixup_mask)
    popq %rbp
    popq %rbx
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    movl $1, %eax
    ret

.text
.global pegasus_fill_epvent_catch_fault
pegasus_fill_epvent_catch_fault:
    leaq .Lpegasus_fill_epvent_catch_fault_fault(%rip), %rax
    movl $0x800, PER_CPU_PRIV(signal_fixup_mask)
    movq %rax, PER_CPU_PRIV(signal_fixup_rip)
    movq %rsp, PER_CPU_PRIV(signal_fixup_rsp)
    movl %esi, (%rdi)
    movq %rdx, 4(%rdi)
    movl $0, PER_CPU_PRIV(signal_fixup_mask)
    xorl %eax, %eax
    ret
.Lpegasus_fill_epvent_catch_fault_fault:
    movl $1, %eax
    ret

.text
.global pegasus_gate_trace_time
pegasus_gate_trace_time:
    movq PER_CPU_PUB(trace_buffer), %rsi
    movl $16, %ecx
    lock xaddq %rcx, (%rsi)
    cmpq PER_CPU_PUB(trace_buffer_size), %rcx
    jge .Lpegasus_gate_trace_time_out
    movq %rdi, (%rsi,%rcx,1)
    rdtsc
    movl %eax, 8(%rsi,%rcx,1)
    movl %edx, 12(%rsi,%rcx,1)
.Lpegasus_gate_trace_time_out:
    ret