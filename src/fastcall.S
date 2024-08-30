#define PAGE_SIZE 4096
#define offset_pcpupriv_current_eid 136
#define PER_CPU_PRIV(name) %gs:(PAGE_SIZE+offset_pcpupriv_ ## name)

.extern pegasus_vdso_clock_gettime
.extern pegasus_handle_fast_call_gettimeofday
.extern pegasus_handle_fast_call_time
.extern pegasus_vdso_clock_getres

.global pegasus_handle_fast_call_clock_gettime
pegasus_handle_fast_call_clock_gettime:
    movq %rsi, %rdi
    subq $16, %rsp
    movq %rsp, %rsi
    callq *pegasus_vdso_clock_gettime(%rip)
    movdqa (%rsp), %xmm0
    addq $16, %rsp
    ret

.global pegasus_handle_fast_call_gettimeofday
pegasus_handle_fast_call_gettimeofday:
    subq $16, %rsp
    movq %rsp, %rdi
    subq $8, %rsp
    testq %rsi, %rsi
    jz .Lpegasus_handle_fast_call_gettimeofday_notz
    movq %rsp, %rsi
.Lpegasus_handle_fast_call_gettimeofday_notz:
    callq *pegasus_vdso_gettimeofday(%rip)
    movdqa 8(%rsp), %xmm0
    popq %r9
    addq $16, %rsp
    ret

.global pegasus_handle_fast_call_getcpu
pegasus_handle_fast_call_getcpu:
    movl PER_CPU_PRIV(current_eid), %eax
    ret

.global pegasus_handle_fast_call_time
pegasus_handle_fast_call_time:
    xorl %edi, %edi
    jmpq *pegasus_vdso_time(%rip)

.global pegasus_handle_fast_call_clock_getres
pegasus_handle_fast_call_clock_getres:
    movq %rsi, %rdi
    testq %r8, %r8
    jz .Lpegasus_handle_fast_call_clock_getres_nores
    subq $16, %rsp
    movq %rsp, %rsi
    callq *pegasus_vdso_clock_getres(%rip)
    movdqa (%rsp), %xmm0
    addq $16, %rsp
    ret
.Lpegasus_handle_fast_call_clock_getres_nores:
    xorl %esi, %esi
    jmpq *pegasus_vdso_clock_getres(%rip)

.global pegasus_handle_fast_call
pegasus_handle_fast_call:
    testl %edi, %edi
    jz pegasus_handle_fast_call_clock_gettime
    cmpl $1, %edi
    je pegasus_handle_fast_call_gettimeofday
    cmpl $2, %edi
    je pegasus_handle_fast_call_getcpu
    cmpl $3, %edi
    je pegasus_handle_fast_call_time
    cmpl $4, %edi
    je pegasus_handle_fast_call_clock_getres
    movl $-38, %eax
    ret
