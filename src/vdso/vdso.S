.text
.global clock_gettime
.global __vdso_clock_gettime
clock_gettime:
__vdso_clock_gettime:
    pushq %r12
    pushq %rbx
    pushq %rbp
    movq %rsi, %r12
    movq %rdi, %rsi
    xorl %edi, %edi
    callq *%gs:32
    movdqa %xmm0, (%r12)
    popq %rbp
    popq %rbx
    popq %r12
    ret

.global gettimeofday
.global __vdso_gettimeofday
gettimeofday:
__vdso_gettimeofday:
    pushq %r12
    pushq %r13
    pushq %rbx
    pushq %rbp
    movq %rdi, %r12
    movq %rsi, %r13
    movl $1, %edi
    callq *%gs:32
    movdqa %xmm0, (%r12)
    testq %r13, %r13
    jz .L__vdso_gettimeofday_notz
    movq %r9, (%r13)
.L__vdso_gettimeofday_notz:
    popq %rbp
    popq %rbx
    popq %r13
    popq %r12
    ret

.global getcpu
.global __vdso_getcpu
getcpu:
__vdso_getcpu:
    pushq %rbx
    pushq %rbp
    movl $2, %edi
    callq *%gs:32
    popq %rbp
    popq %rbx
    ret

.global time
.global __vdso_time
time:
__vdso_time:
    pushq %r12
    pushq %rbx
    pushq %rbp
    movq %rdi, %r12
    movl $3, %edi
    callq *%gs:32
    testq %r12, %r12
    jz .L__vdso_time_notloc
    movq %rax, (%r12)
.L__vdso_time_notloc:
    popq %rbp
    popq %rbx
    popq %r12
    ret

.global clock_getres
.global __vdso_clock_getres
clock_getres:
__vdso_clock_getres:
    pushq %r12
    pushq %rbx
    pushq %rbp
    movq %rsi, %r12
    movq %rdi, %rsi
    movl $4, %edi
    callq *%gs:32
    testq %r12, %r12
    jz .L__vdso_clock_getres_nores
    movdqa %xmm0, (%r12)
.L__vdso_clock_getres_nores:
    popq %rbp
    popq %rbx
    popq %r12
    ret
