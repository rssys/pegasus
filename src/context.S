.text
.global pegasus_executor_context_switch
pegasus_executor_context_switch:
    leaq .Lpegasus_executor_context_switch_resume(%rip), %rax
    movq %rax, (%rdi)
    movq %rsp, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %rbx, 24(%rdi)
    movq %r12, 32(%rdi)
    movq %r13, 40(%rdi)
    movq %r14, 48(%rdi)
    movq %r15, 56(%rdi)
    movq 56(%rsi), %r15
    movq 48(%rsi), %r14
    movq 40(%rsi), %r13
    movq 32(%rsi), %r12
    movq 24(%rsi), %rbx
    movq 16(%rsi), %rbp
    movq 8(%rsi), %rsp
    movq (%rsi), %r10
    movq %rdx, %rax
    jmpq *%r10
.Lpegasus_executor_context_switch_resume:
    ret