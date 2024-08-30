#include <string>
#include <exception>
#include <stdexcept>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include "pegasus/exception.h"

using namespace pegasus;

Exception::Exception(const std::string &msg, int ret_) : std::runtime_error(msg), ret(ret_) {}

Exception::Exception(const char *msg, int ret_) : std::runtime_error(msg), ret(ret_) {}

ExecutorException::ExecutorException(const std::string &msg) : Exception(msg) {}

ExecutorException::ExecutorException(const char *msg) : Exception(msg) {}

NoPKeyException::NoPKeyException() : Exception("no available pkey") {}

FaultException::FaultException(uintptr_t start_, uintptr_t end_)
    : Exception("page fault", W_EXITCODE(SIGSEGV + 128, SIGSEGV)), start(start_), end(end_) {}

SignalException::SignalException(int sig_)
    : Exception("unhandled signal: " + std::to_string(sig_), W_EXITCODE(sig_ + 128, sig_)),
      sig(sig_) {}

SyscallException::SyscallException(int syscall_)
    : Exception("unhandled syscall: " + std::to_string(syscall_), W_EXITCODE(SIGSYS + 128, SIGSYS)),
      syscall(syscall_)  {}

SigReturnException::SigReturnException() : Exception("unhandled sigreturn") {}

CorruptedSignalFrameException::CorruptedSignalFrameException()
    : Exception("corrupted signal frame", W_EXITCODE(SIGSEGV + 128, SIGSEGV)) {}

ExitGroupException::ExitGroupException() : Exception("program exited") {}

ExitException::ExitException() : Exception("thread exited") {}

SystemException::SystemException(int err_) :
    Exception(std::string("system error: ") + strerror(err_)), err(err_) {}
