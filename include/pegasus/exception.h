#pragma once
#include <string>
#include <exception>
#include <stdexcept>

namespace pegasus {
class Exception : public std::runtime_error {
public:
    Exception(const std::string &msg, int ret_ = 0);
    Exception(const char *msg, int ret_ = 0);
    virtual ~Exception() {}
    int ret;
};

class ExecutorException : public Exception {
public:
    ExecutorException(const std::string &msg);
    ExecutorException(const char *msg);
    virtual ~ExecutorException() {}
};

class NoPKeyException : public Exception {
public:
    NoPKeyException();
    virtual ~NoPKeyException() {}
};

class FaultException : public Exception {
public:
    FaultException(uintptr_t start_, uintptr_t end_);
    virtual ~FaultException() {}
    uintptr_t start, end;
};

class SignalException : public Exception {
public:
    SignalException(int sig_);
    virtual ~SignalException() {}
    int sig;
};

class SyscallException : public Exception {
public:
    SyscallException(int syscall_);
    virtual ~SyscallException() {}
    int syscall;
};

class SigReturnException : public Exception {
public:
    SigReturnException();
    virtual ~SigReturnException() {}
};

class CorruptedSignalFrameException : public Exception {
public:
    CorruptedSignalFrameException();
    virtual ~CorruptedSignalFrameException() {}
};

class ExitGroupException : public Exception {
public:
    ExitGroupException();
    virtual ~ExitGroupException() {}
};

class ExitException : public Exception {
public:
    ExitException();
    virtual ~ExitException() {}
};

class SystemException : public Exception {
public:
    SystemException(int err_);
    virtual ~SystemException() {}
    int err;
};

class MapleTreeException : public SystemException {
public:
    MapleTreeException(int err_) : SystemException(err_) {}
    virtual ~MapleTreeException() {}
};
}