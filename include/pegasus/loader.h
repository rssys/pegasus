#pragma once
#include <vector>
#include <string>
#include <cinttypes>
#include "file.h"

namespace pegasus {
class MM;
struct ELFLoader {
    ELFLoader() : mm(nullptr) {}
    ELFLoader(const ELFLoader &) = delete;
    ELFLoader &operator=(const ELFLoader &) = delete;
    void load_elf(std::vector<uint8_t> &buf, MonitorFile &f, std::string &path,
                  const char *filename, std::string *interp,
                  uintptr_t *start, uintptr_t *base, bool main_program);
    uintptr_t load_program(const char *filename, const std::vector<std::string> &args,
                           const std::vector<std::string> &env, MonitorFile &file,
                           std::string &path,
                           const char *override_interp,
                           uintptr_t override_entry, bool load_vdso = true);
    MM *mm;
    uintptr_t stack;
    std::vector<uint8_t> elf_program;
    std::vector<uint8_t> elf_interp;
    std::string interp;
    uintptr_t base;
};
}