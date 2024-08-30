#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <functional>
#include <tuple>
#include <cinttypes>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/random.h>
#include "pegasus/elf.h"
#include "pegasus/exception.h"
#include "pegasus/loader.h"
#include "pegasus/mm.h"
#include "pegasus/runtime.h"

using namespace pegasus;

static constexpr size_t MainThreadSize = 8192 * 1024;

void ELFLoader::load_elf(std::vector<uint8_t> &buffer, MonitorFile &f, std::string &path, const char *filename,
                         std::string *interp, uintptr_t *start, uintptr_t *base, bool main_program) {
    size_t size = buffer.size();
    if (!size) {
        char *buf = realpath(filename, nullptr);
        if (!buf) {
            throw Exception("failed to ge realpath of ELF file: " + std::string(strerror(errno)));
        }
        try {
            path = buf;
        } catch (...) {
            free(buf);
            throw;
        }
        free(buf);
        f.fd = open(filename, O_RDONLY);
        if (f.fd == -1) {
            throw Exception("failed to open ELF file: " + std::string(strerror(errno)));
        }
        size = lseek64(f.fd, 0, SEEK_END);
        if (size == -1ull) {
            throw Exception("failed to seek ELF file: " + std::string(strerror(errno)));
        }
        lseek64(f.fd, 0, SEEK_SET);
        buffer.resize(size);
        if (read(f.fd, (char *)buffer.data(), size) != size) {
            throw Exception("failed to read ELF file: " + std::string(strerror(errno)));
        }
    }

    uint8_t *file_start = buffer.data();
    if (size < sizeof(Elf_Ehdr)) {
        throw Exception("corrupted ELF file");
    }
    Elf_Ehdr *ehdr = (Elf_Ehdr *)file_start;
    if (!ehdr->e_phoff) {
        throw Exception("corrupted ELF file");
    }
    Elf_Phdr *phdr = (Elf_Phdr *)(file_start + ehdr->e_phoff);
    if ((uint8_t *)&phdr[ehdr->e_phnum] > file_start + size) {
        throw Exception("corrupted ELF file");
    }
    if (ehdr->e_type != ET_DYN) {
        throw Exception("ELF file is not dynamic: " + std::string(filename));
    }

    size_t mem_size = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_offset + phdr[i].p_filesz > size) {
            throw Exception("corrupted ELF file");;
        }
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }
        uintptr_t end = page_round_up(phdr[i].p_vaddr + phdr[i].p_memsz);
        if (end > mem_size) {
            mem_size = end;
        }
    }

    uintptr_t b = -1;
    {
        uintptr_t mem_start = mm->mmap(
            main_program ? (uintptr_t)mm->get_base() : 0, mem_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0, false, !main_program);
        if (is_fail_address(mem_start)) {
            throw Exception("failed to allocate virtual address for ELF");;
        }
        std::vector<std::tuple<void *, size_t, int>> prots;
        for (int i = 0; i < ehdr->e_phnum; ++i) {
            Elf_Phdr &p = phdr[i];
            Elf_Word type = p.p_type;
            if (type == PT_GNU_STACK) {
                if (p.p_flags & PF_X) {
                    throw Exception("unsupported executable stack");;
                }
                continue;
            } else if (type == PT_INTERP && interp) {
                *interp = std::string((const char *)file_start + p.p_offset, p.p_filesz);
                continue;
            } else if (type != PT_LOAD) {
                continue;
            }
            uintptr_t map_start = page_round_down(p.p_vaddr);
            uintptr_t map_end = page_round_up(p.p_vaddr + p.p_memsz);
            int prot = 0;
            uintptr_t addr = mm->mmap(mem_start + map_start, map_end - map_start, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0, false, true);
            if (is_fail_address(addr)) {
                throw Exception("failed to allocate segment space");;
            }
            if (p.p_filesz) {
                if (p.p_filesz > p.p_memsz) {
                    throw Exception("corrupted ELF file");;
                }
                memcpy((void *)(mem_start + p.p_vaddr), file_start + p.p_offset, p.p_filesz);
            }
            if (p.p_memsz > p.p_filesz) {
                memset((void *)(mem_start + p.p_vaddr + p.p_filesz), 0, p.p_memsz - p.p_filesz);
            }
            if (p.p_flags & PF_R) {
                prot |= PROT_READ;
            }
            if (p.p_flags & PF_W) {
                prot |= PROT_WRITE;
            }
            if (p.p_flags & PF_X) {
                prot |= PROT_EXEC;
            }
            prots.emplace_back((void *)(mem_start + map_start), map_end - map_start, prot);
            if (mem_start + map_start < b) {
                b = mem_start + map_start;
            }
        }
        for (auto &&p : prots) {
            if (mm->mprotect((uintptr_t)std::get<0>(p), std::get<1>(p), std::get<2>(p), false) < 0) {
                throw Exception("failed to set memory protection");;
            }
        }
        if (start) {
            *start = mem_start;
        }
        if (base) {
            *base = b;
        }
    }
}

uintptr_t ELFLoader::load_program(const char *filename, const std::vector<std::string> &args,
                                  const std::vector<std::string> &env,
                                  MonitorFile &file,
                                  std::string &path,
                                  const char *override_interp,
                                  uintptr_t override_entry, bool enable_vdso) {
    uintptr_t start, interp_start;
    uintptr_t interp_base;
    void *vdso_base = nullptr;
    //uintptr_t vdso_start, vdso_base;
    //bool has_vdso = false;
    MonitorFile interp_file, vdso_file;
    std::string interp_path, vdso_path;
    load_elf(elf_program, file, path, filename, &interp, &start, &base, true);
    mm->init_heap(PAGE_SIZE);
    if (!interp.empty()) {
        if (override_interp) {
            interp = override_interp;
        }
        load_elf(elf_interp, interp_file, interp_path, interp.c_str(), nullptr, &interp_start, &interp_base, false);
    }
    uintptr_t stack_base = mm->mmap(0, MainThreadSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                                    -1, 0, false, true);
    stack = stack_base + MainThreadSize;
    //std::vector<uint8_t> &elf_vdso = Runtime::get()->get_vdso_elf();
    //if (enable_vdso && elf_vdso.size()) {
    //    has_vdso = true;
    //    //load_elf(elf_vdso, vdso_file, vdso_path, nullptr, nullptr, &vdso_start, &vdso_base, false);
    //}
    if (enable_vdso) {
        vdso_base = Runtime::get()->get_vdso_base();
    }
    static constexpr size_t MaxArgEnvSize = 1024 * 32;
    size_t str_size = 0;
    for (const std::string &s : args) {
        str_size += s.size() + 1;
    }
    for (const std::string &s: env) {
        str_size += s.size() + 1;
    }
    if (str_size > MaxArgEnvSize) {
        throw Exception("the size of arguments and environment variables is too big");
    }
    if (stack - str_size < stack_base) {
        throw Exception("stack overflow");
    }
    stack -= str_size;
    uint8_t *ptr = (uint8_t *)stack;
    std::vector<uintptr_t> arg_ptr;
    std::vector<uintptr_t> env_ptr;
    for (size_t i = 0; i < args.size(); ++i) {
        memcpy(ptr, args[i].c_str(), args[i].size() + 1);
        arg_ptr.push_back((uintptr_t)ptr);
        ptr += args[i].size() + 1;
    }
    for (size_t i = 0; i < env.size(); ++i) {
        memcpy(ptr, env[i].c_str(), env[i].size() + 1);
        env_ptr.push_back((uintptr_t)ptr);
        ptr += env[i].size() + 1;
    }
    if (stack - 16 < stack_base) {
        throw Exception("stack overflow");
    }
    stack -= 16;
    uint8_t *random = (uint8_t *)stack;
    if (getrandom(random, 16, 0) != 16) {
        throw Exception("failed to get random");
    }
    struct AT {
        uintptr_t id;
        uintptr_t value;
    };
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elf_program.data();
    uintptr_t entry = start + ehdr->e_entry;
    if (override_entry != 0) {
        entry = override_entry;
    }
    std::vector<AT> at {
        {AT_PHDR,           base + ehdr->e_phoff},
        {AT_PHENT,          sizeof(Elf_Phdr)},
        {AT_PHNUM,          ehdr->e_phnum},
        {AT_PAGESZ,         PAGE_SIZE},
        {AT_BASE,           interp_start},
        {AT_FLAGS,          0},
        {AT_ENTRY,          entry},
        {AT_UID,            getuid()},
        {AT_EUID,           geteuid()},
        {AT_GID,            getgid()},
        {AT_EGID,           getegid()},
        {AT_RANDOM,         (uintptr_t)random},
        {AT_SECURE,         0},
    };
    if (vdso_base) {
        at.push_back({AT_SYSINFO_EHDR, (uintptr_t)vdso_base});
    }
    at.push_back({AT_NULL, 0});
    size_t aux_info_size = at.size() * sizeof(AT) + sizeof(uintptr_t) +
        (args.size() + 1 + env.size() + 1) * sizeof(uintptr_t);
    stack = (stack - aux_info_size) & (~0xfull);
    if (stack < stack_base) {
        throw Exception("stack overflow");
    }
    uintptr_t *p = (uintptr_t *)stack;
    *(p++) = args.size();
    for (uintptr_t x : arg_ptr) {
        *(p++) = x;
    }
    *(p++) = 0;
    for (uintptr_t x : env_ptr) {
        *(p++) = x;
    }
    *(p++) = 0;
    memcpy(p, at.data(), at.size() * sizeof(AT));
    uintptr_t jump_addr;
    if (elf_interp.size()) {
        jump_addr = interp_start + ((Elf_Ehdr *)elf_interp.data())->e_entry;
    } else {
        jump_addr = entry;
    }
    return jump_addr;
}
