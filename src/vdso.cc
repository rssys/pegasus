#include <cstring>
#include <sys/mman.h>
#include <sys/auxv.h>
#include "pegasus/elf.h"
#include "pegasus/exception.h"
#include "pegasus/mm.h"
#include "pegasus/vdso.h"

using namespace pegasus;

struct VDSOInfo {
    uintptr_t base;
    uintptr_t load_offset;

    Elf_Sym *symtab;
    const char *symstrings;
    Elf_Word *bucket, *chain;
    Elf_Word nbucket, nchain;

    Elf_Versym *versym;
    Elf_Verdef *verdef;
};

static VDSOInfo info;
int (*pegasus_vdso_clock_gettime)(clockid_t, struct __kernel_timespec *);
int (*pegasus_vdso_gettimeofday)(struct timeval *, struct timezone *);
__kernel_old_time_t (*pegasus_vdso_time)(__kernel_old_time_t *);
int (*pegasus_vdso_clock_getres)(clockid_t, struct __kernel_timespec *);

static void load_vdso(VDSOInfo &info) {
    info.base = getauxval(AT_SYSINFO_EHDR);
    if (!info.base) {
        throw Exception("failed to get vDSO base address");
    }
    Elf_Ehdr *ehdr = (Elf_Ehdr *)info.base;
    Elf_Phdr *phdr = (Elf_Phdr *)(info.base + ehdr->e_phoff);
    Elf_Dyn *dyn = nullptr;
    bool found_vaddr = false;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && !found_vaddr) {
            found_vaddr = true;
            info.load_offset = info.base + phdr[i].p_offset - phdr[i].p_vaddr;
        } else if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf_Dyn *)(info.base + phdr[i].p_offset);
        }
    }

    if (!found_vaddr || !dyn) {
        throw Exception("failed to parse vDSO");
    }

    Elf_Word *hash = nullptr;
    info.symstrings = nullptr;
    info.symtab = nullptr;
    info.versym = nullptr;
    info.verdef = nullptr;
    for (int i = 0; dyn[i].d_tag != DT_NULL; ++i) {
        uintptr_t addr = (uintptr_t)dyn[i].d_un.d_ptr + info.load_offset;
        switch (dyn[i].d_tag) {
        case DT_STRTAB:
            info.symstrings = (const char *)addr;
            break;
        case DT_SYMTAB:
            info.symtab = (Elf_Sym *)addr;
            break;
        case DT_HASH:
            hash = (Elf_Word *)addr;
            break;
        case DT_VERSYM:
            info.versym = (Elf_Versym *)addr;
            break;
        case DT_VERDEF:
            info.verdef =(Elf_Verdef *)addr;
            break;
        }
    }

    if (!info.symstrings || !info.symtab || !hash) {
        throw Exception("failed to parse vDSO");
    }

    if (!info.verdef) {
        info.versym = nullptr;
    }

    info.nbucket = hash[0];
    info.nchain = hash[1];
    info.bucket = &hash[2];
    info.chain = &hash[info.nbucket + 2];
}

static unsigned long elf_hash(const unsigned char *name)
{
    unsigned long h = 0, g;
    while (*name) {
        h = (h << 4) + *name++;
        if ((g = (h & 0xf0000000))) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

static void *vdso_sym(VDSOInfo &info, const char *name) {
    Elf_Word chain = info.bucket[elf_hash((const unsigned char *)name) % info.nbucket];
    for (; chain != STN_UNDEF; chain = info.chain[chain]) {
        Elf_Sym *sym = &info.symtab[chain];

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;
        if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL &&
            ELF64_ST_BIND(sym->st_info) != STB_WEAK)
            continue;
        if (sym->st_shndx == SHN_UNDEF)
            continue;
        if (strcmp(name, info.symstrings + sym->st_name))
            continue;
        return (void *)(info.load_offset + sym->st_value);
    }
    return nullptr;
}

static void get_vdso_symbols(std::vector<void *> &symbols,
                             const std::vector<std::string> &names) {
    for (const std::string &name : names) {
        void *symbol = vdso_sym(info, name.c_str());
        if (!symbol) {
            throw Exception("failed to solve symbol from vDSO: " + name);
        }
        symbols.push_back(symbol);
    }
}

void pegasus::init_vdso() {
    load_vdso(info);
    if (pkey_mprotect((void *)info.base, PAGE_SIZE * 2, PROT_READ | PROT_EXEC, PkeyReadonly) == -1) {
        throw Exception("failed to set vdso");
    }
    if (pkey_mprotect((void *)(info.base - PAGE_SIZE * 4), PAGE_SIZE * 4, PROT_READ, PkeyReadonly) == -1) {
        throw Exception("failed to set vvar");
    }
    std::vector<void *> symbols;
    get_vdso_symbols(symbols, {
        "__vdso_clock_gettime",
        "__vdso_gettimeofday",
        "__vdso_time",
        "__vdso_clock_getres"
    });
    pegasus_vdso_clock_gettime = (decltype(pegasus_vdso_clock_gettime))symbols[0];
    pegasus_vdso_gettimeofday = (decltype(pegasus_vdso_gettimeofday))symbols[1];
    pegasus_vdso_time = (decltype(pegasus_vdso_time))symbols[2];
    pegasus_vdso_clock_getres = (decltype(pegasus_vdso_clock_getres))symbols[3];
}

void *pegasus::get_vdso_base() {
    return (void *)info.base;
}
