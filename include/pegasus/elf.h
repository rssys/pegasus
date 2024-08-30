#pragma once
#include <elf.h>
#include <stdint.h>

#if INTPTR_MAX == INT32_MAX
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Word Elf_Word;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Half Elf_Half;
typedef Elf32_Versym Elf_Versym;
typedef Elf32_Verdef Elf_Verdef;
#define ELF_R_SYM(x) ELF32_R_SYM(x)
#define ELF_R_TYPE(x) ELF32_R_TYPE(x)
#elif INTPTR_MAX == INT64_MAX
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Word Elf_Word;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Half Elf_Half;
typedef Elf64_Versym Elf_Versym;
typedef Elf64_Verdef Elf_Verdef;
#define ELF_R_SYM(x) ELF64_R_SYM(x)
#define ELF_R_TYPE(x) ELF64_R_TYPE(x)
#endif