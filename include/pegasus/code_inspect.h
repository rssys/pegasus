#pragma once
#include <vector>
#include <string>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <cinttypes>

namespace pegasus {
struct BinaryPattern {
    std::string seq;
    std::string unsafe_seq;
    std::string replace_seq;
    size_t offset;
    bool replace;
};

class CodeInspector {
public:
    CodeInspector(const std::string &rule_filename, bool load_default_patterns = true);
    CodeInspector(const CodeInspector &) = delete;
    CodeInspector &operator=(const CodeInspector &) = delete;
    void load_default_patterns();
    void ignore(const uint8_t *seq, size_t size);
    void replace(const uint8_t *from, const uint8_t *to, size_t size);
    void load_rules(const std::string &filename);
    bool inspect(const uint8_t *start, size_t size, uint8_t *rewrite_start,
                    size_t rewrite_size, int fd, bool may_rewrite) const;
    void find_unsafe_instructions(const uint8_t *start, size_t size, std::vector<uintptr_t> &res) const;
    bool inspect_process();
private:
    bool find_next(const uint8_t *start, const uint8_t *end, const uint8_t **pos,
                   size_t *size, int *prefix, bool check_rip, uint8_t *rstart = nullptr, uint8_t *rend = nullptr) const;
    bool check_xrstor_rip(const uint8_t *start, const uint8_t *end) const;
    std::unordered_map<std::string, std::vector<BinaryPattern>> patterns;
    std::unordered_set<unsigned int> passthrough_syscalls;
    bool is_syscall_rewriting_enabled;
};
}