#include <vector>
#include <memory>
#include <string>
#include <string_view>
#include <fstream>
#include <unordered_map>
#include <cinttypes>
#include <cstring>
#include <sys/mman.h>
#include "pegasus/code_inspect.h"
#include "pegasus/exception.h"
#include "pegasus/gate.h"
#include "pegasus/mm.h"
#include "pegasus/runtime.h"

using namespace pegasus;

extern uint8_t __start_pegasus_trusted_code;
extern uint8_t __stop_pegasus_trusted_code;

static constexpr int LongestUnsafeSequence = 5;

CodeInspector::CodeInspector(const std::string &rule_filename, bool load_default_patterns_) {
    if (load_default_patterns_) {
        load_default_patterns();
    }
    if (!rule_filename.empty()) {
        load_rules(rule_filename);
    }
}

void CodeInspector::load_default_patterns() {
    // ldso
    uint8_t code[12];
    code[0] = 0x48;
    code[1] = 0xb8;
    *(void **)(code + 2) = (void *)pegasus_ld_so_safe_xrstor;
    code[10] = 0xff;
    code[11] = 0xd0;
    replace((const uint8_t *)"\xb8\xee\x00\x00\x00\x31\xd2\x0f\xae\x6c\x24\x40", code, 12);
    // glibc pkey_set
    replace((const uint8_t *)"\x0f\x01\xef\x31\xc0\xc3",
            (const uint8_t *)"\xb8\xff\xff\xff\xff\xc3", 6);
}

void CodeInspector::ignore(const uint8_t *seq, size_t size) {
    const uint8_t *start = seq;
    const uint8_t *end = seq + size;
    const uint8_t *pos;
    size_t inst_size;
    const uint8_t *i = start;
    int prefix;
    while (find_next(i, end, &pos, &inst_size, &prefix, false)) {
        std::string unsafe_seq((const char *)pos, inst_size);
        BinaryPattern pattern;
        pattern.seq = std::string((const char *)start, size);
        pattern.replace = false;
        pattern.unsafe_seq = unsafe_seq;
        pattern.offset = pos - start;
        patterns[unsafe_seq].push_back(pattern);
        i = pos + inst_size;
    }
}

void CodeInspector::replace(const uint8_t *from, const uint8_t *to, size_t size) {
    const uint8_t *start = from;
    const uint8_t *end = from + size;
    const uint8_t *pos;
    size_t inst_size;
    const uint8_t *i = start;
    int prefix;
    while (find_next(i, end, &pos, &inst_size, &prefix, false)) {
        std::string unsafe_seq((const char *)pos, inst_size);
        BinaryPattern pattern;
        pattern.seq = std::string((const char *)start, size);
        pattern.replace = true;
        pattern.replace_seq = std::string((const char *)to, size);
        pattern.unsafe_seq = unsafe_seq;
        pattern.offset = pos - start;
        patterns[unsafe_seq].push_back(pattern);
        i = pos + inst_size;
    }
}

void CodeInspector::load_rules(const std::string &filename) {
    std::ifstream ifs(filename);
    if (!ifs) {
        throw Exception("cannot open file");
    }
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.length() > 0 && line.back() == '\n') {
            line = line.substr(0, line.length() - 1);
        }
        size_t pos1 = line.find(',');
        if (pos1 == std::string::npos) {
            throw Exception("wrong rule format");
        }
        std::string method(line.c_str(), pos1);
        std::string from;
        std::string to;
        bool is_ignore = false;
        if (method == "ignore") {
            is_ignore = true;
            from = line.substr(pos1 + 1, line.length() - pos1 - 1);
        } else if (method == "replace") {
            size_t pos2 = line.find(',', pos1 + 1);
            if (pos2 == std::string::npos) {
                throw Exception("wrong rule format");
            }
            from = line.substr(pos1 + 1, pos2 - pos1 - 1);
            to = line.substr(pos2 + 1, line.length() - pos2 - 1);
        } else {
            throw Exception("wrong rule format");
        }
        size_t len_from = from.length() / 2;
        if (from.length() != len_from * 2) {
            throw Exception("wrong rule format");
        }
        std::string from_bin('\0', len_from);
        for (size_t i = 0; i < len_from; ++i) {
            from_bin[i] = (char)stoi(from.substr(i * 2, 2), nullptr, 16);
        }
        if (!is_ignore) {
            size_t len_to = to.length() / 2;
            if (to.length() != len_to * 2 || len_from != len_to) {
                throw Exception("wrong rule format5");
            }
            std::string to_bin('\0', len_to);
            for (size_t i = 0; i < len_from; ++i) {
                to_bin[i] = (char)stoi(to.substr(i * 2, 2), nullptr, 16);
            }
            replace((const uint8_t *)from_bin.c_str(), (const uint8_t *)to_bin.c_str(), len_from);
        } else {
            ignore((const uint8_t *)from_bin.c_str(), len_from);
        }
    }
}

bool CodeInspector::inspect(const uint8_t *start, size_t size, uint8_t *rewrite_start,
                            size_t rewrite_size, int fd, bool may_rewrite) const {
    const uint8_t *pos;
    size_t inst_size;
    const uint8_t *s = start;
    const uint8_t *e = start + size;
    const uint8_t *rw_s = (const uint8_t *)rewrite_start;
    const uint8_t *rw_e = (const uint8_t *)rewrite_start + rewrite_size;
    int prefix;
    if (!find_next(s, e, &pos, &inst_size, &prefix, true, rewrite_start, rewrite_start + rewrite_size)) {
        return true;
    }
    const uint8_t *i;
    // first replace
    if (may_rewrite) {
        do {
            std::string unsafe_seq((const char *)pos, inst_size);
            auto it = patterns.find(unsafe_seq);
            if (it == patterns.end()) {
                i = pos + inst_size;
                continue;
            }
            for (auto &&p : it->second) {
                uint8_t *s_pattern = (uint8_t *)pos - p.offset;
                if (s_pattern < rw_s || s_pattern + p.seq.size() > rw_e) {
                    continue;
                }
                if (memcmp(s_pattern, p.seq.data(), p.seq.size()) == 0) {
                    memcpy(s_pattern, p.replace_seq.data(), p.seq.size());
                    break;
                }
            }
            i = pos + inst_size;
        } while (find_next(i, e, &pos, &size, &prefix, true, rewrite_start, rewrite_start + rewrite_size));
    }
    i = s;
    while (find_next(i, e, &pos, &inst_size, &prefix, true)) {
        std::string unsafe_seq((const char *)pos, inst_size);
        auto it = patterns.find(unsafe_seq);
        if (it == patterns.end()) {
            return false;
        }
        bool find_ignore = false;
        for (auto &&p : it->second) {
            const uint8_t *s_pattern = pos - p.offset;
            if (s_pattern < s || s_pattern + p.seq.size() > e) {
                continue;
            }
            if (memcmp(s_pattern, p.seq.data(), p.seq.size()) == 0) {
                find_ignore = true;
                break;
            }
        }
        if (!find_ignore) {
            return false;
        }
        i = pos + inst_size;
    }
    return true;
}

void CodeInspector::find_unsafe_instructions(const uint8_t *start, size_t size, std::vector<uintptr_t> &res) const {
    const uint8_t *s = start;
    const uint8_t *e = start + size;
    const uint8_t *i = s;
    const uint8_t *pos;
    size_t inst_size;
    int prefix;
    while (find_next(i, e, &pos, &inst_size, &prefix, true)) {
        std::string unsafe_seq((const char *)pos, inst_size);
        auto it = patterns.find(unsafe_seq);
        bool find_ignore = false;
        if (it == patterns.end()) {
            for (int j = 0; j <= prefix; ++j) {
                res.push_back((uintptr_t)(pos - j));
            }
            goto next;
        }
        for (auto &&p : it->second) {
            const uint8_t *s_pattern = pos - p.offset;
            if (s_pattern < s || s_pattern + p.seq.size() > e) {
                continue;
            }
            if (memcmp(s_pattern, p.seq.data(), p.seq.size()) == 0) {
                find_ignore = true;
                break;
            }
        }
        if (!find_ignore) {
            for (int j = 0; j <= prefix; ++j) {
                res.push_back((uintptr_t)(pos - j));
            }
        }
next:
        i = pos + inst_size;
    }
    if (Runtime::get()->get_config().log_code_inspection) {
        for (uintptr_t p : res) {
            char buf[64];
            sprintf(buf, "Found unsafe instruction @ %p:", (void *)p);
            std::string msg = buf;
            const uint8_t *log_s = (const uint8_t *)p - 32;
            if (log_s < s) {
                log_s = s;
            }
            const uint8_t *log_e = (const uint8_t *)p + 32;
            if (log_e > e) {
                log_e = e;
            }
            for (const uint8_t *q = log_s; q < log_e; ++q) {
                if ((uintptr_t)q == p) {
                    sprintf(buf, " <%02x>", (int)*q);
                } else {
                    sprintf(buf, " %02x", (int)*q);
                }
                msg += buf;
            }
            puts(msg.c_str());
        }
    }
}

bool CodeInspector::find_next(const uint8_t *start, const uint8_t *end, const uint8_t **pos,
                              size_t *size, int *prefix, bool check_rip, uint8_t *rstart, uint8_t *rend) const {
    for (const uint8_t *i = start; i < end; ++i) {
        if (*i == 0x0f && i + 2 < end) {
            if (*(i + 1) == 0x01 && *(i + 2) == 0xef) {
                // wrpkru
                int p = 0;
                const uint8_t *s = i - 1;
                // prefix, including rex prefix and legacy prefixes
                // note that the limit of instruction length is 15 bytes
                for (int j = 0; j < 12; ++j) {
                    if (s >= start) {
                        uint8_t pr = *s;
                        if ((pr & 0xf0) == 0x40 ||
                            pr == 0x67 || pr == 0x64 || pr == 0x65 || pr == 0x2e ||
                            pr == 0x36 || pr == 0x3e || pr == 0x26) {
                            ++p;
                            --s;
                            continue;
                        }
                    }
                    break;
                }

                *pos = i;
                *size = 3;
                *prefix = p;
                return true;
            } else if (*(i + 1) == 0xae) {
                int h = *(i + 2) & 0xf8;
                if (h == 0x28 || h == 0x68 || h == 0xa8) {
                    // xrstor
                    int p = 0;
                    const uint8_t *s = i - 1;
                    bool is_fs_gs = false;
                    // the rex prefix must be W/R
                    if (s >= start && (*s & 0xf0) == 0x40) {
                        if ((*s & 0xf3) != 0x40) {
                            *pos = i;
                            *size = 3;
                            *prefix = 0;
                            return true;
                        } else {
                            ++p;
                            --s;
                        }
                    }
                    for (int j = 0; j < 12; ++j) {
                        if (s >= start) {
                            uint8_t pr = *s;
                            if ((pr & 0xf0) == 0x40 ||
                                pr == 0x67 || pr == 0x64 || pr == 0x65 || pr == 0x2e ||
                                pr == 0x36 || pr == 0x3e || pr == 0x26) {
                                ++p;
                                --s;
                                if (pr == 0x64 || pr == 0x65) {
                                    is_fs_gs = true;
                                }
                                continue;
                            }
                        }
                        break;
                    }
                    if (!is_fs_gs && check_rip && *(i + 2) == 0x2d && check_xrstor_rip(i, end)) {
                        // xrstor $CONST(%rip) or xrstor $CONST(%eip)
                        continue;
                    }
                    *pos = i;
                    *size = 3;
                    *prefix = p;
                    return true;
                }
            }
        } else if (*i == 0xf3 && i + 3 < end) {
            // wrgsbase
            if (*(i + 1) == 0x0f && *(i + 2) == 0xae &&
                (*(i + 3) >= 0xd8 && *(i + 3) <= 0xdf)) {
                int p = 0;
                const uint8_t *s = i - 1;
                for (int j = 0; j < 11; ++j) {
                    if (s >= start) {
                        uint8_t pr = *s;
                        if ((pr & 0xf0) == 0x40 ||
                            pr == 0x66 || pr == 0x67 || pr == 0x64 || pr == 0x65 ||
                            pr == 0x2e || pr == 0x36 || pr == 0x3e || pr == 0x26) {
                            ++p;
                            --s;
                            continue;
                        }
                    }
                    break;
                }
                *pos = i;
                *size = 4;
                *prefix = p;
                return true;
            }
            if (i + 4 < end &&
                ((*(i + 1) & 0xf0) == 0x40) &&
                *(i + 2) == 0x0f &&
                *(i + 3) == 0xae &&
                (*(i + 4) >= 0xd8 && *(i + 4) <= 0xdf)) {
                int p = 0;
                const uint8_t *s = i - 1;
                for (int j = 0; j < 10; ++j) {
                    if (s >= start) {
                        uint8_t pr = *s;
                        if ((pr & 0xf0) == 0x40 ||
                            pr == 0x66 || pr == 0x67 || pr == 0x64 || pr == 0x65 ||
                            pr == 0x2e || pr == 0x36 || pr == 0x3e || pr == 0x26) {
                            ++p;
                            --s;
                            continue;
                        }
                    }
                    break;
                }
                *pos = i;
                *size = 5;
                *prefix = p;
                return true;
            }
        }
    }
    return false;
}

bool CodeInspector::check_xrstor_rip(const uint8_t *start, const uint8_t *end) const {
    // if the byte sequence is xrstor $CONST(%rip), we can compute %rip+$CONST
    // if it's not 64 byte aligned, then this xrstor will cause GPF so it's safe
    if (start + 7 > end) {
        // illegal instruction
        return true;
    }
    uintptr_t rip = (uintptr_t)start + 7;
    int32_t offset = *(int32_t *)(start + 3);
    rip += offset;
    return rip % 64;
}

static void get_executable_maps(std::vector<std::pair<uintptr_t, uintptr_t>> &maps) {
    std::string line;
    std::ifstream ifs("/proc/self/maps");
    if (!ifs) {
        throw Exception("failed to open /proc/self/maps");;
    }
    while (std::getline(ifs, line)) {
        std::string_view line_view(line);
        size_t p1, p2;
        p2 = line_view.find('-');
        if (p2 == std::string_view::npos) {
            continue;
        }
        line[p2] = 0;
        std::string_view addr_start_s = line_view.substr(0, p2);

        p1 = p2 + 1;
        p2 = line_view.find(' ', p1);
        if (p2 == std::string_view::npos) {
            continue;
        }
        line[p2] = 0;
        std::string_view addr_end_s = line_view.substr(p1, p2 - p1);

        p1 = p2 + 1;
        p2 = line_view.find(' ', p1);
        if (p2 == std::string_view::npos) {
            continue;
        }
        std::string_view prot_s = line_view.substr(p1, p2 - p1);
        if (prot_s.length() != 4) {
            continue;
        }
        bool prot_r = prot_s[0] == 'r';
        bool prot_x = prot_s[2] == 'x';

        p1 = p2 + 1;
        p2 = line_view.find(' ', p1);
        if (p2 == std::string_view::npos) {
            continue;
        }

        p1 = p2 + 1;
        p2 = line_view.find(' ', p1);
        if (p2 == std::string_view::npos) {
            continue;
        }

        p1 = p2 + 1;
        p2 = line_view.find(' ', p1);
        if (p2 == std::string_view::npos) {
            continue;
        }
        for (p1 = p2 + 1; p1 < line_view.length() && line_view[p1] == ' '; ++p1);
        std::string filename;
        if (p1 != line_view.length()) {
            filename = line_view.substr(p1);
        }
        unsigned long addr_start = strtoul(addr_start_s.begin(), nullptr, 16);
        unsigned long addr_end = strtoul(addr_end_s.begin(), nullptr, 16);
        if (!prot_x || !prot_r) {
            continue;
        }
        maps.emplace_back(addr_start, addr_end);
    }
}

bool CodeInspector::inspect_process() {
    std::vector<std::pair<uintptr_t, uintptr_t>> maps;
    get_executable_maps(maps);
    std::vector<std::pair<uintptr_t, uintptr_t>> merged_maps;
    if (maps.empty()) {
        return true;
    }
    uintptr_t start = maps[0].first;
    uintptr_t end = maps[0].second;
    for (size_t i = 1; i < maps.size(); ++i) {
        if (maps[i].first > end) {
            merged_maps.emplace_back(start, end);
            start = maps[i].first;
            end = maps[i].second;
        } else {
            end = maps[i].second;
        }
    }
    merged_maps.emplace_back(start, end);
    for (auto &&m : merged_maps) {
        uint8_t *s = (uint8_t *)m.first;
        uint8_t *e = (uint8_t *)m.second;
        const uint8_t *pos;
        size_t size;
        bool found_unsafe_seq = false;
        int prefix;
        while (s < e && find_next(s, e, &pos, &size, &prefix, true)) {
            if (!(pos >= &__start_pegasus_trusted_code && pos + size < &__stop_pegasus_trusted_code)) {
                found_unsafe_seq = true;
                s = (uint8_t *)pos + size;
            } else {
                s = &__stop_pegasus_trusted_code;
            }
        }
        if (!found_unsafe_seq) {
            continue;
        }
        s = page_round_down(s);
        if (mprotect(s, e - s, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            return false;
        }
        if (!inspect(s, e - s, s, e - s, -1, true)) {
            return false;
        }
        mprotect(s, e - s, PROT_READ | PROT_EXEC);
    }
    return true;
}
