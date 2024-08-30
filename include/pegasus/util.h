#pragma once
#include <string>
#include <string_view>
#include <functional>

namespace pegasus {
inline static bool startswith(const std::string &s, const std::string &pattern) {
    return s.length() >= pattern.length() &&
        std::string_view(s.c_str(), pattern.length()) == std::string_view(pattern.c_str());
}

struct CleanupHelper {
    CleanupHelper(const std::function<void ()> &routine_) : routine(routine_) {}
    CleanupHelper(const CleanupHelper &) = delete;
    CleanupHelper &operator=(const CleanupHelper &) = delete;
    ~CleanupHelper() {
        routine();
    }
    std::function<void ()> routine;
};
}