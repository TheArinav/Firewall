#ifndef COMPRESSED_AC_HPP
#define COMPRESSED_AC_HPP

#include <vector>
#include <array>
#include <queue>
#include <string>
#include <unordered_map>

constexpr int COMPRESSED_ALPHABET_SIZE = 256;  // Full ASCII range

class CompressedAC {
public:
    CompressedAC();

    void buildAutomaton(const std::vector<std::string>& patterns);
    bool search(const std::string& text) const;

private:
    struct alignas(64) State {  // Ensures cache alignment
        std::array<int, COMPRESSED_ALPHABET_SIZE> transitions{};  // Compact transition table
        int failureLink = 0;  // Uses indices instead of pointers
        bool isEndOfPattern = false;

        State() {
            transitions.fill(-1);  // Initialize with no transitions
        }
    };

    std::vector<State> states;  // Stores all states contiguously for cache efficiency
};

#endif // COMPRESSED_AC_HPP
