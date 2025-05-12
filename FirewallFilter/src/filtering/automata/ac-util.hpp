#ifndef AC_UTIL_HPP
#define AC_UTIL_HPP

#include <string>

constexpr int ALPHABET_SIZE = 256;

struct RegexPatternMetadata {
    std::string pattern;
    std::string ruleID;
    std::string srcIP;
    std::string dstIP;
    int srcPort;
    int dstPort;
    bool allow;
};

struct alignas(64) Node {
    std::array<int, ALPHABET_SIZE> transitions{};
    int failureLink = 0;
    bool isEndOfPattern = false;
    int patternCount = 0;
    std::vector<MatchTarget> matchTargets;

    Node() { transitions.fill(-1); }
};

#endif //AC_UTIL_HPP
