#include "regex-ac-extractor.hpp"
#include <string>
#include <vector>

using namespace std;

static bool isRegexMetaChar(char c) {
    return c == '.' || c == '*' || c == '+' || c == '?' ||
           c == '(' || c == ')' || c == '[' || c == ']' ||
           c == '{' || c == '}' || c == '^' || c == '$' || c == '|';
}

RegexEnforcer convertRegexToEnforcer(const string& pattern, bool allow) {
    string currentLiteral;
    vector<string> literalSegments;
    bool foundMeta = false;

    for (size_t i = 0; i < pattern.length(); ++i) {
        char c = pattern[i];

        if (c == '\\' && i + 1 < pattern.length()) {
            currentLiteral += pattern[++i];
            continue;
        }

        if (isRegexMetaChar(c)) {
            if (!currentLiteral.empty() && currentLiteral.length() >= 3) {
                literalSegments.push_back(currentLiteral);
            }
            currentLiteral.clear();
            foundMeta = true;
        } else {
            currentLiteral += c;
        }
    }
    if (!currentLiteral.empty() && currentLiteral.length() >= 3) {
        literalSegments.push_back(currentLiteral);
    }

    // === CASE 1: Fully AC-compatible ===
    if (!foundMeta && literalSegments.size() == 1 && literalSegments[0] == pattern) {
        // *** FIXED: use the full pattern as the AC prefix ***
        return RegexEnforcer(
            pattern,        // full regex
            pattern,        // AC prefix == full literal
            "",             // no regex remainder
            RegexMatchMode::FULL_AC,
            allow
        );
    }

    // === CASE 2: Hybrid mode ===
    if (!literalSegments.empty()) {
        return RegexEnforcer(
            pattern,                  // full regex
            literalSegments[0],       // AC‐compatible literal chunk
            pattern,                  // fallback regex
            RegexMatchMode::PARTIAL_AC,
            allow
        );
    }

    // === CASE 3: No AC potential ===
    return RegexEnforcer(pattern, allow);
}
