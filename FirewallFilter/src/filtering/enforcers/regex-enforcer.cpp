#include "regex-enforcer.hpp"

using namespace std;

RegexEnforcer::RegexEnforcer(const string& pattern)
    : regexPattern(pattern), regexPatternStr(pattern) {}

bool RegexEnforcer::validate(const string& payload) const {
    return regex_match(payload, regexPattern);
}

const string& RegexEnforcer::getPattern() const {
    return regexPatternStr;
}

