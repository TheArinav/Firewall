#include "regex-enforcer.hpp"

using namespace std;

RegexEnforcer::RegexEnforcer(const string& pattern, bool allow)
    : matchMode(RegexMatchMode::FULL_REGEX),
      allowAction(allow),
      fullPattern(pattern),
      regexPattern(pattern) {}

RegexEnforcer::RegexEnforcer(const string& fullPattern, const string& acPrefix,
                             const string& regexRemainder,
                             RegexMatchMode mode, bool allow)
    : matchMode(mode),
      allowAction(allow),
      fullPattern(fullPattern),
      acPrefix(acPrefix),
      regexRemainder(regexRemainder),
      regexPattern(regexRemainder) {}

bool RegexEnforcer::validate(const string& fullPacket) const {
    switch (matchMode) {
    case RegexMatchMode::FULL_AC:
        return true; // already validated by AC

    case RegexMatchMode::PARTIAL_AC:
        return regex_match(fullPacket, regexPattern);

    case RegexMatchMode::FULL_REGEX:
        return regex_match(fullPacket, regexPattern);
    }
    return false;
}

const string& RegexEnforcer::getFullPattern() const {
    return fullPattern;
}

const string& RegexEnforcer::getACPrefix() const {
    return acPrefix;
}

RegexMatchMode RegexEnforcer::getMode() const {
    return matchMode;
}

bool RegexEnforcer::isAllow() const {
    return allowAction;
}
