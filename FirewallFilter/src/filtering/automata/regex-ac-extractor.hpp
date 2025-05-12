#ifndef REGEX_AC_EXTRACTOR_HPP
#define REGEX_AC_EXTRACTOR_HPP

#include <string>
#include <vector>
#include "../enforcers/regex-enforcer.hpp"

// Converts a regex string into a RegexEnforcer instance.
// Automatically classifies it as FULL_AC, HYBRID, or FULL_REGEX.
RegexEnforcer convertRegexToEnforcer(const std::string& pattern, bool allow);

#endif // REGEX_AC_EXTRACTOR_HPP
