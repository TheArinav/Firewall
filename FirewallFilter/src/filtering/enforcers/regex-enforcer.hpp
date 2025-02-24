#ifndef REGEX_ENFORCER_HPP
#define REGEX_ENFORCER_HPP

#include <string>
#include <regex>

class RegexEnforcer {
public:
    RegexEnforcer() = default;
    RegexEnforcer(const std::string& pattern);

    [[nodiscard]] bool validate(const std::string& payload) const;

    [[nodiscard]] const std::string& getPattern() const;

private:
    std::regex regexPattern;
    std::string regexPatternStr;
};

#endif // REGEX_ENFORCER_HPP
