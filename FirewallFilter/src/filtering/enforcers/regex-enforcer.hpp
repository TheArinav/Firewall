#ifndef REGEX_ENFORCER_HPP
#define REGEX_ENFORCER_HPP

#include <string>
#include <regex>

enum class RegexMatchMode {
    FULL_AC,
    PARTIAL_AC,
    FULL_REGEX
};

class RegexEnforcer {
public:
    RegexEnforcer() = default;

    // Full regex fallback constructor
    RegexEnforcer(const std::string& pattern, bool allow);

    // AC-only or partial AC
    RegexEnforcer(const std::string& fullPattern, const std::string& acPrefix,
                  const std::string& regexRemainder, RegexMatchMode mode, bool allow);

    [[nodiscard]] bool validate(const std::string& fullPacket) const;

    [[nodiscard]] const std::string& getFullPattern() const;
    [[nodiscard]] const std::string& getACPrefix() const;
    [[nodiscard]] RegexMatchMode getMode() const;
    [[nodiscard]] bool isAllow() const;

private:
    RegexMatchMode matchMode;
    bool allowAction;

    std::string fullPattern;
    std::string acPrefix;
    std::string regexRemainder;

    std::regex regexPattern;
};

#endif // REGEX_ENFORCER_HPP
