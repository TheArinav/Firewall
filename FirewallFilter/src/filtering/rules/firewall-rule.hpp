#ifndef FIREWALL_RULE_HPP
#define FIREWALL_RULE_HPP

#include "../enforcers/payload-length-enforcer.hpp"
#include "../enforcers/rate-limit-enforcer.hpp"
#include "../enforcers/regex-enforcer.hpp"
#include "../enforcers/tls-fingerprint-enforcer.hpp"
#include "../enforcers/tcp-state-enforcer.hpp"
#include <vector>
#include <string>
#include <optional>

class FirewallRule {
public:
    FirewallRule(const std::string& id, bool active = true);

    // Setters
    void setActive(bool status);
    void addPayloadLengthEnforcer(const PayloadLengthEnforcer& enforcer);
    void addRegexEnforcer(const RegexEnforcer& enforcer);
    void addRateLimitEnforcer(const RateLimitEnforcer& enforcer);
    void addTCPStateEnforcer(TCPStateEnforcer& enforcer);
    void addTLSEnforcer(const TLSFingerprintEnforcer& enforcer);

    // Getters
    std::string getRuleID() const;
    bool isActive() const;
    const PayloadLengthEnforcer& getPayloadLengthEnforcer() const;
    const std::vector<RegexEnforcer>& getRegexEnforcers() const;
    const RateLimitEnforcer& getRateLimitEnforcer() const;
    const TCPStateEnforcer& getTCPStateEnforcer() const;
    const TLSFingerprintEnforcer& getTLSEnforcer() const;

    bool hasPayloadLengthEnforcer() const {return payloadLengthEnforcer.has_value();}
    bool hasRegexEnforcer() const {return !regexEnforcers.empty();}
    bool hasRateLimitEnforcer() const { return rateLimitEnforcer.has_value();}
    bool hasTCPStateEnforcer() const { return tcpStateEnforcer.has_value(); }
    bool hasTLSEnforcer() const { return tlsEnforcer.has_value(); }

    FirewallRule(const FirewallRule&) = delete;
    FirewallRule& operator=(const FirewallRule&) = delete;
    FirewallRule(FirewallRule&&) noexcept = default;
    FirewallRule& operator=(FirewallRule&&) noexcept = default;


private:
    std::string ruleID;
    bool activeStatus;

    // Enforcers
    std::optional<PayloadLengthEnforcer> payloadLengthEnforcer;
    std::vector<RegexEnforcer> regexEnforcers;
    std::optional<RateLimitEnforcer> rateLimitEnforcer;
    std::optional<TCPStateEnforcer> tcpStateEnforcer;
    std::optional<TLSFingerprintEnforcer> tlsEnforcer;
};

#endif // FIREWALL_RULE_HPP
