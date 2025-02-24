#ifndef FIREWALL_RULE_HPP
#define FIREWALL_RULE_HPP

#include "../enforcers/ip-port-enforcer.hpp"
#include "../enforcers/payload-length-enforcer.hpp"
#include "../enforcers/rate-limit-enforcer.hpp"
#include "../enforcers/regex-enforcer.hpp"
#include "../enforcers/tls-fingerprint-enforcer.hpp"
#include <vector>
#include <string>

class FirewallRule {
public:
    FirewallRule(const std::string& id, bool active = true);

    // Setters
    void setActive(bool status);
    void addIpPortEnforcer(const IpPortEnforcer& enforcer);
    void addPayloadLengthEnforcer(const PayloadLengthEnforcer& enforcer);
    void addRegexEnforcer(const RegexEnforcer& enforcer);
    void addRateLimitEnforcer(const RateLimitEnforcer& enforcer);
    void addTLSEnforcer(const TLSFingerprintEnforcer& enforcer);

    // Getters
    std::string getRuleID() const;
    bool isActive() const;
    const IpPortEnforcer& getIpPortEnforcer() const;
    const PayloadLengthEnforcer& getPayloadLengthEnforcer() const;
    const std::vector<RegexEnforcer>& getRegexEnforcers() const;
    const RateLimitEnforcer& getRateLimitEnforcer() const;
    const TLSFingerprintEnforcer& getTLSEnforcer() const;
    bool hasTLSEnforcer() const;

private:
    std::string ruleID;
    bool activeStatus;

    // Enforcers
    IpPortEnforcer ipPortEnforcer;
    PayloadLengthEnforcer payloadLengthEnforcer;
    std::vector<RegexEnforcer> regexEnforcers;
    RateLimitEnforcer rateLimitEnforcer;
    TLSFingerprintEnforcer tlsEnforcer;
    bool hasTLS = false;
};

#endif // FIREWALL_RULE_HPP
