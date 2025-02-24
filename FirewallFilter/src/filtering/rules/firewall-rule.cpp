#include "firewall-rule.hpp"

FirewallRule::FirewallRule(const std::string& id, bool active)
    : ruleID(id), activeStatus(active) {}

void FirewallRule::setActive(bool status) {
    activeStatus = status;
}

void FirewallRule::addIpPortEnforcer(const IpPortEnforcer& enforcer) {
    ipPortEnforcer = enforcer;
}

void FirewallRule::addPayloadLengthEnforcer(const PayloadLengthEnforcer& enforcer) {
    payloadLengthEnforcer = enforcer;
}

void FirewallRule::addRegexEnforcer(const RegexEnforcer& enforcer) {
    regexEnforcers.push_back(enforcer);
}

void FirewallRule::addRateLimitEnforcer(const RateLimitEnforcer& enforcer) {
    rateLimitEnforcer = enforcer;
}

void FirewallRule::addTLSEnforcer(const TLSFingerprintEnforcer& enforcer) {
    tlsEnforcer = enforcer;
    hasTLS = true;
}

std::string FirewallRule::getRuleID() const {
    return ruleID;
}

bool FirewallRule::isActive() const {
    return activeStatus;
}

const IpPortEnforcer& FirewallRule::getIpPortEnforcer() const {
    return ipPortEnforcer;
}

const PayloadLengthEnforcer& FirewallRule::getPayloadLengthEnforcer() const {
    return payloadLengthEnforcer;
}

const std::vector<RegexEnforcer>& FirewallRule::getRegexEnforcers() const {
    return regexEnforcers;
}

const RateLimitEnforcer& FirewallRule::getRateLimitEnforcer() const {
    return rateLimitEnforcer;
}

const TLSFingerprintEnforcer& FirewallRule::getTLSEnforcer() const {
    return tlsEnforcer;
}

bool FirewallRule::hasTLSEnforcer() const {
    return hasTLS;
}
