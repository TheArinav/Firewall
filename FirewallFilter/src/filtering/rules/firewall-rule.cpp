#include "firewall-rule.hpp"

FirewallRule::FirewallRule(const std::string& id, bool active)
    : ruleID(id), activeStatus(active) {}

void FirewallRule::setActive(bool status) {
    activeStatus = status;
}

void FirewallRule::addPayloadLengthEnforcer(const PayloadLengthEnforcer& enforcer) {
    *payloadLengthEnforcer = enforcer;
}

void FirewallRule::addRegexEnforcer(const RegexEnforcer& enforcer) {
    regexEnforcers.push_back(enforcer);
}

void FirewallRule::addRateLimitEnforcer(const RateLimitEnforcer& enforcer) {
    *rateLimitEnforcer = enforcer;
}

void FirewallRule::addTCPStateEnforcer(TCPStateEnforcer& enforcer)
{
    *tcpStateEnforcer = enforcer;
}

void FirewallRule::addTLSEnforcer(const TLSFingerprintEnforcer& enforcer) {
    *tlsEnforcer = enforcer;
}

std::string FirewallRule::getRuleID() const {
    return ruleID;
}

bool FirewallRule::isActive() const {
    return activeStatus;
}

const PayloadLengthEnforcer& FirewallRule::getPayloadLengthEnforcer() const {
    return *payloadLengthEnforcer;
}

const std::vector<RegexEnforcer>& FirewallRule::getRegexEnforcers() const {
    return regexEnforcers;
}

const RateLimitEnforcer& FirewallRule::getRateLimitEnforcer() const {
    return *rateLimitEnforcer ;
}

const TCPStateEnforcer& FirewallRule::getTCPStateEnforcer() const
{
    return *tcpStateEnforcer;
}

const TLSFingerprintEnforcer& FirewallRule::getTLSEnforcer() const {
    return *tlsEnforcer;
}
