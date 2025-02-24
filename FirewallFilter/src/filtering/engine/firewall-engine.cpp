#include "firewall-engine.hpp"

#include "firewall-engine.hpp"
#include "../utils/logger.hpp"

using namespace std;

FirewallEngine::FirewallEngine() {}

void FirewallEngine::loadRules(const vector<FirewallRule>& rules) {
    firewallRules = rules;

    // Load regex-based rules into Aho-Corasick
    vector<string> regexPatterns;
    for (const auto& rule : firewallRules) {
        for (const auto& enforcer : rule.getRegexEnforcers()) {
            regexPatterns.push_back(enforcer.getPattern());
        }
    }

    // Build both automata with regex patterns
    fullMatrixAutomaton.buildAutomaton(regexPatterns);
    compressedAutomaton.buildAutomaton(regexPatterns);

    Logger::info("Firewall rules loaded successfully.");
}

bool FirewallEngine::processPacket(const string& sourceIP, const string& destIP,
                                   int sourcePort, int destPort, const string& payload) {
    Logger::debug("Processing packet from " + sourceIP + ":" + to_string(sourcePort) +
                  " to " + destIP + ":" + to_string(destPort));

    for (const auto& rule : firewallRules) {
        // Check IP/Port rules
        if (!rule.getIpPortEnforcer().validate(sourceIP, destIP, sourcePort, destPort))
            continue; // Move to next rule

        // Check payload length
        if (!rule.getPayloadLengthEnforcer().validate(payload.size()))
            continue;

        // Check regex-based filtering
        if (!fullMatrixAutomaton.search(payload))
            continue;

        // Check TLS fingerprinting if applicable
        if (rule.hasTLSEnforcer() && !rule.getTLSEnforcer().validate(payload))
            continue;

        Logger::info("Packet allowed by rule: " + rule.getRuleID());
        return true;
    }

    Logger::warn("Packet dropped: No matching rule found.");
    return false;
}
