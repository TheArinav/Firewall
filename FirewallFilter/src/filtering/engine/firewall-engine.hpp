#ifndef FIREWALL_ENGINE_HPP
#define FIREWALL_ENGINE_HPP

#include "../rules/firewall-rule.hpp"
#include "../enforcers/ip-port-enforcer.hpp"
#include "../enforcers/payload-length-enforcer.hpp"
#include "../enforcers/rate-limit-enforcer.hpp"
#include "../enforcers/regex-enforcer.hpp"
#include "../enforcers/tls-fingerprint-enforcer.hpp"
#include "../automata/aho-corasick.hpp"
#include "../automata/compressed-ac.hpp"
#include <vector>
#include <string>

class FirewallEngine {
public:
    FirewallEngine();

    // Load firewall rules into the system
    void loadRules(const std::vector<FirewallRule>& rules);

    // Process an incoming packet and return whether it should be allowed
    bool processPacket(const std::string& sourceIP, const std::string& destIP,
                       int sourcePort, int destPort, const std::string& payload);

private:
    std::vector<FirewallRule> firewallRules;
    AhoCorasick fullMatrixAutomaton;
    CompressedAC compressedAutomaton;
};

#endif // FIREWALL_ENGINE_HPP
