#include "filtering.hpp"

#include "filtering.hpp"
#include "engine/firewall-engine.hpp"
#include "rules/rule-parser.hpp"
#include "utils/logger.hpp"

FirewallEngine firewallEngine;

void initializeFirewall(const std::vector<FirewallRule>& rules) {
    firewallEngine.loadRules(rules);
}

bool filterPacket(const std::string& sourceIP, const std::string& destIP,
                  int sourcePort, int destPort, const std::string& payload) {
    return firewallEngine.processPacket(sourceIP, destIP, sourcePort, destPort, payload);
}
