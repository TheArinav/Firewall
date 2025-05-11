#ifndef FILTERING_HPP
#define FILTERING_HPP

#include "rules/firewall-rule.hpp"
#include <vector>
#include <string>

// Initialize firewall with rules
void initializeFirewall(std::vector<FirewallRule>& rules);

// Process an incoming packet
bool filterPacket(const std::string& sourceIP, const std::string& destIP,
                  int sourcePort, int destPort, const std::string& payload);

#endif // FILTERING_HPP
