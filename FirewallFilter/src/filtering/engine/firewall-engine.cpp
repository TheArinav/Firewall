#include "firewall-engine.hpp"

#include "firewall-engine.hpp"
#include "../utils/logger.hpp"
#include "../automata/ac-util.hpp"

using namespace std;

#include "../automata/aho-corasick.hpp"
#include "../automata/compressed-ac.hpp"
#include "../enforcers/regex-enforcer.hpp"
#include "firewall-engine.hpp"
#include "../utils/logger.hpp"

void FirewallEngine::loadRules(std::vector<FirewallRule>& rules) {
    // Steal the new rules into our member
    firewallRules = std::move(rules);

    // Reset both automata
    fullMatrixAutomaton = AhoCorasick();
    compressedAutomaton = CompressedAC();

    // For each rule, for each regex enforcer that is AC-eligible,
    // add its literal prefix into both automata under the rule's connection key.
    for (auto const& rule : firewallRules) {
        auto const& filter = rule.getConnectionFilter();
        ACConnectionKey key {
            filter.srcIP,
            filter.dstIP,
            filter.srcPort,
            filter.dstPort
        };

        for (auto const& enforcer : rule.getRegexEnforcers()) {
            auto mode = enforcer.getMode();
            if (mode == RegexMatchMode::FULL_AC || mode == RegexMatchMode::PARTIAL_AC) {
                // AC-compatible literal
                std::string const &lit = enforcer.getACPrefix();

                // Build the metadata for a match
                MatchTarget mt {
                    /*ruleID=*/ rule.getRuleID(),
                    /*srcIP=*/ filter.srcIP,
                    /*dstIP=*/ filter.dstIP,
                    /*srcPort=*/ filter.srcPort,
                    /*dstPort=*/ filter.dstPort
                };

                // Insert into each automaton
                fullMatrixAutomaton.addPattern(key, lit, mt);
                compressedAutomaton.addPattern(key, lit, mt);
            }
        }
    }

    // Now build failure links
    fullMatrixAutomaton.build();
    compressedAutomaton.build();

    // Recreate the packet-processor with the new automata
    processor = std::make_unique<PacketProcessor>(
        LCGRandom(),
        fullMatrixAutomaton,
        compressedAutomaton
    );

    Logger::info("Firewall rules loaded successfully.");
}



bool FirewallEngine::processPacket(const string& sourceIP, const string& destIP,
                                   int sourcePort, int destPort, const string& payload) {
    Logger::debug("Processing packet from " + sourceIP + ":" + to_string(sourcePort) +
                  " to " + destIP + ":" + to_string(destPort));

    for (const auto& rule : firewallRules) {
        const auto& filter = rule.getConnectionFilter();
        if (!filter.matches(sourceIP, destIP, sourcePort, destPort))
            continue;

        if (rule.hasPayloadLengthEnforcer() &&
            !rule.getPayloadLengthEnforcer().validate(payload.size()))
            continue;

        if (rule.hasRateLimitEnforcer() &&
            !rule.getRateLimitEnforcer().validate(sourceIP))
            continue;

        if (rule.hasTCPStateEnforcer() &&
            !rule.getTCPStateEnforcer().validate(sourceIP, destIP, sourcePort, destPort,
                                                 false, true, false, false))
            continue;

        if (rule.hasTunnelDetectionEnforcer() &&
            !rule.getTunnelDetectionEnforcer().validate(payload))
            continue;

        if (rule.hasTLSEnforcer() &&
            !rule.getTLSEnforcer().validate(payload))
            continue;

        bool regexPassed = !rule.hasRegexEnforcer(); // no regex = allow
        if (!regexPassed) {
            for (const auto& enforcer : rule.getRegexEnforcers()) {
                switch (enforcer.getMode()) {
                    case RegexMatchMode::FULL_AC:
                        regexPassed =  processor->processPacket(sourceIP, destIP, sourcePort, destPort, payload) == enforcer.isAllow();
                        break;

                    case RegexMatchMode::PARTIAL_AC:
                        {
                            bool f = processor->processPacket(sourceIP, destIP, sourcePort, destPort, payload);
                            if (f)
                                f = f == enforcer.validate(payload);
                            regexPassed = f == enforcer.isAllow();
                        }
                        break;

                    case RegexMatchMode::FULL_REGEX:
                        regexPassed = enforcer.validate(payload) == enforcer.isAllow();
                        break;
                }
                if (regexPassed) break;
            }
        }

        if (regexPassed) {
            Logger::info("Packet allowed by rule: " + rule.getRuleID());
            return true;
        }
    }

    Logger::warn("Packet dropped: No matching rule found.");
    return false;
}



