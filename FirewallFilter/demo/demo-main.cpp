#include "../src/filtering/filtering.hpp"
#include "../src/filtering/enforcers/regex-enforcer.hpp"
#include "../src/filtering/enforcers/payload-length-enforcer.hpp"
#include "../src/filtering/rules/firewall-rule.hpp"
#include "../src/filtering/utils/logger.hpp"
#include "filtering/automata/regex-ac-extractor.hpp"

using namespace std;

int main() {
    Logger::setLogLevel(LogLevel::DEBUG);
    Logger::setLogFile("demo.log");

    // === Hardcoded ruleset ===
    vector<FirewallRule> rules;

    FirewallRule rule1("RULE_ALLOW_HELLO");
    rule1.addRegexEnforcer(convertRegexToEnforcer("wav.*",true));
    rule1.addPayloadLengthEnforcer(PayloadLengthEnforcer(1, 100));
    rule1.setConnectionFilter({
    .srcIP = "10.0.0.1",
    .dstIP = "1.1.1.1",
    .srcPort = -1,  // wildcard
    .dstPort = 80
});
    rules.push_back(move(rule1));

    FirewallRule rule3("RULE_DENY_DROP_TABLE");
    rule3.addRegexEnforcer(convertRegexToEnforcer("drop",false));
    rule3.setConnectionFilter({
    .srcIP = "10.0.0.2",
    .dstIP = "1.1.1.1",
    .srcPort = -1,  // wildcard
    .dstPort = 80
});
    rules.push_back(move(rule3));

    FirewallRule rule2("RULE_ALLOW_ANY_SHORT");
    rule2.addPayloadLengthEnforcer(PayloadLengthEnforcer(1, 50));
    rules.push_back(move(rule2));

    initializeFirewall(rules);

    // === Simulate packets ===
    struct TestPacket {
        string srcIP, dstIP;
        int srcPort, dstPort;
        string payload;
    };

    vector<TestPacket> testPackets = {
        {"10.0.0.1", "1.1.1.1", 1234, 80, "wavy"},
        {"10.0.0.1", "1.1.1.1", 1234, 80, "waves"},
        {"10.0.0.1", "1.1.1.1", 1234, 80, "wow"},
        {"10.0.0.2", "1.1.1.1", 1234, 80, "drop table"},
        {"192.168.1.5", "8.8.8.8", 3000, 53, "query_dns"},
        {"10.0.0.2", "8.8.4.4", 4321, 443, "super_long_payload_exceeding_the_maximum_limit.................................."}
    };

    for (auto& pkt : testPackets) {
        Logger::info("Testing packet: " + pkt.payload);
        bool result = filterPacket(pkt.srcIP, pkt.dstIP, pkt.srcPort, pkt.dstPort, pkt.payload);
        Logger::info(string("Decision: ") + (result ? "ACCEPTED" : "DROPPED"));
    }

    return 0;
}
