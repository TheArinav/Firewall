#include "compressed-ac.hpp"

#include "filtering/rules/firewall-rule.hpp"

void CompressedAC::addPattern(const ACConnectionKey& conn,
                              const std::string& pattern,
                              const MatchTarget& target) {
    auto& aut = automata_[conn];
    int st = 0;
    for (unsigned char ch : pattern) {
        if (aut.nodes[st].next[ch] == -1) {
            aut.nodes[st].next[ch] = aut.nodes.size();
            aut.nodes.emplace_back();
        }
        st = aut.nodes[st].next[ch];
    }
    aut.nodes[st].outputs.push_back(target);
}

void CompressedAC::build() {
    for (auto& kv : automata_) {
        kv.second.buildFailure();
    }
}

std::vector<MatchTarget>
CompressedAC::search(const ACConnectionKey& conn, const std::string& text) const {
    std::vector<MatchTarget> result;

    // exact
    auto it = automata_.find(conn);
    if (it != automata_.end()) {
        auto v = it->second.search(text);
        result.insert(result.end(), v.begin(), v.end());
    }

    // wildcard/fallback
    for (auto const& [patternKey, aut] : automata_) {
        if (patternKey == conn) continue;
        EndpointFilter f{
            patternKey.srcIP,
            patternKey.dstIP,
            patternKey.srcPort,
            patternKey.dstPort
        };
        if (f.matches(conn.srcIP, conn.dstIP, conn.srcPort, conn.dstPort)) {
            auto v = aut.search(text);
            result.insert(result.end(), v.begin(), v.end());
        }
    }

    return result;
}
