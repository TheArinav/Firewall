#include "aho-corasick.hpp"

#include "filtering/rules/firewall-rule.hpp"

void AhoCorasick::addPattern(const ACConnectionKey& conn,
                             const std::string& pattern,
                             const MatchTarget& target) {
    auto& aut = automata_[conn];
    int st = 0;
    for (unsigned char ch : pattern) {
        if (aut.nodes[st].transitions[ch] == -1) {
            aut.nodes[st].transitions[ch] = aut.nodes.size();
            aut.nodes.emplace_back();
        }
        st = aut.nodes[st].transitions[ch];
        aut.nodes[st].patternCount++;
    }
    aut.nodes[st].outputs.push_back(target);
}

void AhoCorasick::build() {
    for (auto& kv : automata_) {
        kv.second.buildFailure();
    }
}

std::vector<MatchTarget>
AhoCorasick::search(const ACConnectionKey& conn, const std::string& text) const {
    std::vector<MatchTarget> result;

    // 1) exact‐key lookup
    auto it = automata_.find(conn);
    if (it != automata_.end()) {
        auto v = it->second.search(text);
        result.insert(result.end(), v.begin(), v.end());
    }

    // 2) fallback: any wildcard‐style key whose filter matches
    for (auto const& [patternKey, aut] : automata_) {
        if (patternKey == conn) continue;  // already did exact

        // build a tiny EndpointFilter to reuse its matches() logic
        EndpointFilter f{
            /*srcIP=*/ patternKey.srcIP,
            /*dstIP=*/ patternKey.dstIP,
            /*srcPort=*/ patternKey.srcPort,
            /*dstPort=*/ patternKey.dstPort
        };
        if (f.matches(conn.srcIP, conn.dstIP, conn.srcPort, conn.dstPort)) {
            auto v = aut.search(text);
            result.insert(result.end(), v.begin(), v.end());
        }
    }

    return result;
}


int AhoCorasick::nextState(const ACConnectionKey& conn, int state, unsigned char ch) const {
    auto it = automata_.find(conn);
    if (it == automata_.end()) return 0;
    const auto& aut = it->second;
    // follow failure links on miss
    while (state && aut.nodes[state].transitions[ch] == -1)
        state = aut.nodes[state].failure;
    int nxt = aut.nodes[state].transitions[ch];
    return nxt != -1 ? nxt : 0;
}

bool AhoCorasick::isRareState(const ACConnectionKey& conn, int state) const {
    auto it = automata_.find(conn);
    if (it == automata_.end()) return false;
    const auto& aut = it->second;
    return aut.nodes[state].patternCount < RARE_THRESHOLD;
}

