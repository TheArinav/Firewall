#ifndef AHO_CORASICK_HPP
#define AHO_CORASICK_HPP

#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <queue>
#include <functional>

// A key identifying a connection (srcIP:dstIP:srcPort:dstPort)
struct ACConnectionKey {
    std::string srcIP, dstIP;
    int srcPort, dstPort;
    bool operator==(const ACConnectionKey& o) const noexcept {
        return srcIP==o.srcIP && dstIP==o.dstIP
            && srcPort==o.srcPort && dstPort==o.dstPort;
    }
};

// Hash for ACConnectionKey
struct ACConnectionKeyHash {
    size_t operator()(ACConnectionKey const& k) const noexcept {
        size_t h1 = std::hash<std::string>{}(k.srcIP);
        size_t h2 = std::hash<std::string>{}(k.dstIP);
        size_t h3 = std::hash<int>{}(k.srcPort);
        size_t h4 = std::hash<int>{}(k.dstPort);
        return h1 ^ (h2<<1) ^ (h3<<2) ^ (h4<<3);
    }
};

// What to report when a pattern matches
struct MatchTarget {
    std::string ruleID;
    std::string srcIP, dstIP;
    int srcPort, dstPort;
};

class AhoCorasick {
public:
    // Insert one literal pattern for a given connection
    void addPattern(const ACConnectionKey& conn,
                    const std::string& pattern,
                    const MatchTarget& target);

    // After all addPattern calls, call build() once
    void build();

    // Run the automaton for a specific connection+text
    // returns all MatchTargets whose patterns appear as substrings
    std::vector<MatchTarget>
    search(const ACConnectionKey& conn, const std::string& text) const;

    /// Advance one character (including failure fallback)
    int nextState(const ACConnectionKey& conn, int state, unsigned char ch) const;

    /// True if this automaton state is “rare” (patternCount < RARE_THRESHOLD)
    bool isRareState(const ACConnectionKey& conn, int state) const;


private:
    static constexpr int RARE_THRESHOLD = 2;

    // Single-trie automaton for one connection
    struct Automaton {
        struct Node {
            std::array<int, 256> transitions;
            int failure = 0;
            int patternCount = 0;
            std::vector<MatchTarget> outputs;
            Node() { transitions.fill(-1); }
        };

        std::vector<Node> nodes{1};

        // Build failure links after all patterns inserted
        void buildFailure() {
            std::queue<int> q;
            // depth-1 nodes: failure -> 0
            for (int c = 0; c < 256; ++c) {
                int v = nodes[0].transitions[c];
                if (v != -1) {
                    nodes[v].failure = 0;
                    q.push(v);
                }
            }
            // BFS
            while (!q.empty()) {
                int u = q.front(); q.pop();
                for (int c = 0; c < 256; ++c) {
                    int v = nodes[u].transitions[c];
                    if (v == -1) continue;
                    int f = nodes[u].failure;
                    while (f && nodes[f].transitions[c] == -1)
                        f = nodes[f].failure;
                    int nf = (nodes[f].transitions[c] != -1 ? nodes[f].transitions[c] : 0);
                    nodes[v].failure = nf;
                    // inherit outputs
                    auto& out_nf = nodes[nf].outputs;
                    nodes[v].outputs.insert(nodes[v].outputs.end(),
                                             out_nf.begin(), out_nf.end());
                    q.push(v);
                }
            }
        }

        // Search for all outputs in text
        std::vector<MatchTarget> search(const std::string& text) const {
            std::vector<MatchTarget> res;
            int state = 0;
            for (unsigned char ch : text) {
                while (state && nodes[state].transitions[ch] == -1)
                    state = nodes[state].failure;
                state = (nodes[state].transitions[ch] != -1)
                        ? nodes[state].transitions[ch]
                        : 0;
                // append outputs
                auto const& out = nodes[state].outputs;
                res.insert(res.end(), out.begin(), out.end());
            }
            return res;
        }
    };

    // Map each connection to its own automaton
    std::unordered_map<ACConnectionKey, Automaton, ACConnectionKeyHash> automata_;
};

#endif // AHO_CORASICK_HPP
