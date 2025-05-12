#ifndef COMPRESSED_AC_HPP
#define COMPRESSED_AC_HPP

#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <queue>
#include <functional>

// Reuse ConnectionKey and MatchTarget from aho-corasick.hpp
#include "aho-corasick.hpp"

class CompressedAC {
public:
    void addPattern(const ACConnectionKey& conn,
                    const std::string& pattern,
                    const MatchTarget& target);

    void build();

    std::vector<MatchTarget>
    search(const ACConnectionKey& conn, const std::string& text) const;

private:
    struct Automaton {
        struct Node {
            std::array<int,256> next;
            int failure = 0;
            std::vector<MatchTarget> outputs;
            Node() { next.fill(-1); }
        };
        std::vector<Node> nodes{1};

        void buildFailure() {
            std::queue<int> q;
            for (int c = 0; c < 256; ++c) {
                int v = nodes[0].next[c];
                if (v != -1) {
                    nodes[v].failure = 0;
                    q.push(v);
                }
            }
            while (!q.empty()) {
                int u = q.front(); q.pop();
                for (int c = 0; c < 256; ++c) {
                    int v = nodes[u].next[c];
                    if (v == -1) continue;
                    int f = nodes[u].failure;
                    while (f && nodes[f].next[c] == -1)
                        f = nodes[f].failure;
                    int nf = (nodes[f].next[c] != -1 ? nodes[f].next[c] : 0);
                    nodes[v].failure = nf;
                    // inherit outputs
                    auto const& out_nf = nodes[nf].outputs;
                    nodes[v].outputs.insert(nodes[v].outputs.end(),
                                            out_nf.begin(), out_nf.end());
                    q.push(v);
                }
            }
        }

        std::vector<MatchTarget> search(const std::string& text) const {
            std::vector<MatchTarget> res;
            int st = 0;
            for (unsigned char ch : text) {
                while (st && nodes[st].next[ch] == -1)
                    st = nodes[st].failure;
                st = (nodes[st].next[ch] != -1 ? nodes[st].next[ch] : 0);
                auto const& out = nodes[st].outputs;
                res.insert(res.end(), out.begin(), out.end());
            }
            return res;
        }
    };

    std::unordered_map<ACConnectionKey, Automaton, ACConnectionKeyHash> automata_;
};

#endif // COMPRESSED_AC_HPP
