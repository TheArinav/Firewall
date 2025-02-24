#ifndef AHO_CORASICK_HPP
#define AHO_CORASICK_HPP

#include <array>
#include <vector>
#include <queue>
#include <unordered_set>
#include <string>

constexpr int ALPHABET_SIZE = 256;

class AhoCorasick {
public:
    AhoCorasick();

    void buildAutomaton(const std::vector<std::string>& patterns);
    bool search(const std::string& text) const;

    int getStateTransition(int state, char ch) const;
    int getFailureLink(int state) const;
    bool isRareState(int state) const;  // Identify if a state is rare

private:
    struct alignas(64) Node {
        std::array<int, ALPHABET_SIZE> transitions{};
        int failureLink = 0;
        bool isEndOfPattern = false;
        int patternCount = 0;  // Tracks how many patterns this state participates in

        Node() {
            transitions.fill(-1);
        }
    };

    std::vector<Node> states;
    std::unordered_set<int> rareStates;  // Stores indices of rare states
};

#endif // AHO_CORASICK_HPP
