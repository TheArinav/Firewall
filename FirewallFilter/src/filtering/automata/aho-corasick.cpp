#include "aho-corasick.hpp"

using namespace std;

AhoCorasick::AhoCorasick() {
    states.emplace_back();
}

void AhoCorasick::buildAutomaton(const vector<string>& patterns) {
    // Step 1: Insert patterns into Trie structure
    for (const string& pattern : patterns) {
        int currentState = 0;
        for (char ch : pattern) {
            if (states[currentState].transitions[ch] == -1) {
                states[currentState].transitions[ch] = states.size();
                states.emplace_back();
            }
            currentState = states[currentState].transitions[ch];
            states[currentState].patternCount++;  //  Track pattern involvement
        }
        states[currentState].isEndOfPattern = true;
    }

    // Step 2: Build Failure Links using BFS
    queue<int> q;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (states[0].transitions[i] != -1) {
            states[states[0].transitions[i]].failureLink = 0;
            q.push(states[0].transitions[i]);
        }
    }

    while (!q.empty()) {
        int stateIdx = q.front();
        q.pop();

        for (int i = 0; i < ALPHABET_SIZE; i++) {
            int transition = states[stateIdx].transitions[i];
            if (transition == -1) continue;

            int failure = states[stateIdx].failureLink;
            while (failure && states[failure].transitions[i] == -1)
                failure = states[failure].failureLink;

            states[transition].failureLink = (states[failure].transitions[i] != -1)
                ? states[failure].transitions[i]
                : 0;

            states[transition].isEndOfPattern |= states[states[transition].failureLink].isEndOfPattern;
            q.push(transition);
        }
    }

    // Step 3: Identify Rare States
    const int RARE_THRESHOLD = 2;  // If a state is involved in fewer than 2 patterns, it's rare
    for (size_t i = 0; i < states.size(); i++) {
        if (states[i].patternCount < RARE_THRESHOLD) {
            rareStates.insert(i);
        }
    }
}

bool AhoCorasick::search(const string& text) const {
    int currentState = 0;

    for (char ch : text) {
        while (currentState && states[currentState].transitions[ch] == -1)
            currentState = states[currentState].failureLink;

        currentState = (states[currentState].transitions[ch] != -1) ? states[currentState].transitions[ch] : 0;

        if (states[currentState].isEndOfPattern)
            return true;
    }

    return false;
}

//  Function to check if a state is rare
bool AhoCorasick::isRareState(int state) const {
    return rareStates.count(state) > 0;
}

int AhoCorasick::getStateTransition(int state, char ch) const {
    return states[state].transitions[ch];
}

int AhoCorasick::getFailureLink(int state) const {
    return states[state].failureLink;
}