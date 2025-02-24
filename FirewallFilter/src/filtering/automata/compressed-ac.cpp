#include "compressed-ac.hpp"

using namespace std;

CompressedAC::CompressedAC() {
    states.emplace_back();  // Root state
}

void CompressedAC::buildAutomaton(const vector<string>& patterns) {
    // Step 1: Insert patterns into Trie structure
    for (const string& pattern : patterns) {
        int currentState = 0;
        for (char ch : pattern) {
            if (states[currentState].transitions[ch] == -1) {
                states[currentState].transitions[ch] = states.size();
                states.emplace_back();
            }
            currentState = states[currentState].transitions[ch];
        }
        states[currentState].isEndOfPattern = true;
    }

    // Step 2: Build Failure Links using BFS
    queue<int> q;
    for (int i = 0; i < COMPRESSED_ALPHABET_SIZE; i++) {
        if (states[0].transitions[i] != -1) {
            states[states[0].transitions[i]].failureLink = 0;
            q.push(states[0].transitions[i]);
        }
    }

    while (!q.empty()) {
        int stateIdx = q.front();
        q.pop();

        for (int i = 0; i < COMPRESSED_ALPHABET_SIZE; i++) {
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
}

bool CompressedAC::search(const string& text) const {
    int currentState = 0;

    for (char ch : text) {
        while (currentState && states[currentState].transitions[ch] == -1)
            currentState = states[currentState].failureLink;

        currentState = (states[currentState].transitions[ch] != -1) ? states[currentState].transitions[ch] : 0;

        if (states[currentState].isEndOfPattern)
            return true; // Match found
    }

    return false;
}
