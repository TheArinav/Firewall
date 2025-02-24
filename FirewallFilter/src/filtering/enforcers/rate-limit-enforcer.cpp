#include "rate-limit-enforcer.hpp"

using namespace std;

RateLimitEnforcer::RateLimitEnforcer(int maxPacketsPerSecond)
    : maxPackets(maxPacketsPerSecond) {}

bool RateLimitEnforcer::validate(const string& srcIP) {
    auto now = chrono::steady_clock::now();
    auto& entry = packetCounts[srcIP];

    if (chrono::duration_cast<chrono::seconds>(now - entry.second).count() >= 1) {
        entry.first = 0;
        entry.second = now;
    }

    entry.first++;
    return entry.first <= maxPackets;
}
