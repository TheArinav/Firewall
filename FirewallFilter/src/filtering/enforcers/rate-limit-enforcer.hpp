#ifndef RATE_LIMIT_ENFORCER_HPP
#define RATE_LIMIT_ENFORCER_HPP

#include <unordered_map>
#include <chrono>

class RateLimitEnforcer {
public:
    RateLimitEnforcer() = default;
    RateLimitEnforcer(int maxPacketsPerSecond);

    bool validate(const std::string& srcIP);

private:
    int maxPackets;
    std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> packetCounts;
};

#endif // RATE_LIMIT_ENFORCER_HPP
