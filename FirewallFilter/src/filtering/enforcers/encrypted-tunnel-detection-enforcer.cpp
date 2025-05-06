#include "encrypted-tunnel-detection-enforcer.hpp"
#include <cmath>
#include <array>

TunnelDetectionEnforcer::TunnelDetectionEnforcer(double threshold)
    : entropyThreshold(threshold) {}

bool TunnelDetectionEnforcer::validate(const std::string& payload) const {
    double entropy = calculateEntropy(payload);
    return entropy < entropyThreshold;
}

double TunnelDetectionEnforcer::calculateEntropy(const std::string& data) {
    if (data.empty()) return 0.0;

    std::array<int, 256> freq{};
    for (unsigned char c : data)
        freq[c]++;

    double entropy = 0.0;
    const double len = static_cast<double>(data.size());

    for (int count : freq) {
        if (count == 0) continue;
        double p = count / len;
        entropy -= p * std::log2(p);
    }

    return entropy;
}
