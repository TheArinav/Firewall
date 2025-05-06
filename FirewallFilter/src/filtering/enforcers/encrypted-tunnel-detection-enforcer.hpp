#ifndef TUNNEL_DETECTION_ENFORCER_HPP
#define TUNNEL_DETECTION_ENFORCER_HPP

#include <string>

class TunnelDetectionEnforcer {
public:
    explicit TunnelDetectionEnforcer(double threshold = 7.2);

    bool validate(const std::string& payload) const;

private:
    double entropyThreshold;

    static double calculateEntropy(const std::string& data);
};

#endif // TUNNEL_DETECTION_ENFORCER_HPP
