#ifndef TLS_FINGERPRINT_ENFORCER_HPP
#define TLS_FINGERPRINT_ENFORCER_HPP

#include <vector>
#include <string>
#include <set>

class TLSFingerprintEnforcer {
public:
    TLSFingerprintEnforcer() = default;
    TLSFingerprintEnforcer(const std::vector<std::string>& allowedFingerprints);

    bool validate(const std::string& fingerprint) const;

private:
    std::set<std::string> allowedFingerprints;
};

#endif // TLS_FINGERPRINT_ENFORCER_HPP
