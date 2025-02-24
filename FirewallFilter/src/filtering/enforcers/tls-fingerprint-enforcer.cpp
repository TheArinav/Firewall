#include "tls-fingerprint-enforcer.hpp"

using namespace std;

TLSFingerprintEnforcer::TLSFingerprintEnforcer(const vector<string>& allowedFingerprints) {
    this->allowedFingerprints.insert(allowedFingerprints.begin(), allowedFingerprints.end());
}

bool TLSFingerprintEnforcer::validate(const string& fingerprint) const {
    return allowedFingerprints.count(fingerprint) > 0;
}
