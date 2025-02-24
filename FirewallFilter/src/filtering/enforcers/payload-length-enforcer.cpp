#include "payload-length-enforcer.hpp"

PayloadLengthEnforcer::PayloadLengthEnforcer(int minLen, int maxLen)
    : minLength(minLen), maxLength(maxLen) {}

bool PayloadLengthEnforcer::validate(int payloadLength) const {
    return (payloadLength >= minLength && payloadLength <= maxLength);
}
