#ifndef PAYLOAD_LENGTH_ENFORCER_HPP
#define PAYLOAD_LENGTH_ENFORCER_HPP

class PayloadLengthEnforcer {
public:
    PayloadLengthEnforcer() = default;
    PayloadLengthEnforcer(int minLen, int maxLen);

    bool validate(int payloadLength) const;

private:
    int minLength;
    int maxLength;
};

#endif // PAYLOAD_LENGTH_ENFORCER_HPP
