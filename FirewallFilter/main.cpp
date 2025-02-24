#include "src/filtering/enforcers/ip-port-enforcer.hpp"
#include "src/filtering/enforcers/payload-length-enforcer.hpp"
#include "src/filtering/enforcers/rate-limit-enforcer.hpp"
#include "src/filtering/enforcers/regex-enforcer.hpp"
#include "src/filtering/enforcers/tls-fingerprint-enforcer.hpp"
#include <iostream>

int main() {
    // Test IP/Port Enforcer
    IpPortEnforcer ipPort({"192.168.1.1"}, {"10.0.0.1"}, {80}, {443});
    std::cout << "IP/Port Enforcer: " << ipPort.validate("192.168.1.1", "10.0.0.1", 80, 443) << std::endl;

    // Test Payload Length Enforcer
    PayloadLengthEnforcer lengthEnforcer(20, 1500);
    std::cout << "Payload Length: " << lengthEnforcer.validate(100) << std::endl;

    // Test Regex Enforcer
    RegexEnforcer regex("^GET /.* HTTP/1.1$");
    std::cout << "Regex Match: " << regex.validate("GET /index.html HTTP/1.1") << std::endl;

    return 0;
}
