#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>

using namespace std;

namespace fwso::utils{
    string format_pid_hex(long int pid);
    string format_uid_hex(long int uid);
    string generate_nonce();
    string base64_decode(const string &encoded);
    string base64_encode(const unsigned char* data, size_t length);
}

#endif //UTILS_HPP
