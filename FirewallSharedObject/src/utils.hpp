#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>

using namespace std;

namespace fwso::utils {
    string format_hex(long int pid);
    string generate_nonce();
}

#endif //UTILS_HPP
