#ifndef FW_MESSAGE_HPP
#define FW_MESSAGE_HPP

#include <string>

using namespace std;

namespace fwso::structs {
    enum message_type {
        UNSET        = 0,
        INIT         = 1,
        CREATE_USER  = 2,
        RESPONSE     = 3,
        REQUEST      = 4,

    };

    class message {
    public:
        message_type type;
        long int sender_pid;
        long int receiver_pid;
        string content;

        message(message_type t, long int spid, long int rpid);

        [[nodiscard]] string to_string() const;
    };
}

#endif //FW_MESSAGE_HPP
