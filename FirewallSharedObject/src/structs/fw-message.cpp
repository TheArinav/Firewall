#include "fw-message.hpp"
#include "../utils.hpp"

#include <sstream>

namespace fwso::structs {

    message::message(message_type t, long int spid, long int rpid) {
        type = t;
        sender_pid = spid;
        receiver_pid = rpid;
    }

    string message::to_string() const {
        stringstream ss = {};
        ss << "{"
           << utils::format_pid_hex(sender_pid)
           << ","
           << utils::format_pid_hex(receiver_pid)
           << ","
           << type
           << ","
           << content
           << "}" << endl;
        return ss.str();
    }
}
