#ifndef ENUMS_HPP
#define ENUMS_HPP

namespace fwso::structs
{
    enum class Subject
    {
        Connection         = 0,
        ConnectionClass    = 1,
        Protocol           = 2,
        Rule               = 3,
        Record             = 4,
        Enforcer           = 5,
        Packet             = 6,

        EncryptedTunnelKey = 7,
        EncryptedTunnel    = 8,
        User               = 9,
        UserPermission     = 10
    };

    enum class Prototype
    {
        Get      = 0,
        Create   = 1,
        Update   = 2,
        Delete   = 3,
        Suppress = 4
    };
}

#endif //ENUMS_HPP
