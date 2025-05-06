#ifndef CONNECTION_TRACKER_HPP
#define CONNECTION_TRACKER_HPP

#include "connection-state.hpp"
#include <unordered_map>
#include <mutex>

class ConnectionTracker {
public:
    ConnectionTracker();

    // Updates connection state based on TCP flags
    TCPConnectionState updateConnection(const ConnectionKey& key, bool syn, bool ack, bool fin, bool rst);

    // Periodic cleanup
    void cleanupOldConnections(int timeoutSeconds = 60);

private:
    std::unordered_map<ConnectionKey, ConnectionEntry, ConnectionKey::Hash> table;
    std::mutex mtx;
};

#endif // CONNECTION_TRACKER_HPP
