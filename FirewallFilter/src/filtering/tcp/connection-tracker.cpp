#include "connection-tracker.hpp"

using namespace std;

ConnectionTracker::ConnectionTracker() {}

TCPConnectionState ConnectionTracker::updateConnection(const ConnectionKey& key, bool syn, bool ack, bool fin, bool rst) {
    lock_guard<mutex> lock(mtx);

    auto now = chrono::steady_clock::now();
    auto& entry = table[key];
    entry.lastSeen = now;

    // Simplified TCP state handling
    switch (entry.state) {
    case TCPConnectionState::NONE:
        if (syn && !ack)
            entry.state = TCPConnectionState::SYN_SENT;
        break;
    case TCPConnectionState::SYN_SENT:
        if (syn && ack)
            entry.state = TCPConnectionState::SYN_RECEIVED;
        break;
    case TCPConnectionState::SYN_RECEIVED:
        if (ack && !syn)
            entry.state = TCPConnectionState::ESTABLISHED;
        break;
    case TCPConnectionState::ESTABLISHED:
        if (fin)
            entry.state = TCPConnectionState::FIN_WAIT;
        else if (rst)
            entry.state = TCPConnectionState::CLOSED;
        break;
    case TCPConnectionState::FIN_WAIT:
        if (ack)
            entry.state = TCPConnectionState::CLOSED;
        break;
    default:
        break;
    }

    return entry.state;
}

void ConnectionTracker::cleanupOldConnections(int timeoutSeconds) {
    lock_guard<mutex> lock(mtx);
    auto now = chrono::steady_clock::now();
    for (auto it = table.begin(); it != table.end(); ) {
        auto duration = chrono::duration_cast<chrono::seconds>(now - it->second.lastSeen);
        if (duration.count() > timeoutSeconds)
            it = table.erase(it);
        else
            ++it;
    }
}
