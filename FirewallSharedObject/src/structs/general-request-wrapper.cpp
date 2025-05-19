#include "general-request-wrapper.hpp"

#include <iostream>

#include <sstream>
#include <utility>
#include "../utils.hpp"

using namespace std;

namespace fwso::structs
{
    GeneralRequestWrapper::GeneralRequestWrapper(long int id, string  sessionID, const std::string& body):
    Id(id), SessionID(move(sessionID)), Body(body)
    {
    }

    [[nodiscard]] string GeneralRequestWrapper::serialize() const noexcept
    {
        stringstream ss;
        ss << "[("
           << utils::format_uid_hex(this->Id)
           << ",'"
           << this->SessionID
           << "'):"
           << this->Body
           << "]";
        return ss.str();
    }

    void GeneralRequestWrapper::disposeData() noexcept
    {
        this->Id = 0;
        this->SessionID = "";
        this->Body = "";
    }
}
