#ifndef GENERAL_REQUEST_WRAPPER_HPP
#define GENERAL_REQUEST_WRAPPER_HPP

#include <string>

namespace fwso::structs{
    class GeneralRequestWrapper
    {
    private:
        long int Id;
        std::string SessionID;
        std::string Body;
    public:
        GeneralRequestWrapper(long int id, std::string  sessionID, const std::string& body);
        [[nodiscard]] std::string serialize() const noexcept;
        void disposeData() noexcept;
    };
}

#endif //GENERAL_REQUEST_WRAPPER_HPP
